# @version 0.3.7


interface ApeAccount:
     def owner() -> address: view
     def signer() -> address: view
     def proxy() -> address: view

interface SignatureChecker:
    def is_valid_signature_now(
        signer: address,
        hash: bytes32,
        signature: Bytes[65]
    ) -> bool: view

interface AccountsProxy:
     def authorise_signer(_account: address, _signer: address) -> bool: nonpayable


event GuardianAdditionRequestsed:
     account: indexed(address)
     guardian: indexed(address)
     execute_after: uint256

event GuardianRevokationRequested:
     account: indexed(address)
     guardian: indexed(address)
     execute_after: uint256

event GuardianAdditionCancelled:
     account: indexed(address)
     guardian: indexed(address)

event GuardianRevokationCancelled:
     account: indexed(address)
     guardian: indexed(address)

event GuardianAdded:
     account: indexed(address)
     guardian: indexed(address)

event GuardianRevoked:
     account: indexed(address)
     guardian: indexed(address)
     
event RecoveryExecuted:
     account: indexed(address)
     recovery: indexed(address)
     execute_after: uint256

event RecoveryConfigs:
     account: indexed(address)
     recovery: indexed(address)
     guardian: indexed(address)

event RecoveryFinalized:
     account: indexed(address)
     recovery: indexed(address)
     
event RecoveryCanceled:
     account: indexed(address)
     recovery: indexed(address)

event OwnershipTransfered:
     account: indexed(address)
     new_owner: indexed(address)

event Locked:
     account: indexed(address)
     release_after: uint256

event Unlocked:
     account: indexed(address)

event SetWithdrawlLimit:
     account: indexed(address)
     max_limit: indexed(uint256)

event TransferOnwership:
     account: indexed(address)
     new_signer: indexed(address)
     old_signer: indexed(address)

event ChangeOwner:
     old_owner: indexed(address)
     new_owner: indexed(address)

event ChangeFactory:
     old_factory: indexed(address)
     new_factory: indexed(address)


struct RecoveryConfig:
     recovery: address
     execute_after: uint256

struct GuardianConfigs:
     account: address
     guardian: address
     pending: uint256

struct GuardianPermit:
     signer: address
     account: address
     guardian: address
     name_id: uint256
     conduit_key: uint256
     nonce: uint256
     start_time: uint256
     end_time: uint256
     owner_signature: Bytes[65]

struct RecoveryPermit:
     signer: address
     account: address
     recovery: address
     guardian: address
     name_id: uint256
     nonce: uint256
     sign_time: uint256
     owner_signature: Bytes[65]


GUARDIAN_PERMIT_TYPEHASH: constant(bytes32) = keccak256(
     "GuardianPermit(address signer,address account,address guardian,uint256 name_id,uint256 conduit_key,uint256 nonce,uint256 start_time,uint256 end_time)"
)
RECOVERY_PERMIT_TYPEHASH: constant(bytes32) = keccak256(
     "RecoveryPermit(address signer,address account,address recovery,address guardian,uint256 name_id,uint256 nonce,uint256 sign_time)"
)

EIP712_TYPEHASH: constant(bytes32) = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")

DOMAIN_SEPARATOR: immutable(bytes32)
NAME: immutable(String[64])
VERSION: constant(String[8]) = "v1.0.0"


pending: HashMap[bytes32, GuardianConfigs]
guardian_configs: HashMap[address, RecoveryConfig]
guardian: HashMap[address, HashMap[address, bool]]
guardian_active: HashMap[address, HashMap[uint256, address]]
guardian_active_index: HashMap[address, HashMap[address, uint256]]
guardian_active_count: HashMap[address, uint256]
locked: HashMap[address, uint256]
guardian_name_id: public(HashMap[address, uint256])

recovery_period: immutable(uint256)
lock_period: immutable(uint256)
security_period: immutable(uint256)

daily_withdrawl_limit_for_native: public(HashMap[address, uint256])

owner: public(address)
signature: public(address)
proxy: public(address)
factory: public(address)


@external
def __init__(_recovery_period: uint256, _lock_period: uint256, _security_period: uint256, _signature: address):
     assert _lock_period >= _recovery_period, "Ape: insecure lock period"

     recovery_period = _recovery_period
     lock_period = _lock_period
     security_period = _security_period

     self.owner = msg.sender
     self.signature = _signature

     name: String[64] = concat("Ape Wallet Security Manager", " v1")
     NAME = name

     DOMAIN_SEPARATOR = keccak256(
          _abi_encode(EIP712_TYPEHASH, keccak256(name), keccak256(VERSION), chain.id, self)
     )


@view
@internal
def _guardian_permit_hash(_param: GuardianPermit) -> bytes32:

     hash: bytes32 = keccak256(
          _abi_encode(
               GUARDIAN_PERMIT_TYPEHASH,
               _param.signer,
               _param.account,
               _param.guardian,
               _param.name_id,
               _param.conduit_key,
               _param.nonce,
               _param.start_time,
               _param.end_time
          )
     )

     digest: bytes32 = keccak256(
        concat(
            b"\x19\x01",
            DOMAIN_SEPARATOR,
            hash
        )
    )

     return digest


@view
@internal
def _recovery_permit_hash(_param: RecoveryPermit) -> bytes32:

     hash: bytes32 = keccak256(
          _abi_encode(
               RECOVERY_PERMIT_TYPEHASH,
               _param.signer,
               _param.account,
               _param.recovery,
               _param.guardian,
               _param.name_id,
               _param.nonce,
               _param.sign_time
          )
     )

     digest: bytes32 = keccak256(
        concat(
            b"\x19\x01",
            DOMAIN_SEPARATOR,
            hash
        )
    )

     return digest


@view
@internal
def _is_lock(_account: address) -> bool:
     period: uint256 = self.locked[_account]
     
     if block.timestamp <= period:
          return True

     return False


@internal
def _set_lock(_account: address):
     self.locked[_account] = block.timestamp + lock_period
     log Locked(_account, block.timestamp + lock_period)


@internal
def _set_unlock(_account: address):
     self.locked[_account] = 0
     log Unlocked(_account)


@view
@external
def is_lock(_account: address) -> bool:
     return self._is_lock(_account)


@view
@external
def is_guardian(_account: address, _guardian: address) -> bool:
     return self.guardian[_account][_guardian]


@view
@external
def get_guardian_addition_period(_account: address, _guardian: address) -> uint256:
     
     execute_id: bytes32 = keccak256(_abi_encode(_account, _guardian, "addition"))
     return self.pending[execute_id].pending


@view
@external
def get_guardian_revokation_period(_account: address, _guardian: address) -> uint256:
     
     execute_id: bytes32 = keccak256(_abi_encode(_account, _guardian, "revokation"))
     return self.pending[execute_id].pending


@view
@external
def get_guardian_count(_account: address) -> uint256:
     return self.guardian_active_count[_account]


@view
@external
def get_guardian(_account: address, _guardian_id: uint256) -> address:
     return self.guardian_active[_account][_guardian_id]


@view
@external
def get_recovery(_account: address) -> RecoveryConfig:
     return self.guardian_configs[_account]


@external
def add_guardian(_account: address, _guardian: address):
     assert _guardian != empty(address) and _account != _guardian, "Ape: invalid address"
     _owner: address = ApeAccount(_account).owner()
     assert _guardian != _owner, "Ape: guardian cannot be owner"

     assert msg.sender == _account, "Ape: only self"
     assert not self.guardian[_account][_guardian], "Ape: duplicate guardian"
     assert not self._is_lock(_account), "Ape: locked"

     execute_id: bytes32 = keccak256(_abi_encode(_account, _guardian, "addition"))
     assert self.pending[execute_id].pending == 0, "Ape: duplicate guardian"

     self.pending[execute_id] = GuardianConfigs({account: _account, guardian: _guardian, pending: block.timestamp + security_period})
     log GuardianAdditionRequestsed(_account, _guardian, block.timestamp + security_period)


@external
def add_guardian_with_permit(_protected_parameters: GuardianPermit, _guardian_parameters: GuardianPermit):

     assert msg.sender == _protected_parameters.account, "Ape: only self"
     assert _protected_parameters.account == _guardian_parameters.account, "Ape: different account"
     assert _protected_parameters.account != _guardian_parameters.guardian, "Ape: invalid address"
     
     _owner: address = ApeAccount(_protected_parameters.account).owner()
     assert not _protected_parameters.guardian in [empty(address), _owner], "Ape: guardian cannot be empty/owner"
     
     assert _protected_parameters.end_time < block.timestamp and _guardian_parameters.end_time < block.timestamp, "Ape: expire time"
     assert not self._is_lock(_protected_parameters.account), "Ape: locked"

     protected_hash: bytes32 = self._guardian_permit_hash(_protected_parameters)
     guardian_hash: bytes32 = self._guardian_permit_hash(_guardian_parameters)

     assert SignatureChecker(self.signature).is_valid_signature_now(_protected_parameters.signer, protected_hash, _protected_parameters.owner_signature), "Ape: protected signature fail"
     assert SignatureChecker(self.signature).is_valid_signature_now(_guardian_parameters.signer, guardian_hash, _guardian_parameters.owner_signature), "Ape: guardian signature fail"
     
     self.guardian[_protected_parameters.account][_protected_parameters.guardian] = True
     self.guardian_active[_protected_parameters.account][self.guardian_active_count[_protected_parameters.account]] = _protected_parameters.guardian
     self.guardian_active_index[_protected_parameters.account][_protected_parameters.guardian] = self.guardian_active_count[_protected_parameters.account]
     self.guardian_active_count[_protected_parameters.account] += 1
     self.guardian_name_id[_protected_parameters.guardian] = _guardian_parameters.name_id

     log GuardianAdded(_protected_parameters.account, _protected_parameters.guardian)


@external
def config_guardian_addition(_account: address, _guardian: address):
     assert not self._is_lock(_account), "Ape: locked"

     execute_id: bytes32 = keccak256(_abi_encode(_account, _guardian, "addition"))
     guardian_pending: GuardianConfigs = self.pending[execute_id]
     
     assert guardian_pending.pending > 0, "Ape: unknow pending addition"
     assert guardian_pending.pending < block.timestamp, "Ape: pending addition not over"

     self.guardian[_account][_guardian] = True
     self.guardian_active[_account][self.guardian_active_count[_account]] = _guardian
     self.guardian_active_index[_account][_guardian] = self.guardian_active_count[_account]
     self.guardian_active_count[_account] += 1
     self.pending[execute_id] = empty(GuardianConfigs)
     self.guardian_name_id[_guardian] = empty(uint256)

     log GuardianAdded(_account, _guardian)


@external
def cancel_guardian_addition(_account: address, _guardian: address):
     assert _guardian != empty(address) and _account != _guardian, "Ape: invalid address"
     _owner: address = ApeAccount(_account).owner()
     assert _guardian != _owner, "Ape: guardian cannot be owner"

     assert msg.sender in [_account, self.owner], "Ape: only self/owner"
     assert not self._is_lock(_account), "Ape: locked"

     execute_id: bytes32 = keccak256(_abi_encode(_account, _guardian, "addition"))
     guardian_pending: GuardianConfigs = self.pending[execute_id]
     
     assert guardian_pending.pending > 0, "Ape: unknow pending addition"
     
     self.pending[execute_id] = empty(GuardianConfigs)
     log GuardianAdditionCancelled(_account, _guardian)


@external
def revoke_guardian(_account: address, _guardian: address):
     assert _guardian != empty(address) and _account != _guardian, "Ape: invalid address"
     _owner: address = ApeAccount(_account).owner()
     assert _guardian != _owner, "Ape: guardian cannot be owner"
     
     assert msg.sender == _account, "Ape: only self"
     assert not self._is_lock(_account), "Ape: locked"
     assert self.guardian[_account][_guardian], "Ape: must be existing guardian"
     assert self.guardian_active_count[_account] > 1, "Ape: least one guardian exists"
     
     execute_id: bytes32 = keccak256(_abi_encode(_account, _guardian, "revokation"))
     assert self.pending[execute_id].pending == 0, "Ape: duplicate guardian pending revoke"
     
     self.pending[execute_id] = GuardianConfigs({account: _account, guardian: _guardian, pending: block.timestamp + security_period})
     log GuardianRevokationRequested(_account, _guardian, block.timestamp + security_period)


@external
def config_guardian_revoke(_account: address, _guardian: address):
     assert _guardian != empty(address) and _account != _guardian, "Ape: invalid address"
     _owner: address = ApeAccount(_account).owner()
     assert _guardian != _owner, "Ape: guardian cannot be owner"

     assert not self._is_lock(_account), "Ape: locked"
     assert self.guardian[_account][_guardian], "Ape: must be existing guardian"

     execute_id: bytes32 = keccak256(_abi_encode(_account, _guardian, "revokation"))
     guardian_pending: GuardianConfigs = self.pending[execute_id]
     
     assert guardian_pending.pending > 0, "Ape: unknow pending revokation"
     assert guardian_pending.pending < block.timestamp, "Ape: pending revokation not over"

     last_guradian_index: uint256 = self.guardian_active_count[_account] - 1
     guardian_index: uint256 = self.guardian_active_index[_account][_guardian]

     if last_guradian_index != guardian_index:
          last_guardian: address = self.guardian_active[_account][last_guradian_index]
          self.guardian_active[_account][guardian_index] = last_guardian
          self.guardian_active_index[_account][last_guardian] = guardian_index

     self.guardian_active_index[_account][_guardian] = empty(uint256)
     self.guardian_active[_account][last_guradian_index] = empty(address)
     self.guardian[_account][_guardian] = False
     self.guardian_active_count[_account] -= 1
     self.pending[execute_id] = empty(GuardianConfigs)
     log GuardianRevoked(_account, _guardian)


@external
def cancel_guardian_revoke(_account: address, _guardian: address):
     assert _guardian != empty(address) and _account != _guardian, "Ape: invalid address"
     _owner: address = ApeAccount(_account).owner()
     assert _guardian != _owner, "Ape: guardian cannot be owner"

     assert msg.sender == _account, "Ape: only self"

     assert not self._is_lock(_account), "Ape: locked"

     execute_id: bytes32 = keccak256(_abi_encode(_account, _guardian, "revokation"))
     guardian_pending: GuardianConfigs = self.pending[execute_id]
     
     assert guardian_pending.pending > 0, "Ape: unknow pending revokation"

     self.pending[execute_id] = empty(GuardianConfigs)
     log GuardianRevokationCancelled(_account, _guardian)


@external
def execute_recovery(_account: address, _recovery: address):
     assert _account != empty(address) and _recovery != empty(address), "Ape: empty address"
     assert not self.guardian[_account][_recovery], "Ape: new owner connet be guardian"

     assert msg.sender == _account, "Ape: only self"

     self.guardian_configs[_account] = RecoveryConfig({recovery: _recovery, execute_after: block.timestamp + recovery_period})
     self._set_lock(_account)

     log RecoveryExecuted(_account, _recovery, block.timestamp + recovery_period)


@external
def finalize_recovery(_account: address):
     assert block.timestamp > self.guardian_configs[_account].execute_after, "Ape: recovery period"

     self._set_unlock(_account)

     # set new signer
     recovery: address = self.guardian_configs[_account].recovery
     assert AccountsProxy(self.proxy).authorise_signer(_account, recovery), "Ape: recovery fail"

     self.guardian_configs[_account] = empty(RecoveryConfig)

     log RecoveryFinalized(_account, recovery)


@external
def execute_recovery_with_permit(_account: address, _parameters: DynArray[RecoveryPermit, max_value(uint8)]):
     assert msg.sender == _account, "Ape: only self"
     assert self._is_lock(_account), "Ape: unlocked"

     recovery: address = self.guardian_configs[_account].recovery
     guardian_arr: DynArray[address, max_value(uint8)] = []

     for param in _parameters:
          assert self.guardian_configs[_account].execute_after < param.sign_time, "Ape: recovery period"
          assert recovery == param.recovery, "Ape: not sure recovery"
          assert _account == param.account, "Ape: not sure account"

          if self.guardian_name_id[param.guardian] != 0:
               assert param.signer == param.guardian, "Ape: not sure signer/guardian"
          assert self.guardian[_account][param.guardian], "Ape: not guardian"
          guardian_arr.append(param.guardian)

          recovery_hash: bytes32 = self._recovery_permit_hash(param)
          assert SignatureChecker(self.signature).is_valid_signature_now(param.signer, recovery_hash, param.owner_signature), "Ape: signature fail"

     assert len(_parameters) == len(guardian_arr), "Ape: invalid guardian signature"

     self._set_unlock(_account)
     assert AccountsProxy(self.proxy).authorise_signer(_account, recovery), "Ape: recovery fail"

     self.guardian_configs[_account] = empty(RecoveryConfig)
     
     log RecoveryFinalized(_account, recovery)


@external
def cancel_account_recovery(_account: address):
     assert msg.sender == _account, "Ape: only self"

     recovery: address = self.guardian_configs[_account].recovery
     self.guardian_configs[_account] = empty(RecoveryConfig)

     self._set_unlock(_account)
     log RecoveryCanceled(_account, recovery)


@external
def lock(_account: address):
     assert self.guardian[_account][msg.sender] or msg.sender == _account, "Ape: must be guardian/self"
     assert not self._is_lock(_account), "Ape: already locked"

     self._set_lock(_account)


@external
def unlock(_account: address):
     assert self.guardian[_account][msg.sender], "Ape: must be guardian"
     assert self._is_lock(_account), "Ape: unlocked"
     
     self._set_unlock(_account)


@external
def daily_withdrawl_limit(_account: address, _max_limit: uint256):
     assert self.guardian[_account][msg.sender] or msg.sender == _account, "Ape: must be guardian/self"
     assert not self._is_lock(_account), "Ape: already locked"

     self.daily_withdrawl_limit_for_native[_account] = _max_limit
     
     log SetWithdrawlLimit(_account, _max_limit)


@external
def transfer_ownership(_account: address, _new_signer: address):
     assert msg.sender == _account, "Ape: only self"
     assert not self._is_lock(_account), "Ape: already locked"

     assert AccountsProxy(self.proxy).authorise_signer(_account, _new_signer), "Ape: transfer fail"

     old_signer: address = ApeAccount(_account).signer()

     log TransferOnwership(_account, _new_signer, old_signer)


@external
def set_owner(_new_owner: address):
     assert msg.sender == self.owner, "Ape: only owner"

     old_owner: address = self.owner
     self.owner = _new_owner

     log ChangeOwner(old_owner, _new_owner)


@external
def initialize_default_guardian(_account: address, _guardian: address):
     assert msg.sender == self.factory, "Ape: only factory"

     self.guardian[_account][_guardian] = True
     self.guardian_active[_account][self.guardian_active_count[_account]] = _guardian
     self.guardian_active_index[_account][_guardian] = self.guardian_active_count[_account]
     self.guardian_active_count[_account] += 1
     log GuardianAdded(_account, _guardian)

     self.daily_withdrawl_limit_for_native[_account] = max_value(uint256)
     log SetWithdrawlLimit(_account, max_value(uint256))



@external
def set_factory(_new_factory: address):
     assert msg.sender == self.owner, "Ape: only owner"

     old_factory: address = self.factory
     self.factory = _new_factory
     
     log ChangeFactory(old_factory, _new_factory)


@external
def set_proxy(_new_proxy: address):
     assert msg.sender == self.owner, "Ape: only owner"

     old_proxy: address = self.proxy
     self.proxy = _new_proxy
     
     log ChangeFactory(old_proxy, _new_proxy)
