# @version 0.3.9
"""
@title Ape Wallet APESecurityManager
@author zkApes
@license Copyright (c) zkApes, 2022-2023 - all rights reserved
"""


interface APELibraryManager:
	def owner(_account: address) -> address: view
	def signer(_account: address) -> address: view
	def account_detail(_account: address) -> AccountDetail: view
	def is_authorise(_module: address) -> bool: view
	def modules_library(_module_id: uint256) -> address: view
	def reload_account(_account: address, _account_detail: AccountDetail) -> bool: nonpayable


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

event ChangeAdmin:
	old_admin: indexed(address)
	new_admin: indexed(address)

event ChangeLibrary:
	old_library: indexed(address)
	new_library: indexed(address)

struct RecoveryConfig:
	recovery: address
	execute_after: uint256

struct GuardianConfigs:
	account: address
	guardian: address
	pending: uint256

struct AccountDetail:
	chain_id: uint256
	token_contract: address
	token_id: uint256
	creator: address
	signer: address
	create_time: uint256

DAY: public(constant(uint256)) = 86400

RECOVERY_PERIOD: public(immutable(uint256))
LOCK_PERIOD: public(immutable(uint256))
SECURITY_PERIOD: public(immutable(uint256))

pending: HashMap[bytes32, GuardianConfigs]
guardian_configs: HashMap[address, RecoveryConfig]
guardian: HashMap[address, HashMap[address, bool]]
guardian_active: HashMap[address, HashMap[uint256, address]]
guardian_active_index: HashMap[address, HashMap[address, uint256]]
guardian_active_count: HashMap[address, uint256]
guardian_by_others: public(HashMap[address, HashMap[uint256, address]])
guardian_by_others_index: public(HashMap[address, uint256])
guardian_by_others_count: public(HashMap[address, HashMap[address, uint256]])
guardian_name_id: public(HashMap[address, uint256])
locked: HashMap[address, uint256]

account_active_time: public(HashMap[address, uint256])
daily_transfer: public(HashMap[address, HashMap[uint256, uint256]])
daily_withdrawl_limit_for_native: public(HashMap[address, uint256])

admin: public(address)
library: public(address)


@external
def __init__(
	_recovery_period: uint256,
	_lock_period: uint256,
	_security_period: uint256,
	_library: address
):

	assert _lock_period >= _recovery_period

	self.admin = msg.sender
	self.library = _library

	RECOVERY_PERIOD = _recovery_period
	LOCK_PERIOD = _lock_period
	SECURITY_PERIOD = _security_period


@view
@internal
def _is_lock(_account: address) -> bool:
	period: uint256 = self.locked[_account]

	if block.timestamp <= period:
		return True

	return False


@view
@internal
def _check_account(_caller: address, _account: address, _index: uint256):
	assert _caller != empty(address), "APE301"

	owner: address = APELibraryManager(self.library).owner(_account)
	signer: address = APELibraryManager(self.library).signer(_account)

	if _index == 0:
		# only self/owner/signer
		assert _caller in [_account, owner, signer], "APE017"

	elif _index == 1:
		# only guradian
		assert self.guardian[_account][_caller], "APE018"

	elif _index == 2:
		# only guradian
		assert self.guardian[_account][_caller] or _caller in [_account, owner, signer], "APE017"


@internal
def _set_lock(_account: address):
	self.locked[_account] = block.timestamp + LOCK_PERIOD
	log Locked(_account, block.timestamp + LOCK_PERIOD)


@internal
def _set_unlock(_account: address):
     self.locked[_account] = 0
     log Unlocked(_account)


@internal
def _upgrade_signer(_account: address, _new_signer: address):
	lib: address = self.library
	account: AccountDetail = APELibraryManager(lib).account_detail(_account)

	new_account_detail: AccountDetail = AccountDetail({
		chain_id: account.chain_id,
		token_contract: account.token_contract,
		token_id: account.token_id,
		creator: account.creator,
		signer: _new_signer,
		create_time: account.create_time
	})

	assert APELibraryManager(lib).reload_account(_account, new_account_detail), "APE101"


@internal
def _upgrade_daily_limit(_account: address, _value: uint256):
	lib: address = self.library
	account: AccountDetail = APELibraryManager(lib).account_detail(_account)

	dt0: uint256 = block.timestamp - account.create_time

	if dt0 >= DAY:
		self.account_active_time[_account] = dt0 / DAY

	ac_time: uint256 = self.account_active_time[_account]
	daily_limit: uint256 = self.daily_withdrawl_limit_for_native[_account]
	self.daily_transfer[_account][ac_time] += _value

	assert self.daily_transfer[_account][ac_time] <= daily_limit, "APE306"


@view
@external
def is_lock(_account: address) -> bool:
	return self._is_lock(_account)


@view
@external
def get_lock_period(_account: address) -> uint256:
	return self.locked[_account]


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
	assert not _guardian in [empty(address), _account], "APE303"
	self._check_account(msg.sender, _account, 0)

	assert not self.guardian[_account][_guardian], "APE304"
	assert not self._is_lock(_account), "APE020"

	execute_id: bytes32 = keccak256(_abi_encode(_account, _guardian, "addition"))
	assert self.pending[execute_id].pending == 0, "APE304"

	self.pending[execute_id] = GuardianConfigs({account: _account, guardian: _guardian, pending: block.timestamp + SECURITY_PERIOD})
	log GuardianAdditionRequestsed(_account, _guardian, block.timestamp + SECURITY_PERIOD)


@external
def config_guardian_addition(_account: address, _guardian: address):
	assert not self._is_lock(_account), "APE202"

	execute_id: bytes32 = keccak256(_abi_encode(_account, _guardian, "addition"))
	guardian_pending: GuardianConfigs = self.pending[execute_id]

	assert guardian_pending.pending > 0, "APE200"
	assert guardian_pending.pending < block.timestamp, "APE201"

	self.guardian[_account][_guardian] = True
	self.guardian_active[_account][self.guardian_active_count[_account]] = _guardian
	self.guardian_active_index[_account][_guardian] = self.guardian_active_count[_account]
	self.guardian_active_count[_account] += 1
	self.pending[execute_id] = empty(GuardianConfigs)
	self.guardian_name_id[_guardian] = empty(uint256)
	self.guardian_by_others_count[_guardian][_account] = self.guardian_by_others_index[_guardian]
	self.guardian_by_others[_guardian][self.guardian_by_others_index[_guardian]] = _account
	self.guardian_by_others_index[_guardian] += 1

	log GuardianAdded(_account, _guardian)


@external
def cancel_guardian_addition(_account: address, _guardian: address):
	self._check_account(msg.sender, _account, 0)

	assert not self._is_lock(_account), "APE020"

	execute_id: bytes32 = keccak256(_abi_encode(_account, _guardian, "addition"))
	guardian_pending: GuardianConfigs = self.pending[execute_id]

	assert guardian_pending.pending > 0, "APE200"

	self.pending[execute_id] = empty(GuardianConfigs)
	log GuardianAdditionCancelled(_account, _guardian)


@external
def revoke_guardian(_account: address, _guardian: address):
	assert not _guardian in [empty(address), _account], "APE303"
	self._check_account(msg.sender, _account, 0)

	assert not self._is_lock(_account), "APE020"
	assert self.guardian[_account][_guardian], "APE202"
	assert self.guardian_active_count[_account] > 1, "APE203"

	execute_id: bytes32 = keccak256(_abi_encode(_account, _guardian, "revokation"))
	assert self.pending[execute_id].pending == 0, "APE204"

	self.pending[execute_id] = GuardianConfigs({account: _account, guardian: _guardian, pending: block.timestamp + SECURITY_PERIOD})
	log GuardianRevokationRequested(_account, _guardian, block.timestamp + SECURITY_PERIOD)


@external
def config_guardian_revoke(_account: address, _guardian: address):
	assert not self._is_lock(_account), "APE020"
	assert self.guardian[_account][_guardian], "APE202"

	execute_id: bytes32 = keccak256(_abi_encode(_account, _guardian, "revokation"))
	guardian_pending: GuardianConfigs = self.pending[execute_id]

	assert guardian_pending.pending > 0, "APE200"
	assert guardian_pending.pending < block.timestamp, "APE201"

	last_guradian_index: uint256 = self.guardian_active_count[_account] - 1
	guardian_index: uint256 = self.guardian_active_index[_account][_guardian]

	if last_guradian_index != guardian_index:
		last_guardian: address = self.guardian_active[_account][last_guradian_index]
		self.guardian_active[_account][guardian_index] = last_guardian
		self.guardian_active_index[_account][last_guardian] = guardian_index

	last_account_index: uint256 = self.guardian_by_others_index[_guardian] - 1
	now_account_index: uint256 = self.guardian_by_others_count[_guardian][_account]

	if last_account_index != now_account_index:
		last_account: address = self.guardian_by_others[_guardian][last_account_index]
		self.guardian_by_others[_guardian][now_account_index] = last_account
		self.guardian_by_others_count[_guardian][last_account] = now_account_index

	self.guardian_active_index[_account][_guardian] = empty(uint256)
	self.guardian_active[_account][last_guradian_index] = empty(address)
	self.guardian[_account][_guardian] = False
	self.guardian_active_count[_account] -= 1
	self.guardian_by_others[_guardian][last_account_index] = empty(address)
	self.guardian_by_others_count[_guardian][_account] = empty(uint256)
	self.guardian_by_others_index[_guardian] -= 1
	self.pending[execute_id] = empty(GuardianConfigs)
	log GuardianRevoked(_account, _guardian)


@external
def cancel_guardian_revoke(_account: address, _guardian: address):
	self._check_account(msg.sender, _account, 0)

	assert not self._is_lock(_account), "APE020"

	execute_id: bytes32 = keccak256(_abi_encode(_account, _guardian, "revokation"))
	guardian_pending: GuardianConfigs = self.pending[execute_id]

	assert guardian_pending.pending > 0, "APE200"

	self.pending[execute_id] = empty(GuardianConfigs)
	log GuardianRevokationCancelled(_account, _guardian)


@external
def execute_recovery(_account: address, _recovery: address):
	assert not empty(address) in [_account, _recovery], "APE301"
	assert not self.guardian[_account][_recovery], "APE304"
	self._check_account(msg.sender, _account, 1)

	self.guardian_configs[_account] = RecoveryConfig({recovery: _recovery, execute_after: block.timestamp + RECOVERY_PERIOD})
	self._set_lock(_account)

	log RecoveryExecuted(_account, _recovery, block.timestamp + RECOVERY_PERIOD)


@external
def finalize_recovery(_account: address):
	assert block.timestamp > self.guardian_configs[_account].execute_after, "APE015"

	self._set_unlock(_account)

	# set new signer
	recovery: address = self.guardian_configs[_account].recovery
	self._upgrade_signer(_account, recovery)

	self.guardian_configs[_account] = empty(RecoveryConfig)

	log RecoveryFinalized(_account, recovery)


@external
def cancel_account_recovery(_account: address):
	self._check_account(msg.sender, _account, 0)

	recovery: address = self.guardian_configs[_account].recovery
	self.guardian_configs[_account] = empty(RecoveryConfig)

	self._set_unlock(_account)
	log RecoveryCanceled(_account, recovery)


@external
def lock(_account: address):
	self._check_account(msg.sender, _account, 2)
	assert not self._is_lock(_account), "APE020"

	self._set_lock(_account)


@external
def unlock(_account: address):
	self._check_account(msg.sender, _account, 2)
	assert self._is_lock(_account), "APE020"

	self._set_unlock(_account)


@external
def daily_withdrawl_limit(_account: address, _max_limit: uint256):
	self._check_account(msg.sender, _account, 2)
	assert not self._is_lock(_account), "APE020"

	self.daily_withdrawl_limit_for_native[_account] = _max_limit

	log SetWithdrawlLimit(_account, _max_limit)


@external
def transfer_ownership(_account: address, _new_signer: address):
	self._check_account(msg.sender, _account, 0)
	assert not self._is_lock(_account), "APE020"

	self._upgrade_signer(_account, _new_signer)

	log TransferOnwership(_account, _new_signer)


@external
def initialize_default_guardian(_account: address, _guardian: address) -> bool:
	assert APELibraryManager(self.library).is_authorise(msg.sender)

	self.guardian[_account][_guardian] = True
	self.guardian_active[_account][self.guardian_active_count[_account]] = _guardian
	self.guardian_active_index[_account][_guardian] = self.guardian_active_count[_account]
	self.guardian_active_count[_account] += 1
	log GuardianAdded(_account, _guardian)

	self.daily_withdrawl_limit_for_native[_account] = max_value(uint256)
	log SetWithdrawlLimit(_account, max_value(uint256))
	return True


@external
def upgrade_daily_limit(_account: address, _amount: uint256) -> bool:
	self._check_account(msg.sender, _account, 0)
	self._upgrade_daily_limit(_account, _amount)

	return True


@external
def change_admin(_new_admin: address):
	assert msg.sender == self.admin, "APE010"

	old_admin: address = self.admin
	self.admin = _new_admin
	log ChangeAdmin(old_admin, _new_admin)


@external
def change_library(_new_library: address):
	assert msg.sender == self.admin, "APE010"

	old_library: address = self.library
	self.library = _new_library
	log ChangeLibrary(old_library, _new_library)





