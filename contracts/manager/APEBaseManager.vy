# @version 0.3.9
"""
@title Ape Wallet APEBaseManager
@author zkApes
@license Copyright (c) zkApes, 2022-2023 - all rights reserved
"""


interface APESecurityManager:
    def get_guardian_count(_account: address) -> uint256: view
    def is_guardian(_account: address, _guardian: address) -> bool: view

interface APEOracleManager:
    def in_token(_token: address, _eth_amount: uint256) -> uint256: view
    def in_eth(_token: address, _token_amount: uint256) -> uint256: view

interface SignatureChecker:
    def recover_sig(_hash: bytes32, _signature: Bytes[65]) -> address: view
    def is_valid_signature_now(_signer: address, _hash: bytes32, _signature: Bytes[65]) -> bool: view

interface APELibraryManager:
	def modules_library(_module_id: uint256) -> address: view
	def reload_nonce(_account: address, _nonce: uint256) -> bool: nonpayable
	def nonce(_account: address) -> uint256: view

event AddAuthoriseRelayer:
    _relayer: indexed(address)
    _exists: bool

event RemoveAuthoriseRelayer:
    _relayer: indexed(address)
    _exists: bool

event AddedToWhitelist:
    _wallet: indexed(address)
    _target: indexed(address)
    _period: uint256

event RemovedForWhitelist:
    _wallet: indexed(address)
    _target: indexed(address)

event TranscationExecuted:
     _wallet: indexed(address)
     _success: bool
     _return_data: Bytes[max_value(uint16)]

event Refund:
     _wallet: indexed(address)
     _refund_address: indexed(address)
     _refund_token: address
     _refund_amount: uint256

event ChangeAdmin:
    _old_admin: indexed(address)
    _new_admin: indexed(address)

event ChangeLibrary:
    _old_library: indexed(address)
    _new_library: indexed(address)


struct ExecuteParameters:
    owner: address
    account: address
    transaction_to: address
    transaction_calldata: Bytes[4096]
    transaction_value: uint256
    nonce: uint256
    gas_price: uint256
    gas_limit: uint256
    deadline: uint256
    refund_token: address
    refund_address: address
    signature: Bytes[1980]


IERC1271_ISVALIDSIGNATURE_SELECTOR: public(constant(bytes4)) = 0x1626BA7E

EXECUTE_PARAMETERS_TYPEHASH: constant(bytes32) = keccak256(
    "ExecuteParameters(address owner,address account,address transaction_to,uint256 transaction_value,uint256 nonce,uint256 gas_price,uint256 gas_limit,uint256 deadline,address refund_token,address refund_address)"
)
EIP712_TYPEHASH: constant(bytes32) = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
DOMAIN_SEPARATOR: public(immutable(bytes32))

authorise_relayer: HashMap[address, bool]
whitelist_period: public(uint256)
whitelist: HashMap[address, HashMap[address, uint256]]
expired_hash: public(HashMap[bytes32, bool])

library: public(address)
admin: public(address)


@payable
@external
def __init__(_whitelist_period: uint256, _library: address):
    self.admin = msg.sender

    self.authorise_relayer[msg.sender] = True
    self.whitelist_period = _whitelist_period

    self.library = _library

    name: String[64] = concat("Ape Wallet Base Manager", " v1")
    version: String[8] = "v1.0.0"

    DOMAIN_SEPARATOR = keccak256(
        _abi_encode(EIP712_TYPEHASH, keccak256(name), keccak256(version), chain.id, self)
    )


@view
@internal
def _is_authorise_relayer(_relayer: address) -> bool:
    return self.authorise_relayer[_relayer]


@view
@internal
def _get_oracle() -> address:
    return APELibraryManager(self.library).modules_library(6)


@view
@internal
def _get_security() -> address:
    return APELibraryManager(self.library).modules_library(5)


@view
@internal
def _get_signature() -> address:
    return APELibraryManager(self.library).modules_library(0)


@view
@internal
def _is_whitelist(_wallet: address, _target: address) -> bool:
    assert _wallet != _target, "APE012"

    _iw: bool = False
    if self.whitelist[_wallet][_target] != 0:
        _iw = True
    return _iw


@view
@internal
def _execute_parameters_hash(_param: ExecuteParameters) -> bytes32:

    param_hash: bytes32 = keccak256(
        _abi_encode(
            EXECUTE_PARAMETERS_TYPEHASH,
            _param.owner,
            _param.account,
            _param.transaction_to,
            _param.transaction_value,
            _param.nonce,
            _param.gas_price,
            _param.gas_limit,
            _param.deadline,
            _param.refund_token,
            _param.refund_address
        )
    )

    digest: bytes32 = keccak256(
        concat(
            b"\x19\x01",
            DOMAIN_SEPARATOR,
            param_hash
        )
    )

    return digest


@view
@internal
def _get_method_id(_data: Bytes[4096]) -> bytes4:
    assert len(_data) != 0, "APE300"

    method: bytes4 = convert(slice(_data, 0, 4), bytes4)
    return method


@view
@internal
def _get_guardian_approvals_count(_account: address, _security: address) -> uint256:

    gac: uint256 = APESecurityManager(_security).get_guardian_count(_account)
    return convert(ceil(convert(gac, decimal) / convert(2, decimal)), uint256)


@view
@internal
def _recover_sig(_hash: bytes32, _signature: Bytes[1980], _slice: uint256) -> address:

    _data: Bytes[65] = slice(_signature, _slice, 65)
    signer: address = SignatureChecker(self._get_signature()).recover_sig(_hash, _data)

    return signer


@view
@internal
def _valid_account_signature(_account: address, _hash: bytes32, _signature: Bytes[65]) -> bytes4:

	response: Bytes[255] = raw_call(
		_account,
		_abi_encode(
			_hash,
			_signature,
			method_id=method_id("isValidSignature(bytes32,bytes)")
		),
		max_outsize=255,
		is_static_call=True
	)

	return convert(convert(slice(response, 64, 32), bytes32), bytes4)


@view
@internal
def _check_nonce(_library: address, _account: address, _nonce: uint256):
	account_nonce: uint256 = APELibraryManager(_library).nonce(_account)
	assert _nonce > account_nonce, "Invalid nonce"


@view
@internal
def _get_required_signatures_from_account(
    _account: address,
    _security: address,
    _data: Bytes[4096]
) -> (uint256, uint256):

    if len(_data) != 0:
        method: bytes4 = self._get_method_id(_data)

        if method == method_id("config_guardian_addition(address,address)", output_type=bytes4) or \
            method == method_id("config_guardian_revoke(address,address)", output_type=bytes4) or \
            method == method_id("finalize_recovery(address)", output_type=bytes4):
            # anyone
            return (0, 5)

        if method == method_id("add_guardian(address,address)", output_type=bytes4) or \
            method == method_id("cancel_guardian_addition(address,address)", output_type=bytes4) or \
            method == method_id("revoke_guardian(address,address)", output_type=bytes4) or \
            method == method_id("cancel_guardian_revoke(address,address)", output_type=bytes4) or \
            method == method_id("token_bound_accounts(address,address,uint256)", output_type=bytes4) or \
			method == method_id("upgrade_signer(address,address)", output_type=bytes4) or \
			method == method_id("transfer_ownership(address,address)", output_type=bytes4):
            # only owner
            return (1, 1)

        if method == method_id("execute_recovery(address,address)", output_type=bytes4):
            gac: uint256 = self._get_guardian_approvals_count(_account, _security)
            assert gac > 0, "Ape: insufficient guardian"
            # more guardian
            return (gac, 6)

        if method == method_id("cancel_account_recovery(address)", output_type=bytes4):
            gac: uint256 = APESecurityManager(_security).get_guardian_count(_account)
            return (convert(ceil(convert((gac+1)/2, decimal)), uint256), 3)

        if method == method_id("lock(address)", output_type=bytes4) or \
            method == method_id("unlock(address)", output_type=bytes4) or \
            method == method_id("daily_withdrawl_limit(address,uint256)", output_type=bytes4):
            # any guardian
            return (1, 2)

    gac: uint256 = self._get_guardian_approvals_count(_account, _security)

    # owner + more guardian
    return (gac + 1, 4)


@view
@internal
def _check_and_valid_signature(
    _account: address,
    _security: address,
    _hash: bytes32,
    _signature: Bytes[1980],
    _option: uint256
) -> bool:

    if len(_signature) == 0:
        return True

    for i in range(255):
        if i >= (len(_signature) / 65):
            break

        signer: address = self._recover_sig(_hash, _signature, i*65)

        if i == 0:
            _data: Bytes[65] = slice(_signature, 0, 65)
            if _option == 1 or _option == 4:
                if IERC1271_ISVALIDSIGNATURE_SELECTOR == self._valid_account_signature(_account, _hash, _data):
                    continue
                return False
            elif _option == 3:
                if IERC1271_ISVALIDSIGNATURE_SELECTOR == self._valid_account_signature(_account, _hash, _data):
                    continue

        if signer == empty(address):
            return False

        is_guardian: bool = APESecurityManager(_security).is_guardian(_account, signer)

        if not is_guardian:
            return False

    return True


@internal
def _refund(
	_account: address,
	_start_gas: uint256,
	_gas_price: uint256,
	_gas_limit: uint256,
	_refund_token: address,
	_refund_address: address
) -> bool:

	if _gas_price > 0:
		assert _refund_address != empty(address), "APE301"

		refund_amount: uint256 = 0

		# empty(address) is ETH
		if _refund_token == empty(address):

			gas_consumed: uint256 = _start_gas - msg.gas + 23000
			refund_amount = _gas_limit * min(_gas_price, tx.gasprice)

			raw_call(
				_account,
				_abi_encode(
					_refund_address,
					refund_amount,
					b"",
					method_id=method_id("execute(address,uint256,bytes)")
				)
			)

		else:
			gas_consumed: uint256 = _start_gas - msg.gas + 37500

			# Here it is also necessary to calculate how many tokens the gas price can be exchanged for
			# Then the final gas fee to be paid is obtained by gaslimit * token price
			token_gas_price: uint256 = APEOracleManager(self._get_oracle()).in_token(_refund_token, tx.gasprice)
			# token_gas_price: uint256 = tx.gasprice
			refund_amount = min(gas_consumed, _gas_limit) + min(_gas_price, token_gas_price)

			success: bool = False
			response: Bytes[32] = b""

			success, response = raw_call(
				_account,
				_abi_encode(
					_refund_token,
					empty(uint256),
					_abi_encode(
						_refund_address,
						refund_amount,
						method_id=method_id("transfer(address,uint256)")
					),
					method_id=method_id("execute(address,uint256,bytes)")
				),
				max_outsize=32,
				revert_on_failure=False
			)

			if len(response) != 0:
				assert convert(response, bool)

			assert success, "APE002"

		log Refund(_account, _refund_address, _refund_token, refund_amount)

	return True


@view
@external
def is_authorise_relayer(_relayer: address) -> bool:
    return self._is_authorise_relayer(_relayer)


@view
@external
def is_whitelist(_wallet: address, _target: address) -> bool:
    return self._is_whitelist(_wallet, _target)


@view
@external
def signature() -> address:
    return self._get_signature()


@view
@external
def oracle() -> address:
    return self._get_oracle()


@view
@external
def security() -> address:
    return self._get_security()


@external
def add_authorise_relayer(_relayers: DynArray[address, 30]):
    assert msg.sender == self.admin, "APE010"

    for relayer in _relayers:
        self.authorise_relayer[relayer] = True
        log AddAuthoriseRelayer(relayer, True)


@external
def remove_authorise_relayer(_relayer: address):
    assert msg.sender == self.admin, "APE010"

    self.authorise_relayer[_relayer] = False
    log RemoveAuthoriseRelayer(_relayer, False)


@external
def add_whitelist(_wallet: address, _target: address):
    assert not self._is_whitelist(_wallet, _target), "APE013"
    assert msg.sender == self.admin, "APE010"

    whitelistAfter: uint256 = block.timestamp + self.whitelist_period
    self.whitelist[_wallet][_target] = whitelistAfter

    log AddedToWhitelist(_wallet, _target, whitelistAfter)


@external
def remove_whitelist(_wallet: address, _target: address):
    assert msg.sender == self.admin, "APE010"

    self.whitelist[_wallet][_target] = 0

    log RemovedForWhitelist(_wallet, _target)


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


@external
def withdraw(_token: address, _amount: uint256) -> bool:
    assert msg.sender == self.admin, "APE010"

    raw_call(
        _token,
        _abi_encode(
            msg.sender,
            _amount,
            method_id=method_id("transfer(address,uint256)")
        )
    )

    return True


@external
def execute(_param: ExecuteParameters) -> bool:
	assert self._is_authorise_relayer(msg.sender), "APE014"
	assert block.timestamp <= _param.deadline, "APE015"

	# gas = 21k + non zero byte * 16 + zero byte * 4
	#     ~= 21k + len(msg.data) * [1/3 * 16 + 2/3 * 4]
	start_gas: uint256 = msg.gas + 21000 + len(msg.data) * 8
	assert start_gas >= _param.gas_limit, "APE203"

	digest: bytes32 = self._execute_parameters_hash(_param)
	assert not self.expired_hash[digest], "APE016"

	number_of_sig: uint256 = 0
	option: uint256 = 0
	sec: address = self._get_security()

	number_of_sig, option = self._get_required_signatures_from_account(_param.account, sec, _param.transaction_calldata)
	assert number_of_sig > 0 or option == 5, "APE303"
	assert number_of_sig * 65 == len(_param.signature), "APE500"
	assert self._check_and_valid_signature(_param.account, sec, digest, _param.signature, option), "APE501"

	lib: address = self.library
	self._check_nonce(lib, _param.account, _param.nonce)

	refund_success: bool = self._refund(
	    _param.account,
	    start_gas,
	    _param.gas_price,
	    _param.gas_limit,
	    _param.refund_token,
	    _param.refund_address
	)

	assert refund_success, "APE004"

	success: bool = False
	response: Bytes[32] = b""

	success, response = raw_call(
	    _param.account,
	    _abi_encode(
	        _param.transaction_to,
	        _param.transaction_value,
	        _param.transaction_calldata,
	        method_id=method_id("execute(address,uint256,bytes)")
	    ),
	    max_outsize=32,
	    revert_on_failure=False
	)

	if len(response) != 0:
	    assert convert(response, bool)

	assert success, "APE002"

	assert APELibraryManager(lib).reload_nonce(_param.account, _param.nonce), "APE101"

	log TranscationExecuted(_param.account, success, response)
	return success

