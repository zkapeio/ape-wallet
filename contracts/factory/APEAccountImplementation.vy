# @version 0.3.9
"""
@title Ape Wallet zkApeAccountImplementation
@author zkApes
@license Copyright (c) zkApes, 2022-2023 - all rights reserved
"""


interface APESecurityManager:
    def is_lock(_account: address) -> bool: view
    def upgrade_daily_limit(_account: address, _amount: uint256) -> bool: nonpayable

interface APELibraryManager:
	def supports_static_call(_method: bytes4) -> bool: pure
	def token(_account: address) -> (uint256, address, uint256): view
	def owner(_account: address) -> address: view
	def signer(_account: address) -> address: view
	def nonce(_account: address) -> uint256: view
	def modules_library(_module_id: uint256) -> address: view
	def is_authorise(_module: address) -> bool: view
	def isValidSignature(_hash: bytes32, _signature: Bytes[65], _account: address) -> bytes4: view


event Received:
    _sender: indexed(address)
    _amount: uint256
    _data: Bytes[1024]

event ChangeAdmin:
    _old_admin: indexed(address)
    _new_admin: indexed(address)

event ChangeLibrary:
    _old_library: indexed(address)
    _new_library: indexed(address)

event Execute:
    _to: indexed(address)
    _value: indexed(uint256)
    _data: indexed(Bytes[max_value(uint16)])


library: public(address)
admin: public(address)


@payable
@external
def __init__(_library: address):
    self.library = _library
    self.admin = msg.sender


@view
@internal
def _check_module(_module: address) -> bool:
    return APELibraryManager(self.library).is_authorise(_module)


@view
@internal
def _enabled_method(_method: bytes4) -> address:
    lib: address = self.library
    if lib != empty(address) and APELibraryManager(self.library).supports_static_call(_method):
        return lib

    return empty(address)


@view
@external
def token() -> (uint256, address, uint256):
    return APELibraryManager(self.library).token(self)


@view
@external
def owner() -> address:
    return APELibraryManager(self.library).owner(self)


@view
@external
def signer() -> address:
    return APELibraryManager(self.library).signer(self)


@view
@external
def nonce() -> uint256:
	return APELibraryManager(self.library).nonce(self)


@view
@external
def isValidSignature(_hash: bytes32, _signature: Bytes[65]) -> bytes4:
	return APELibraryManager(self.library).isValidSignature(_hash, _signature, self)


@external
def set_admin(_new_admin: address):
    assert msg.sender == self.admin, "APE010"

    old_admin: address = self.admin
    self.admin = _new_admin
    log ChangeAdmin(old_admin, _new_admin)


@external
def set_library(_new_library: address):
    assert msg.sender == self.admin, "APE010"

    old_library: address = self.library
    self.library = _new_library
    log ChangeLibrary(old_library, _new_library)


@external
def execute(_target: address, _amount: uint256, _data: Bytes[4096]) -> bool:
	assert self._check_module(msg.sender), "APE011"

	security: address = APELibraryManager(self.library).modules_library(5)
	assert not APESecurityManager(security).is_lock(self), "APE020"

	if _amount != 0:
		assert APESecurityManager(security).upgrade_daily_limit(self, _amount), "APE021"

	success: bool = False
	response: Bytes[32] = b""

	success, response = raw_call(_target, _data, max_outsize=32, value=_amount, revert_on_failure=False)

	if len(response) != 0:
		assert convert(response, bool)

	assert success, "APE002"

	log Execute(_target, _amount, _data)
	return True


@payable
@external
def __default__() -> Bytes[32]:
	method: bytes4 = convert(slice(msg.data, 0, 4), bytes4)
	module: address = self._enabled_method(method)

	if module == empty(address):
		log Received(msg.sender, msg.value, b"")
		return b""

	assert self._check_module(module), "APE011"

	response: Bytes[32] = raw_call(
		self.library,
		msg.data,
		max_outsize=32,
		is_static_call=True
	)

	if len(response) != 0:
		assert convert(response, bool), "APE003"
	else:
		raise "non-response"

	return response

