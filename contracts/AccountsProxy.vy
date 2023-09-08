# @version 0.3.7

interface ApeAccount:
    def authorise_proxy(_module: address) -> bool: nonpayable
    def authorise_signer(_signer: address) -> bool: nonpayable
    def token_bound_accounts(_token: address, _token_id: uint256) -> bool: nonpayable
    def execute(_target: address, _value: uint256, _data: Bytes[max_value(uint16)]) -> bool: nonpayable

interface SecurityManager:
    def is_lock(_account: address) -> bool: view

event AuthoriseModules:
    _authorise: indexed(address)
    _status: bool

event SetSecurity:
    _old_security: indexed(address)
    _new_security: indexed(address)

is_authorise: public(HashMap[address, bool])
admin: public(address)
security: public(address)


@external
def __init__(_security: address):
    self.admin = msg.sender
    self.security = _security


@payable
@external
def __default__():
    pass


@internal
def _is_lock(_account: address) -> bool:
    return SecurityManager(self.security).is_lock(_account)


@external
def authorise_module(_module: address) -> bool:
    assert not self.is_authorise[_module], "Already authorise"
    assert msg.sender == self.admin

    self.is_authorise[_module] = True

    log AuthoriseModules(_module, True)
    return True


@external
def set_security(_new_security: address) -> bool:
    assert msg.sender == self.admin

    old_security: address = self.security
    self.security = _new_security

    log SetSecurity(old_security, _new_security)
    return True


@external
def authorise_proxy(_account: address, _new_proxy: address) -> bool:
    assert self.is_authorise[msg.sender] or msg.sender == _account, "only module"
    assert not empty(address) in [_account, _new_proxy], "empty address"
    assert not self._is_lock(_account), "account locked"
 
    ApeAccount(_account).authorise_proxy(_new_proxy)

    return True


@external
def authorise_signer(_account: address, _new_signer: address) -> bool:
    assert self.is_authorise[msg.sender], "only module"
    assert not empty(address) in [_account, _new_signer], "empty address"
    assert not self._is_lock(_account), "account locked"
 
    ApeAccount(_account).authorise_signer(_new_signer)

    return True


@external
def token_bound_accounts(_account: address, _token: address, _token_id: uint256) -> bool:
    assert self.is_authorise[msg.sender] or msg.sender == _account, "only module"
    assert not empty(address) in [_account, _token], "empty address"

    ApeAccount(_account).token_bound_accounts(_token, _token_id)

    return True


@external
def execute(_account: address, _target: address, _value: uint256, _data: Bytes[max_value(uint16)]) -> bool:
    assert self.is_authorise[msg.sender], "only module"
    assert not empty(address) in [_account, _target], "empty address"

    ApeAccount(_account).execute(_target, _value, _data)

    return True

