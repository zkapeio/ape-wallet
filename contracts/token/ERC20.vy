# @version 0.3.7

from vyper.interfaces import ERC20
implements: ERC20


event Transfer:
    owner: indexed(address)
    to: indexed(address)
    amount: uint256

event Approval:
    owner: indexed(address)
    spender: indexed(address)
    amount: uint256

event OwnershipTransferred:
    previous_owner: indexed(address)
    new_owner: indexed(address)

event RoleMinterChanged:
    minter: indexed(address)
    status: bool


decimals: public(constant(uint8)) = 18
name: public(immutable(String[25]))
symbol: public(immutable(String[5]))
balanceOf: public(HashMap[address, uint256])
allowance: public(HashMap[address, HashMap[address, uint256]])
totalSupply: public(uint256)
owner: public(address)
is_minter: public(HashMap[address, bool])


@external
def __init__():

    name = "TestCoin"
    symbol = "T1"

    self._mint(msg.sender, 100000000*10**18)

    self._transfer_ownership(msg.sender)
    self.is_minter[msg.sender] = True
    log RoleMinterChanged(msg.sender, True)


@internal
def _transfer(_owner: address, _to: address, _amount: uint256):
    assert _owner != empty(address), "ERC20: transfer from the zero address"
    assert _to != empty(address), "ERC20: transfer to the zero address"

    owner_balanceOf: uint256 = self.balanceOf[_owner]
    assert owner_balanceOf >= _amount, "ERC20: transfer amount exceeds balance"
    self.balanceOf[_owner] = unsafe_sub(owner_balanceOf, _amount)
    self.balanceOf[_to] = unsafe_add(self.balanceOf[_to], _amount)
    log Transfer(_owner, _to, _amount)


@internal
def _mint(_owner: address, _amount: uint256):
    assert _owner != empty(address), "ERC20: mint to the zero address"

    self.totalSupply += _amount
    self.balanceOf[_owner] = unsafe_add(self.balanceOf[_owner], _amount)
    log Transfer(empty(address), _owner, _amount)


@internal
def _burn(_owner: address, _amount: uint256):
    assert _owner != empty(address), "ERC20: burn from the zero address"

    account_balance: uint256 = self.balanceOf[_owner]
    assert account_balance >= _amount, "ERC20: burn amount exceeds balance"
    self.balanceOf[_owner] = unsafe_sub(account_balance, _amount)
    self.totalSupply = unsafe_sub(self.totalSupply, _amount)
    log Transfer(_owner, empty(address), _amount)


@internal
def _approve(_owner: address, _spender: address, _amount: uint256):
    assert _owner != empty(address), "ERC20: approve from the zero address"
    assert _spender != empty(address), "ERC20: approve to the zero address"

    self.allowance[_owner][_spender] = _amount
    log Approval(_owner, _spender, _amount)


@internal
def _spend_allowance(_owner: address, _spender: address, _amount: uint256):

    current_allowance: uint256 = self.allowance[_owner][_spender]
    assert current_allowance >= _amount, "ERC20: insufficient allowance"
    self._approve(_owner, _spender, unsafe_sub(current_allowance, _amount))


@internal
def _check_owner():
    assert msg.sender == self.owner, "Ownable: caller is not the owner"


@internal
def _transfer_ownership(_new_owner: address):

    old_owner: address = self.owner
    self.owner = _new_owner
    log OwnershipTransferred(old_owner, _new_owner)


@external
def transfer(_to: address, _amount: uint256) -> bool:

    self._transfer(msg.sender, _to, _amount)
    return True


@external
def approve(_spender: address, _amount: uint256) -> bool:

    self._approve(msg.sender, _spender, _amount)
    return True


@external
def transferFrom(_owner: address, _to: address, _amount: uint256) -> bool:

    self._spend_allowance(_owner, msg.sender, _amount)
    self._transfer(_owner, _to, _amount)
    return True


@external
def burn(_amount: uint256):

    self._burn(msg.sender, _amount)


@external
def burn_from(_owner: address, _amount: uint256):

    self._spend_allowance(_owner, msg.sender, _amount)
    self._burn(_owner, _amount)


@external
def mint(_owner: address, _amount: uint256):
    assert self.is_minter[msg.sender], "AccessControl: access is denied"
    self._mint(_owner, _amount)


@external
def set_minter(_minter: address, _status: bool):

    self._check_owner()
    assert _minter != empty(address), "AccessControl: minter is the zero address"
    assert _minter != self.owner, "AccessControl: minter is owner address"
    self.is_minter[_minter] = _status
    log RoleMinterChanged(_minter, _status)


@external
def transfer_ownership(_new_owner: address):

    self._check_owner()
    assert _new_owner != empty(address), "Ownable: new owner is the zero address"

    self.is_minter[msg.sender] = False
    log RoleMinterChanged(msg.sender, False)

    self._transfer_ownership(_new_owner)
    self.is_minter[_new_owner] = True
    log RoleMinterChanged(_new_owner, True)


@external
def renounce_ownership():

    self._check_owner()
    self.is_minter[msg.sender] = False
    log RoleMinterChanged(msg.sender, False)
    self._transfer_ownership(empty(address))


