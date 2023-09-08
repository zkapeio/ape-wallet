# @version 0.3.7

interface Demo:
    def compute_add_mul(_x: uint256, _y: uint256): nonpayable

a: public(uint256)
b: public(uint256)
g: public(uint256)

owner: public(address)

@external
def __init__():
    self.owner = msg.sender


@external
def compute_add(_x: uint256, _y: uint256):
    self.a = _x + _y


@external
def compute_add_owner(_x: uint256, _y: uint256):
    assert msg.sender == self.owner, "only owner"
    self.a = _x + _y


@external
def compute_add_mul_owner(_x: uint256, _y: uint256):
    assert msg.sender == self.owner, "only owner"
    self.a = _x * _y


@external
def compute_add_mul(_x: uint256, _y: uint256):
    self.a = _x * _y


@view
@external
def slice_method(_data: Bytes[max_value(uint16)]) -> bytes4:
    
    method: bytes4 = convert(slice(_data, 0, 4), bytes4)
    return method


@external
def run_self():
    Demo(self).compute_add_mul(2, 5)
    self.g = msg.gas