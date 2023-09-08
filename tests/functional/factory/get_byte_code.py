from web3 import Web3
from hexbytes import HexBytes


def vyper_proxy_byte_code(_target: str):
    """
    create2 bytecode_hash 
    _target: ape account address
    """

    addr = HexBytes(_target)
    pre = HexBytes("0x602D3D8160093D39F3363d3d373d3d3d363d73")
    post = HexBytes("0x5af43d82803e903d91602b57fd5bf3")
    return HexBytes(pre + (addr + HexBytes(0) * (20 - len(addr))) + post)

# a = vyper_proxy_init_code(0xEcd68a755B1698072B1B23cE48b9b9a4572706F1)
# print(w3.keccak(hexstr=a.hex()).hex())

