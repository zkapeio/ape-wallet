# @version 0.3.9


interface UniSwapV2Router:
    def WETH() -> address: view
    def factory() -> address: view
    def getAmountIn(_amountOut: uint256, _reserveIn: uint256, _reserveOut: uint256) -> uint256: view
    def getAmountOut(_amountIn: uint256, _reserveIn: uint256, _reserveOut: uint256) -> uint256: view
    def getAmountsIn(_amountOut: uint256, _path: DynArray[address, 2]) -> uint256: view
    def getAmountsOut(_amountIn: uint256, _path: DynArray[address, 2]) -> uint256: view
    def quote(_amountA: uint256, _reserveA: uint256, _reserveB: uint256) -> uint256: view

interface UniSwapV2Factory:
    def getPair(_token0: address, _token1: address) -> address: view

interface UniSwapV2Pair:
    def getReserves() -> DynArray[uint256, 3]: view
    def token0() -> address: view
    def token1() -> address: view


owner: public(address)
factory: public(address)
weth: public(address)


@external
def __init__():
    self.owner = msg.sender



# @view
# @internal
# def _getPair(_token0: address, _token1: address) -> address:
#     return UniSwapV2Factory(self.factory).getPair(_token0, _token1)


# @view
# @internal
# def _getReserve(_token: address) -> (uint256, uint256):
#     _pair: address = self._getPair(_token, self.weth)
    
#     _token0: address = UniSwapV2Pair(_pair).token0()
#     _reserve: DynArray[uint256, 3] = UniSwapV2Pair(_pair).getReserves()
#     _ethReserve: uint256 = _reserve[0]
#     _tokenReserve: uint256 = _reserve[1]

#     if _token == _token0:
#         _ethReserve = _tokenReserve 
#         _tokenReserve = _ethReserve

#     return _ethReserve, _tokenReserve


# @view
# @external
# def in_eth(_token: address, _ethAmount: uint256) -> uint256:
#     _ethReserve: uint256 = 0
#     _tokenReserve: uint256 = 0
#     _ethReserve, _tokenReserve = self._getReserve(_token)

#     return _ethAmount * _tokenReserve / _ethReserve


# @view
# @external
# def in_token(_token: address, _tokenAmount: uint256) -> uint256:
#     _ethReserve: uint256 = 0
#     _tokenReserve: uint256 = 0
#     _ethReserve, _tokenReserve = self._getReserve(_token)

#     return _tokenAmount * (_ethReserve / _tokenReserve)


@view
@external
def in_token(_token: address, _eth_amount: uint256) -> uint256:
    return _eth_amount


@view
@external
def in_eth(_token: address, _token_amount: uint256) -> uint256:
    return _token_amount