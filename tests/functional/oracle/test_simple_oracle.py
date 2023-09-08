import pytest
import time
from ape import accounts, Contract



def test_in_token(oracle):
    
    usdt = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    usdt_amount = int(100e18)

    assert oracle.in_token(usdt, usdt_amount) == int(100e18)


def test_in_eth(oracle):
    
    usdt = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    eth_amount = int(1e18)

    assert oracle.in_token(usdt, eth_amount) == int(1e18)