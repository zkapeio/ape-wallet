import pytest
import time
from ape import accounts, Contract


@pytest.fixture
def fork_uniswap_router():
    return Contract("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")


def test_check_uniswap(fork_uniswap_router):
    factory = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"
    assert fork_uniswap_router.factory() == factory
    

def test_transfer_eth(
    bob, 
    w3,
    proxy,
    base, 
    base_sign_message, 
    new_account, 
    fork_uniswap_router,
    get_key
):

    # authorise fist
    proxy.authorise_module(base.address, sender=bob)

    new_account_address = new_account

    # encode eth -> usdt data
    amount_out_min = 0
    weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
    usdt = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    path = [weth, usdt]
    to = new_account_address
    swap_deadline = int(time.time()) + 1800
    
    data = fork_uniswap_router.swapExactETHForTokens.encode_input(amount_out_min, path, to, swap_deadline)

    zero_address = "0x0000000000000000000000000000000000000000"

    owner = bob.address
    account = new_account_address
    transaction_to = fork_uniswap_router.address
    transaction_calldata = data
    transaction_value = int(1e18)
    nonce = 1
    gas_price = 10000
    gas_limit = 10000
    deadline = int(time.time()) + 1800
    refund_token = zero_address
    refund_addres = accounts[0].address

    owner_signature = base_sign_message(
        owner, 
        account, 
        transaction_to, 
        transaction_value, 
        nonce, 
        gas_price, 
        gas_limit, 
        deadline, 
        refund_token, 
        refund_addres, 
        base.address, 
        w3,
        get_key(0)
    )

    guardian_signature = base_sign_message(
        owner, 
        account, 
        transaction_to, 
        transaction_value, 
        nonce, 
        gas_price, 
        gas_limit, 
        deadline, 
        refund_token, 
        refund_addres, 
        base.address, 
        w3,
        get_key(1)
    )

    guardian_signature = guardian_signature[2:]
    signature = owner_signature + guardian_signature

    param = {
        "owner": owner,
        'account': account,
        'transaction_to': transaction_to,
        'transaction_calldata': transaction_calldata,
        'transaction_value': transaction_value,
        'nonce': nonce,
        'gas_price': gas_price,
        'gas_limit': gas_limit,
        'deadline': deadline,
        'refund_token': refund_token,
        'refund_address': refund_addres,
        'signature': signature
    }

    base.execute(param, sender=bob)

    # check usdt value
    # fork_usdt = Contract(usdt)
    # assert fork_usdt.balanceOf(new_account_address) == 1827258896

