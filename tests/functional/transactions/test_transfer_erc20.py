import pytest
import time
from ape import accounts


def test_transfer_erc20(bob, w3, proxy, base, token, base_sign_message, new_account, get_key):

    # authorise fist
    proxy.authorise_module(base.address, sender=bob)

    new_account_address = new_account
    
    token.mint(new_account_address, int(10000e18), sender=bob)

    zero_address = "0x0000000000000000000000000000000000000000"

    # encode transfer token data
    data = token.transfer.encode_input(accounts[0], int(100e18))

    owner = bob.address
    account = new_account_address
    transaction_to = token.address
    transaction_calldata = data
    transaction_value = 0
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

    assert token.balanceOf(accounts[0]) == int(100e18)

