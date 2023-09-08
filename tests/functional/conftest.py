import pytest
import time
from ape import chain, accounts
from factory.get_byte_code import *
from eth_abi import encode



@pytest.fixture
def new_account(bob, w3, ape_account, factory, proxy, security, factory_sign_message):

    # first init functions
    security.set_factory(factory, sender=bob)
    security.set_proxy(proxy, sender=bob)

    zero_address = "0x0000000000000000000000000000000000000000"

    owner = bob.address
    signer = owner
    token = zero_address
    token_id = 0
    chain_id = chain.chain_id
    proxy_address = proxy.address
    refund_amount = int(1e10)
    refund_token = zero_address
    # salt_text = "12345"
    salt_text = "Ape Wallet Factory v1" + "create_mini_proxy" + str(time.time())
    salt = w3.to_int(hexstr=w3.keccak(text=salt_text).hex())

    print("salt: ", salt)

    signature = factory_sign_message(owner, signer, token, token_id, chain_id, proxy_address, refund_amount, refund_token, salt, factory.address, w3)

    print("create sign: ", signature)

    param = {
        "owner": owner,
        "signer": signer, 
        "token": token,
        "token_id": token_id,
        "chain_id": chain_id,
        "proxy": proxy_address,
        "salt": salt,
        "refund_amount": refund_amount,
        "refund_token": refund_token,
        "owner_signature": signature
    }

    byte_code = vyper_proxy_byte_code(str(ape_account.address))
    byte_code = w3.keccak(hexstr=byte_code.hex()).hex()

    news = encode(['address', 'address', 'address', 'uint256', 'uint256', 'address', 'uint256'],
            [str(ape_account.address), owner, str(token), token_id, chain_id, proxy_address, salt]).hex()

    new_salt = w3.keccak(hexstr=news).hex()
    new_account_address = factory.compute_address_self(new_salt, byte_code)

    bob.transfer(new_account_address, int(10e18))
    account_balance = accounts[new_account_address]
    assert account_balance.balance == int(10e18)

    proxy.authorise_module(factory.address, sender=bob)

    factory.create_account(param, sender=bob)

    return new_account_address
    
