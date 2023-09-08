from ape import accounts
import time

def test_lock(bob, alice, w3, security, proxy, base, base_sign_message, new_account, get_key):

    proxy.authorise_module(base.address, sender=bob)

    data = security.lock.encode_input(new_account)
    zero_address = "0x0000000000000000000000000000000000000000"

    owner = bob.address
    account = new_account
    transaction_to = security.address
    transaction_calldata = data
    transaction_value = 0
    nonce = 1
    gas_price = 10000
    gas_limit = 10000
    deadline = int(time.time()) + 1800
    refund_token = zero_address
    refund_addres = bob.address

    signature = base_sign_message(
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

    assert security.is_lock(new_account)