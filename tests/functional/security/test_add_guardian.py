from ape import accounts, chain
import time



def test_add_guardian(bob, alice, w3, proxy, base, security, new_account, base_sign_message, get_key):

    assert security.is_guardian(new_account, alice.address), "not guardian"

    new_guardian1 = accounts[0]

    proxy.authorise_module(base.address, sender=bob)

    zero_address = "0x0000000000000000000000000000000000000000"

    data = security.add_guardian.encode_input(new_account, new_guardian1)

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
        get_key(0)
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

    assert security.get_guardian_addition_period(new_account, new_guardian1) != 0

    chain.pending_timestamp += (deadline + 864000)

    # config guardian addtion
    # everyone can call this transactions
    security.config_guardian_addition(new_account, new_guardian1, sender=bob)

    assert security.is_guardian(new_account, new_guardian1)
    assert security.get_guardian_addition_period(new_account, new_guardian1) == 0

