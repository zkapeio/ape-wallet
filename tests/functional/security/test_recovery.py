from ape import accounts, chain, Contract
import time


def test_recovery(bob, alice, w3, proxy, base, security, new_account, base_sign_message, get_key):

    new_signer = accounts[1]

    proxy.authorise_module(base.address, sender=bob)
    proxy.authorise_module(security.address, sender=bob)

    zero_address = "0x0000000000000000000000000000000000000000"

    data = security.execute_recovery.encode_input(new_account, new_signer)

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

    assert security.is_lock(new_account)

    # guardian config recovery
    new_acc_contract = Contract(new_account)
    old_signer = new_acc_contract.signer()

    assert security.is_guardian(new_account, alice.address)

    chain.pending_timestamp += (int(time.time()) + 1800000)

    security.finalize_recovery(new_account, sender=bob)
    
    assert old_signer != new_acc_contract.signer() and new_signer == new_acc_contract.signer()