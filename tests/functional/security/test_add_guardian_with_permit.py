from ape import chain, accounts
from eth_account.messages import encode_structured_data
import time


def security_sign_message(
    signer,
    account,
    guardian,
    name_id,
    conduit_key,
    nonce,
    start_time,
    end_time,
    security_address,
    w3,
    alice
):

    msg = {
        "domain": {
            "name": 'Ape Wallet Security Manager v1',
            "version": 'v1.0.0',
            "chainId": chain.chain_id,
            "verifyingContract": security_address,
        },
        "message": {
            "signer": signer, 
            "account": account,
            "guardian": guardian,
            "name_id": name_id,
            "conduit_key": conduit_key,
            "nonce": nonce,
            "start_time": start_time,
            "end_time": end_time
        },
        "primaryType": 'GuardianPermit',
        "types": {
            "EIP712Domain": [
                {"name": 'name', "type": 'string'},
                {"name": 'version', "type": 'string'},
                {"name": 'chainId', "type": 'uint256'},
                {"name": 'verifyingContract', "type": 'address'},
            ],
            "GuardianPermit": [
                {"name": 'signer', "type": 'address'},
                {"name": 'account', "type": 'address'},
                {"name": 'guardian', "type": 'address'},
                {"name": 'name_id', "type": 'uint256'},
                {"name": 'conduit_key', "type": 'uint256'},
                {"name": 'nonce', "type": 'uint256'},
                {"name": 'start_time', "type": 'uint256'},
                {"name": 'end_time', "type": 'uint256'}
            ]
        }
    }

    message = encode_structured_data(primitive=msg)
    signed_msg = w3.eth.account.sign_message(message, private_key=alice)

    signature = signed_msg['signature'].hex()

    return signature


def test_add_guardian_with_permit(bob, w3, security, proxy, base, base_sign_message, new_account):
    
    new_guardian_pub = "0x87F073E66f1F1f59d4D7CB3C9675375f215D1E56"
    new_guardian_pri = "3aa5bc6759a31a2ac75942d0f06b44e64d52a6e148bda832781ce182bfeb2f32"
    bob_pri = '0x416b8a7d9290502f5661da81f0cf43893e3d19cb9aea3c426cfb36e8186e9c09'

    signer = bob.address
    account = new_account
    guardian = new_guardian_pub
    name_id = 0
    conduit_key = 123456
    nonce = 112233
    start_time = int(time.time())
    end_time = int(time.time()) + 86400

    owner_signature = security_sign_message(
        signer,
        account,
        guardian,
        name_id,
        conduit_key,
        nonce,
        start_time,
        end_time,
        security.address,
        w3,
        bob_pri
    )

    protected_parameters = {
        "signer": signer, 
        "account": account,
        "guardian": guardian,
        "name_id": name_id,
        "conduit_key": conduit_key,
        "nonce": nonce,
        "start_time": start_time,
        "end_time": end_time,
        "owner_signature": owner_signature
    }

    guardian_signer = new_guardian_pub
    guardian_account = new_account
    guardian = new_guardian_pub
    guardian_name_id = 0
    guardian_conduit_key = 678910
    guardian_nonce = 445566
    guardian_start_time = int(time.time())
    guardian_end_time = int(time.time()) + 86400

    guardian_owner_signature = security_sign_message(
        guardian_signer,
        guardian_account,
        guardian,
        guardian_name_id,
        guardian_conduit_key,
        guardian_nonce,
        guardian_start_time,
        guardian_end_time,
        security.address,
        w3,
        new_guardian_pri
    )

    guardian_parameters = {
        "signer": guardian_signer, 
        "account": guardian_account,
        "guardian": guardian,
        "name_id": guardian_name_id,
        "conduit_key": guardian_conduit_key,
        "nonce": guardian_nonce,
        "start_time": guardian_start_time,
        "end_time": guardian_end_time,
        "owner_signature": guardian_owner_signature
    }

    pending_time = int(time.time()) + 172800

    chain.pending_timestamp += pending_time

    proxy.authorise_module(base.address, sender=bob)

    zero_address = "0x0000000000000000000000000000000000000000"

    data = security.add_guardian_with_permit.encode_input(protected_parameters, guardian_parameters)

    owner = bob.address
    account = new_account
    transaction_to = security.address
    transaction_calldata = data
    transaction_value = 0
    nonce = 1
    gas_price = 10000
    gas_limit = 10000
    deadline = pending_time + 86400000000000000
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
        w3
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

    assert security.is_guardian(account, guardian)