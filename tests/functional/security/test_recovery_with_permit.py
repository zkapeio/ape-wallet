from ape import chain, accounts, Contract
from eth_account.messages import encode_structured_data
import time


def recovery_sign_message(
    signer,
    account,
    recovery,
    guardian,
    name_id,
    nonce,
    sign_time,
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
            "recovery": recovery,
            "guardian": guardian,
            "name_id": name_id,
            "nonce": nonce,
            "sign_time": sign_time,
        },
        "primaryType": 'RecoveryPermit',
        "types": {
            "EIP712Domain": [
                {"name": 'name', "type": 'string'},
                {"name": 'version', "type": 'string'},
                {"name": 'chainId', "type": 'uint256'},
                {"name": 'verifyingContract', "type": 'address'},
            ],
            "RecoveryPermit": [
                {"name": 'signer', "type": 'address'},
                {"name": 'account', "type": 'address'},
                {"name": 'recovery', "type": 'address'},
                {"name": 'guardian', "type": 'address'},
                {"name": 'name_id', "type": 'uint256'},
                {"name": 'nonce', "type": 'uint256'},
                {"name": 'sign_time', "type": 'uint256'}
            ]
        }
    }

    message = encode_structured_data(primitive=msg)
    signed_msg = w3.eth.account.sign_message(message, private_key=alice)

    signature = signed_msg['signature'].hex()

    return signature


def test_recovery_with_permit(bob, w3, proxy, base, security, new_account, base_sign_message):

    proxy.authorise_module(security.address, sender=bob)

    new_guardian_pub = "0x87F073E66f1F1f59d4D7CB3C9675375f215D1E56"
    new_guardian_pri = "3aa5bc6759a31a2ac75942d0f06b44e64d52a6e148bda832781ce182bfeb2f32"
    bob_pri = '0x416b8a7d9290502f5661da81f0cf43893e3d19cb9aea3c426cfb36e8186e9c09'

    signer = bob.address
    account = new_account
    recovery = accounts[2].address
    guardian = bob.address
    name_id = 0
    nonce = 112233
    sign_time = int(time.time()) + 864000

    owner_signature = recovery_sign_message(
        signer,
        account,
        recovery,
        guardian,
        name_id,
        nonce,
        sign_time,
        security.address,
        w3,
        bob_pri
    )

    owner_param = {
        "signer": signer, 
        "account": account,
        "recovery": recovery,
        "guardian": guardian,
        "name_id": name_id,
        "nonce": nonce,
        "sign_time": sign_time,
        "owner_signature": owner_signature
    }

    gaurdian_signer = bob.address
    guardian_account = new_account
    guardian_recovery = accounts[2].address
    guardian_guardian = bob.address
    guardian_name_id = 0
    guardian_nonce = 112233
    guardian_sign_time = int(time.time()) + 864000

    guardian_signature = recovery_sign_message(
        gaurdian_signer,
        guardian_account,
        guardian_recovery,
        guardian_guardian,
        guardian_name_id,
        guardian_nonce,
        guardian_sign_time,
        security.address,
        w3,
        bob_pri
    )

    guardian_param = {
        "signer": gaurdian_signer, 
        "account": guardian_account,
        "recovery": guardian_recovery,
        "guardian": guardian_guardian,
        "name_id": guardian_name_id,
        "nonce": guardian_nonce,
        "sign_time": guardian_sign_time,
        "owner_signature": guardian_signature
    }

    param_arr = [owner_param, guardian_param]

    # security.execute_recovery(account, recovery, sender=bob)

    # security.execute_recovery_with_permit(account, param_arr, sender=bob)

    # acc_contract = Contract(new_account)
    # assert acc_contract.signer() == accounts[2].address