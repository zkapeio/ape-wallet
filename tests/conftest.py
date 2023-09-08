import pytest
import time
from ape import chain, networks, accounts
from eth_account.messages import encode_structured_data


@pytest.fixture
def bob(accounts):
    
    bob = accounts['0x14b0Ed2a7C4cC60DD8F676AE44D0831d3c9b2a9E']
    bob.balance += int(10000e18)
    return bob


@pytest.fixture
def alice(accounts):
    
    alice = accounts['0xeA8DC210e93eaf9fCFE29939426a2Ac3Fe69017C']
    alice.balance += int(10000e18)
    return alice


@pytest.fixture
def w3():
    return networks.provider._web3


@pytest.fixture
def ape_account(project, bob):
    return bob.deploy(project.ApeAccount)


@pytest.fixture
def signature_checker(project, bob):
    return bob.deploy(project.SignatureChecker)


@pytest.fixture
def security(project, bob, signature_checker):
    recovery_period = 86400
    lock_period = 172800
    security_period = 86400
    return bob.deploy(project.SecurityManager, recovery_period, lock_period, security_period, signature_checker)


@pytest.fixture
def factory(project, bob, ape_account, signature_checker, security):
    return bob.deploy(project.ApeFactory, ape_account, bob, signature_checker, security)


@pytest.fixture
def proxy(project, bob, security):
    return bob.deploy(project.AccountsProxy, security)


@pytest.fixture
def nft(project, bob):
    return bob.deploy(project.ERC721)


@pytest.fixture
def token(project, bob):
    return bob.deploy(project.ERC20)


@pytest.fixture
def oracle(project, bob):
    factory = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"
    weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"

    return bob.deploy(project.OracleManager, factory, weth)


@pytest.fixture
def base(project, bob, proxy, oracle, security):
    relayer = bob.address
    whitelist_period = int(time.time())
    return bob.deploy(project.BaseManager, relayer, whitelist_period, proxy.address, oracle, security)


@pytest.fixture
def factory_sign_message():
    def factory_sign_message(
        owner, 
        signer, 
        token1, 
        token_id, 
        chain_id, 
        proxy, 
        refund_amount, 
        refund_token, 
        salt, 
        factory_address, 
        w3
    ):
        
        msg = {
            "domain": {
                "name": 'Ape Wallet Factory v1',
                "version": 'v1.0.0',
                "chainId": chain_id,
                "verifyingContract": factory_address,
            },
            "message": {
                "owner": owner,
                "signer": signer, 
                "token": token1,
                "token_id": token_id,
                "chain_id": chain_id,
                "proxy": proxy,
                "salt": salt,
                "refund_amount": refund_amount,
                "refund_token": refund_token
            },
            "primaryType": 'AccountParameters',
            "types": {
                "EIP712Domain": [
                    {"name": 'name', "type": 'string'},
                    {"name": 'version', "type": 'string'},
                    {"name": 'chainId', "type": 'uint256'},
                    {"name": 'verifyingContract', "type": 'address'},
                ],
                "AccountParameters": [
                    {"name": 'owner', "type": 'address'},
                    {"name": 'signer', "type": 'address'},
                    {"name": 'token', "type": 'address'},
                    {"name": 'token_id', "type": 'uint256'},
                    {"name": 'chain_id', "type": 'uint256'},
                    {"name": 'proxy', "type": 'address'},
                    {"name": 'salt', "type": 'uint256'},
                    {"name": 'refund_amount', "type": 'uint256'},
                    {"name": 'refund_token', "type": 'address'}
                ]
            }
        }

        bob = '0x416b8a7d9290502f5661da81f0cf43893e3d19cb9aea3c426cfb36e8186e9c09'

        message = encode_structured_data(primitive=msg)
        signed_msg = w3.eth.account.sign_message(message, private_key=bob)

        signature = signed_msg['signature'].hex()

        return signature
    
    return factory_sign_message


@pytest.fixture
def base_sign_message():
    def base_sign_message(
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
        base_address, 
        w3,
        key
    ):

        msg = {
            "domain": {
                "name": 'Ape Wallet Base Manager v1',
                "version": 'v1.0.0',
                "chainId": chain.chain_id,
                "verifyingContract": base_address,
            },
            "message": {
                "owner": owner,
                'account': account,
                'transaction_to': transaction_to,
                'transaction_value': transaction_value,
                'nonce': nonce,
                'gas_price': gas_price,
                'gas_limit': gas_limit,
                'deadline': deadline,
                'refund_token': refund_token,
                'refund_address': refund_addres,
            },
            "primaryType": 'ExecuteParameters',
            "types": {
                "EIP712Domain": [
                    {"name": 'name', "type": 'string'},
                    {"name": 'version', "type": 'string'},
                    {"name": 'chainId', "type": 'uint256'},
                    {"name": 'verifyingContract', "type": 'address'},
                ],
                "ExecuteParameters": [
                    {"name": 'owner', "type": 'address'},
                    {"name": 'account', "type": 'address'},
                    {"name": 'transaction_to', "type": 'address'},
                    {"name": 'transaction_value', "type": 'uint256'},
                    {"name": 'nonce', "type": 'uint256'},
                    {"name": 'gas_price', "type": 'uint256'},
                    {"name": 'gas_limit', "type": 'uint256'},
                    {"name": 'deadline', "type": 'uint256'},
                    {"name": 'refund_token', "type": 'address'},
                    {"name": 'refund_address', "type": 'address'}
                ]
            }
        }

        message = encode_structured_data(primitive=msg)
        signed_msg = w3.eth.account.sign_message(message, private_key=key)
        signature = signed_msg['signature'].hex()

        return signature
    
    return base_sign_message


@pytest.fixture
def get_key():
    def get_key(id):
        """
        default guardian: 
        0xeA8DC210e93eaf9fCFE29939426a2Ac3Fe69017C
        0c674f4ebb1efb9aad8ce9a7198604f75c0f342bc1968dd771a91d662a80515b

        owner:
        0x14b0Ed2a7C4cC60DD8F676AE44D0831d3c9b2a9E
        0x416b8a7d9290502f5661da81f0cf43893e3d19cb9aea3c426cfb36e8186e9c09
        """

        if id == 1:
            return "0c674f4ebb1efb9aad8ce9a7198604f75c0f342bc1968dd771a91d662a80515b"
        return "0x416b8a7d9290502f5661da81f0cf43893e3d19cb9aea3c426cfb36e8186e9c09"
    return get_key