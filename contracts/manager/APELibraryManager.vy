# @version 0.3.9
"""
@title Ape Wallet APELibraryManager
@author zkApes
@license Copyright (c) zkApes, 2022-2023 - all rights reserved
"""

interface APEBaseManager:
    def is_authorise(_module: address) -> bool: view

interface ERC721:
    def ownerOf(_token_id: uint256) -> address: view

interface SignatureChecker:
    def is_valid_signature_now(_signer: address, _hash: bytes32, _signature: Bytes[65]) -> bool: view
    def recover_sig(_hash: bytes32, _signature: Bytes[65]) -> address: view

event Reload:
    _account: indexed(address)
    _token_contract: indexed(address)
    _token_id: uint256
    _chain_id: uint256
    _creator: address
    _signer: address
    _create_time: uint256

event ChangeAdmin:
     _old_admin: indexed(address)
     _new_admin: indexed(address)

event SetupModule:
    _id: indexed(uint256)
    _module: indexed(address)

struct AccountDetail:
    chain_id: uint256
    token_contract: address
    token_id: uint256
    creator: address
    signer: address
    create_time: uint256


ERC1271_ISVALIDSIGNATURE_SELECTOR: public(constant(bytes4)) = 0x1626BA7E
ERC165_INTERFACE: public(constant(bytes4)) = 0x01ffc9a7
ERC721_RECEIVED: public(constant(bytes4)) = method_id("onERC721Received(address,address,uint256,bytes)", output_type=bytes4)
ERC1155_RECEIVED: public(constant(bytes4)) = method_id("onERC1155Received(address,address,uint256,uint256,bytes)", output_type=bytes4)
ERC1155_BATCH_RECEIVED: public(constant(bytes4)) = method_id("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)", output_type=bytes4)

# module index
# 0 - Signature, 1 - Library, 2 - AccountProxy
# 3 - DeployFactory, 4 - Implementation, 5 - Security
# 6 - Oracle, 7 - Base
modules_library: public(HashMap[uint256, address])
account_detail: public(HashMap[address, AccountDetail])
nonce: public(HashMap[address, uint256])
authorise_module: HashMap[address, bool]

admin: public(address)


@payable
@external
def __init__():
    self.admin = msg.sender


@view
@internal
def _owner(_account: address) -> address:

    account: AccountDetail = self.account_detail[_account]

    if account.chain_id != chain.id or account.token_contract == empty(address):
        return empty(address)

    return ERC721(account.token_contract).ownerOf(account.token_id)


@view
@external
def token(_account: address) -> (uint256, address, uint256):
    account: AccountDetail = self.account_detail[_account]
    return account.chain_id, account.token_contract, account.token_id


@view
@external
def owner(_account: address) -> address:
    return self._owner(_account)


@view
@external
def signer(_account: address) -> address:
    account: AccountDetail = self.account_detail[_account]
    return account.signer


@view
@external
def isValidSignature(_hash: bytes32, _signature: Bytes[65], _account: address) -> bytes4:
	assert len(_signature) == 65, "APE502"

	signer: address = SignatureChecker(self.modules_library[0]).recover_sig(_hash, _signature)

	account: AccountDetail = self.account_detail[_account]
	owner: address = self._owner(_account)
	if signer in [owner, account.signer]:
		return ERC1271_ISVALIDSIGNATURE_SELECTOR
	return empty(bytes4)


@view
@external
def is_authorise(_module: address) -> bool:
    return self.authorise_module[_module]


@pure
@external
def supportsInterface(_interface_id: bytes4) -> bool:

    return _interface_id in [
        0x01FFC9A7, # The ERC-165 identifier for ERC-165.
        0x80AC58CD, # The ERC-165 identifier for ERC-721.
        0x5B5E139F, # The ERC-165 identifier for the ERC-721 metadata extension.
        0x780E9D63, # The ERC-165 identifier for the ERC-721 enumeration extension.
        0x589C5CE2, # The ERC-165 identifier for ERC-4494.
        0x49064906, # The ERC-165 identifier for ERC-4906.
        0xD9B67A26, # The ERC-165 identifier for ERC-1155.
        0x0E89341C # The ERC-165 identifier for the ERC-1155 metadata extension.
    ]


@pure
@external
def onERC721Received(_operator: address, _from: address, _token_id: uint256, _data: Bytes[1024]) -> bytes4:
    return method_id("onERC721Received(address,address,uint256,bytes)", output_type=bytes4)


@pure
@external
def onERC1155Received(_operator: address, _from: address, _id: uint256, _value: uint256, _data: Bytes[1024]) -> bytes4:
    return method_id("onERC1155Received(address,address,uint256,uint256,bytes)", output_type=bytes4)


@pure
@external
def onERC1155BatchReceived(_operator: address, _from: address, _ids: DynArray[uint256, max_value(uint16)], _values: DynArray[uint256, max_value(uint16)], _data: Bytes[1024]) -> bytes4:
    return method_id("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)", output_type=bytes4)


@pure
@external
def supports_static_call(_method_id: bytes4) -> bool:
    return _method_id in [
        ERC165_INTERFACE,
        ERC721_RECEIVED,
        ERC1155_RECEIVED,
        ERC1155_BATCH_RECEIVED,
		ERC1271_ISVALIDSIGNATURE_SELECTOR
    ]


@external
def reload_account(_account: address, _account_detail: AccountDetail) -> bool:
    assert self.authorise_module[msg.sender], "APE011"

    self.account_detail[_account] = _account_detail

    log Reload(
        _account,
        _account_detail.token_contract,
        _account_detail.token_id,
        _account_detail.chain_id,
        _account_detail.creator,
        _account_detail.signer,
        _account_detail.create_time
    )
    return True


@external
def reload_nonce(_account: address, _nonce: uint256) -> bool:
	assert self.authorise_module[msg.sender], "APE011"

	self.nonce[_account] = _nonce
	return True


@external
def change_admin(_new_admin: address):
     assert msg.sender == self.admin, "APE010"

     old_admin: address = self.admin
     self.admin = _new_admin
     log ChangeAdmin(old_admin, _new_admin)


@external
def setup_modules(
    _module_id: DynArray[uint256, 10],
    _modules: DynArray[address, 10],
    _bools: DynArray[uint256, 10]
):
    assert msg.sender == self.admin, "APE010"
    assert len(_module_id) == len(_modules), "APE303"

    for i in range(10):
        if i >= len(_modules):
            break

        is_authorised: bool = False
        if _bools[i] == 1:
            is_authorised = True

        self.modules_library[_module_id[i]] = _modules[i]
        self.authorise_module[_modules[i]] = is_authorised
        log SetupModule(_module_id[i], _modules[i])

