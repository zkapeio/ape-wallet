# @version 0.3.7

interface CreateAddress:
    def compute_address(_salt: bytes32, _bytecode_hash: bytes32, _deployer: address) -> address: pure

interface ApeAccount:
    def initialize(
        _creator: address,
        _signer: address,
        _factory: address,
        _proxy: address,
        _contract: address,
        _signature: address,
        _security: address,
        _token_id: uint256,
        _chain_id: uint256
    ) -> bool: nonpayable

interface SignatureChecker:
    def is_valid_signature_now(
        _signer: address,
        _hash: bytes32,
        _signature: Bytes[65]
    ) -> bool: view

interface SecurityManager:
    def initialize_default_guardian(_account: address, _guardian: address) -> bool: nonpayable


event AccountCreated:
    account: indexed(address)
    owner: indexed(address)
    token: indexed(address)
    token_id: uint256
    proxy: address
    salt: bytes32
    refund_amount: uint256
    refund_token: address

event ChangeOwner:
    old_owner: indexed(address)
    new_owner: indexed(address)

event ChangeAccount:
    old_Account: indexed(address)
    new_Account: indexed(address)

event ChangeSecurity:
    old_security: indexed(address)
    new_security: indexed(address)
    

struct AccountParameters:
    owner: address
    signer: address
    token: address
    token_id: uint256
    chain_id: uint256
    proxy: address
    salt: uint256
    refund_amount: uint256
    refund_token: address
    owner_signature: Bytes[65]


_COLLISION_OFFSET: constant(bytes1) = 0xFF
EIP712_TYPEHASH: constant(bytes32) = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
ACCOUNT_PARAMETERS_TYPEHASH: constant(bytes32) = keccak256("AccountParameters(address owner,address signer,address token,uint256 token_id,uint256 chain_id,address proxy,uint256 salt,uint256 refund_amount,address refund_token)")
DEFAULT_GUARDIAN: constant(address) = 0xeA8DC210e93eaf9fCFE29939426a2Ac3Fe69017C

DOMAIN_SEPARATOR: immutable(bytes32)
NAME: immutable(String[64])
VERSION: constant(String[8]) = "v1.0.0"

owner: public(address)
ape_account: public(address)
refund_address: public(address)
signature_checker: public(address)
security: public(address)
accounts_length: public(uint256)
all_accounts: public(HashMap[uint256, address])
get_account: public(HashMap[address, HashMap[uint256, address]])
is_account: public(HashMap[address, bool])


@external
def __init__(_ape_account: address, _refund_address: address, _signature_checker: address, _security: address):
    self.owner = msg.sender
    self.ape_account = _ape_account
    self.refund_address = _refund_address
    self.signature_checker = _signature_checker
    self.security = _security

    name: String[64] = "Ape Wallet Factory v1"
    NAME = name

    DOMAIN_SEPARATOR = keccak256(
        _abi_encode(EIP712_TYPEHASH, keccak256(name), keccak256(VERSION), chain.id, self)
    )


@pure
@internal
def _convert_keccak256_2_address(_digest: bytes32) -> address:
    return convert(convert(_digest, uint256) & convert(max_value(uint160), uint256), address)


@internal
def _validate_input(_owner: address, _guardian: address):
    assert not empty(address) in [_owner, _guardian]


@view
@internal
def _new_salt(
    _owner: address, 
    _token: address, 
    _token_id: uint256,
    _chain_id: uint256,
    _proxy: address, 
    _salt: uint256
) -> bytes32:

    return keccak256(
        _abi_encode(
            self.ape_account, 
            _owner, 
            _token,
            _token_id,
            _chain_id,
            _proxy, 
            _salt
        )
    )


@pure
@internal
def _account_parameters_hash(_param: AccountParameters) -> bytes32:
    
    hash: bytes32 = keccak256(
        _abi_encode(
            ACCOUNT_PARAMETERS_TYPEHASH,
            _param.owner,
            _param.signer,
            _param.token,
            _param.token_id,
            _param.chain_id,
            _param.proxy,
            _param.salt,
            _param.refund_amount,
            _param.refund_token
        )
    )

    digest: bytes32 = keccak256(
        concat(
            b"\x19\x01",
            DOMAIN_SEPARATOR,
            hash
        )
    )

    return digest
    

@internal
def _execute_call(_target: address, _calldata: Bytes[1024]):
    success: bool = False
    response: Bytes[32] = b""

    success, response = raw_call(_target, _calldata, max_outsize=32, revert_on_failure=False)
    
    if len(response) != 0:
        assert convert(response, bool), "Ape: call fail"

    assert success, "Ape: refund transfer fail"


@internal
def _validate_and_refund(
    _proxy: address,
    _account: address, 
    _refund_amount: uint256, 
    _refund_token: address,
    _owner: address,
    _hash: bytes32,
    _owner_signature: Bytes[65]
):

    assert SignatureChecker(self.signature_checker).is_valid_signature_now(_owner, _hash, _owner_signature), "Ape: invalid signature"

    if _refund_token == empty(address):

        call_data:Bytes[1024] = _abi_encode(
            _account,
            self.refund_address,
            _refund_amount,
            b"",
            method_id=method_id("execute(address,address,uint256,bytes)")
        )
        self._execute_call(_proxy, call_data)

    else:

        refund_data: Bytes[1024] = _abi_encode(
            _account,
            _refund_token,
            empty(uint256),
            _abi_encode(
                self.refund_address,
                _refund_amount,
                method_id=method_id("transfer(address,uint256)")
            ),
            method_id=method_id("execute(address,address,uint256,bytes)")
        )

        self._execute_call(_proxy, refund_data)


@view
@external
def compute_address_self(_salt: bytes32, _bytecode_hash: bytes32) -> address:
    return CreateAddress(self).compute_address(_salt, _bytecode_hash, self)


@pure
@external
def compute_address(_salt: bytes32, _bytecode_hash: bytes32, _deployer: address) -> address:
    assert _deployer != empty(address), "Ape: empty address"

    data: bytes32 = keccak256(
        concat(
            _COLLISION_OFFSET, 
            convert(_deployer, bytes20),
            _salt, 
            _bytecode_hash
        )
    )

    return self._convert_keccak256_2_address(data)


@external
def create_account(_param: AccountParameters) -> address:

    assert msg.sender != empty(address), "Ape: empty sender address"

    self._validate_input(_param.owner, _param.proxy)
    new_salt: bytes32 = self._new_salt(_param.signer, _param.token, _param.token_id, _param.chain_id, _param.proxy, _param.salt)
    new_account: address = create_minimal_proxy_to(self.ape_account, salt=new_salt)

    assert ApeAccount(new_account).initialize(
        _param.owner,
        _param.signer,
        self,
        _param.proxy,
        _param.token,
        self.signature_checker,
        self.security,
        _param.token_id,
        chain.id,
        default_return_value=True
    ) # dev: initialized fail

    assert SecurityManager(self.security).initialize_default_guardian(new_account, DEFAULT_GUARDIAN, default_return_value=True), "Ape: initialize default guardian fail"

    if _param.refund_amount != 0:
        account_hash: bytes32 = self._account_parameters_hash(_param)
        self._validate_and_refund(_param.proxy, new_account, _param.refund_amount, _param.refund_token, self.owner, account_hash, _param.owner_signature)
    
    self.all_accounts[self.accounts_length] = new_account
    self.accounts_length += 1
    self.get_account[_param.token][_param.token_id] = new_account
    self.is_account[new_account] = True

    log AccountCreated(
        new_account,
        _param.owner, 
        _param.token, 
        _param.token_id,
        _param.proxy,
        new_salt, 
        _param.refund_amount, 
        _param.refund_token
    )

    return new_account


@external
def change_owner(_new_owner: address) -> bool:
    assert msg.sender == self.owner, "Ape: only owner"

    old_owner: address = self.owner
    self.owner = _new_owner
    log ChangeOwner(old_owner, _new_owner)

    return True


@external
def change_wallet(_new_account: address) -> bool:
    assert msg.sender == self.owner, "Ape: only owner"

    old_account: address = self.ape_account
    self.ape_account = _new_account
    log ChangeAccount(old_account, _new_account)

    return True


@external
def change_security(_new_security: address) -> bool:
    assert msg.sender == self.owner, "Ape: only owner"

    old_security: address = self.security
    self.security = _new_security
    log ChangeSecurity(old_security, _new_security)

    return True


@external
def storage_accounts(_account: address, _token: address, _token_id: uint256) -> bool:
    assert self.is_account[msg.sender], "Ape: Empty account"
    assert _account == msg.sender, "Ape: Only account"

    self.get_account[_token][_token_id] = _account

    return True


@external
def withdraw(_token: address, _amount: uint256) -> bool:
    assert msg.sender == self.owner, "Ape: only owner"

    raw_call(
        _token,
        _abi_encode(
            msg.sender,
            _amount,
            method_id=method_id("transfer(address,uint256)")
        )
    )

    return True