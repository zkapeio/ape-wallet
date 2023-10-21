# @version 0.3.9
"""
@title Ape Wallet APEDeployFactory
@author zkApes
@license Copyright (c) zkApes, 2022-2023 - all rights reserved
"""

interface CreateAddress:
    def compute_address(salt: bytes32, bytecode_hash: bytes32, deployer: address, input: Bytes[4096]) -> address: pure

interface ContractDeployer:
    def create2(_salt: bytes32, _bytecode: Bytes[133]) -> address: nonpayable

interface APEAccountProxy:
	def initialize(_library: address) -> bool: nonpayable

interface APELibraryManager:
    def reload_account(_account: address, _account_detail: AccountDetail) -> bool: nonpayable
    def account_detail(_account: address) -> AccountDetail: view
    def signer(_account: address) -> address: view
    def modules_library(_module_id: uint256) -> address: view
    def is_authorise(_module: address) -> bool: view

interface SignatureChecker:
    def is_valid_signature_now(_signer: address, _hash: bytes32, _signature: Bytes[65]) -> bool: view

interface APESecurityManager:
    def initialize_default_guardian(_account: address, _guardian: address) -> bool: nonpayable
    def library() -> address: view


event AccountCreated:
    _account: indexed(address)
    _creator: indexed(address)
    _token: indexed(address)
    _token_id: uint256
    _salt: bytes32
    _refund_amount: uint256
    _refund_token: address

event TokenBoundAccounts:
    _account: indexed(address)
    _token_contract: indexed(address)
    _token_id: indexed(uint256)

event AuthoriseSigner:
    _old_signer: indexed(address)
    _new_signer: indexed(address)
    _status: bool

event ChangeAdmin:
    _old_admin: indexed(address)
    _new_admin: indexed(address)

event ChangeLibrary:
    _old_library: indexed(address)
    _new_library: indexed(address)


struct AccountParameters:
    creator: address
    signer: address
    token: address
    token_id: uint256
    chain_id: uint256
    salt: uint256
    refund_amount: uint256
    refund_token: address
    owner_signature: Bytes[65]

struct AccountDetail:
    chain_id: uint256
    token_contract: address
    token_id: uint256
    creator: address
    signer: address
    create_time: uint256


BYTECODE_HASH: constant(bytes32) = 0x0100020f8cb3f8367874542e0a74e1b38264a64007bf44e27950c3b640c4c490
SALT: constant(bytes32) = 0x6551655165516551655165516551655165516551655165516551655165516551
_CREATE2_PREFIX: constant(bytes32) = 0x2020dba91b30cc0006188af794c2fb30dd8520db7e2c088b7fc7c103c00ca494
EIP712_TYPEHASH: constant(bytes32) = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
ACCOUNT_PARAMETERS_TYPEHASH: constant(bytes32) = keccak256("AccountParameters(address creator,address owner,address token,uint256 token_id,uint256 chain_id,uint256 salt,uint256 refund_amount,address refund_token)")
DEFAULT_GUARDIAN: constant(address) = 0xeA8DC210e93eaf9fCFE29939426a2Ac3Fe69017C

DEPLOYER: public(immutable(address))
DOMAIN_SEPARATOR: public(immutable(bytes32))
BYTECODE: public(immutable(Bytes[133]))
APE_ACCOUNT: public(immutable(address))

accounts_length: public(uint256)
all_accounts: public(HashMap[uint256, address])
get_account: public(HashMap[address, HashMap[uint256, address]])
is_account: public(HashMap[address, bool])
salt_storage: public(HashMap[bytes32, bool])
library: public(address)
admin: public(address)


@payable
@external
def __init__(
    _ape_account: address,
    _deployer: address,
    _library: address,
    _bytecode: Bytes[133]
):

    self.admin = msg.sender
    self.library = _library

    name: String[64] = "Ape Wallet Factory v1"
    version: String[8] = "v1.0.0"

    DOMAIN_SEPARATOR = keccak256(
        _abi_encode(EIP712_TYPEHASH, keccak256(name), keccak256(version), chain.id, self)
    )

    APE_ACCOUNT = _ape_account
    DEPLOYER = _deployer
    BYTECODE = _bytecode

    self.is_account[_ape_account] = True


@view
@internal
def _get_security() -> address:
    return APELibraryManager(self.library).modules_library(5)


@view
@internal
def _get_signature() -> address:
    return APELibraryManager(self.library).modules_library(0)


@view
@internal
def _new_salt(
    _token: address,
    _token_id: uint256,
    _chain_id: uint256,
    _salt: uint256
) -> bytes32:

	s: uint256 = 0
	if _token == empty(address):
		s = _salt

	return keccak256(
		_abi_encode(
			APE_ACCOUNT,
			SALT,
			self,
			_token,
			_token_id,
			_chain_id,
			s
		)
	)


@view
@internal
def _account_parameters_hash(_param: AccountParameters) -> bytes32:

    hash: bytes32 = keccak256(
        _abi_encode(
            ACCOUNT_PARAMETERS_TYPEHASH,
            _param.creator,
            _param.signer,
            _param.token,
            _param.token_id,
            _param.chain_id,
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
def _check_salt(_salt: bytes32):
    assert not self.salt_storage[_salt], "APE022"
    self.salt_storage[_salt] = True


@internal
def _execute_call(_target: address, _value: uint256, _calldata: Bytes[1024]):
    success: bool = False
    response: Bytes[32] = b""

    success, response = raw_call(_target, _calldata, value=_value, max_outsize=32, revert_on_failure=False)

    if len(response) != 0:
        assert convert(response, bool)

    assert success, "APE002"


@internal
def _validate_and_refund(
    _account: address,
    _refund_amount: uint256,
    _refund_token: address,
    _signer: address,
    _hash: bytes32,
    _signature: Bytes[65]
):

    assert SignatureChecker(self._get_signature()).is_valid_signature_now(_signer, _hash, _signature), "APE501"

    if _refund_token == empty(address):

        # encode implemention execute
        call_data: Bytes[1024] = _abi_encode(
            self.admin,
            _refund_amount,
            b"",
            method_id=method_id("execute(address,uint256,bytes)")
        )

        self._execute_call(_account, 0, call_data)

    else:

        call_data: Bytes[1024] = _abi_encode(
            _refund_token,
            empty(uint256),
            _abi_encode(
                self.admin,
                _refund_amount,
                method_id=method_id("transfer(address,uint256)")
            ),
            method_id=method_id("execute(address,uint256,bytes)")
        )

        self._execute_call(_account, 0, call_data)


@internal
def _initialize(_account: address, _account_detail: AccountDetail) -> bool:
    return APELibraryManager(self.library).reload_account(_account, _account_detail)


@pure
@external
def compute_address(_salt: bytes32, _bytecode_hash: bytes32, _deployer: address, _input: Bytes[4096]=b"") -> address:
	constructor_input_hash: bytes32 = keccak256(_input)
	data: bytes32 = keccak256(concat(_CREATE2_PREFIX, empty(bytes12), convert(_deployer, bytes20), _salt, _bytecode_hash, constructor_input_hash))

	return convert(convert(data, uint256) & convert(max_value(uint160), uint256), address)


@view
@external
def compute_address_self(_salt: bytes32, _bytecode_hash: bytes32, _deployer: address, _input: Bytes[4096]) -> address:
    return CreateAddress(self).compute_address(_salt, _bytecode_hash, _deployer, _input)


@view
@external
def security() -> address:
    return self._get_security()


@view
@external
def signature() -> address:
    return self._get_signature()


@external
def create_account(_param: AccountParameters) -> address:

	account: address = self.get_account[_param.token][_param.token_id]
	assert empty(address) == account, "Account already exists"

	new_salt: bytes32 = self._new_salt(_param.token, _param.token_id, _param.chain_id, _param.salt)
	self._check_salt(new_salt)

	# new_account: address = CreateAddress(self).compute_address(new_salt, BYTECODE_HASH, DEPLOYER, _abi_encode(self.library))
	# new_account: address = ContractDeployer(DEPLOYER).create2(new_salt, BYTECODE)

	new_account: address = create_minimal_proxy_to(APE_ACCOUNT, salt=new_salt)

	new_account_detail: AccountDetail = AccountDetail({
		chain_id: chain.id,
		token_contract: _param.token,
		token_id: _param.token_id,
		creator: _param.creator,
		signer: _param.signer,
		create_time: block.timestamp
	})

	assert APEAccountProxy(new_account).initialize(self.library), "APE100"
	assert self._initialize(new_account, new_account_detail), "APE101"
	assert APESecurityManager(self._get_security()).initialize_default_guardian(new_account, DEFAULT_GUARDIAN), "APE102"

	if _param.refund_amount != 0:
		account_hash: bytes32 = self._account_parameters_hash(_param)
		self._validate_and_refund(new_account, _param.refund_amount, _param.refund_token, self.admin, account_hash, _param.owner_signature)

	self.all_accounts[self.accounts_length] = new_account
	self.accounts_length += 1

	if _param.token != empty(address):
		self.get_account[_param.token][_param.token_id] = new_account

	self.is_account[new_account] = True

	log AccountCreated(
		new_account,
		_param.creator,
		_param.token,
		_param.token_id,
		new_salt,
		_param.refund_amount,
		_param.refund_token
	)

	return new_account


@external
def upgrade_signer(_account: address, _new_signer: address) -> bool:
    assert msg.sender == _account, "APE017"

    account: AccountDetail = APELibraryManager(self.library).account_detail(_account)
    assert account.signer == empty(address), "APE304"

    new_account_detail: AccountDetail = AccountDetail(
        {
            chain_id: account.chain_id,
            token_contract: account.token_contract,
            token_id: account.token_id,
            creator: account.creator,
            signer: _new_signer,
            create_time: account.create_time
        }
    )

    assert self._initialize(_account, new_account_detail), "APE101"

    log AuthoriseSigner(empty(address), _new_signer, True)
    return True


@external
def token_bound_accounts(_account: address, _token_contract: address, _token_id: uint256) -> bool:
	assert msg.sender == _account, "APE017"
	assert self.is_account[_account], "APE301"
	assert _token_contract.is_contract, "APE305"

	account: AccountDetail = APELibraryManager(self.library).account_detail(_account)
	tba_account: address = self.get_account[_token_contract][_token_id]
	assert empty(address) == tba_account and empty(address) == account.token_contract, "APE304"

	new_account_detail: AccountDetail = AccountDetail(
		{
			chain_id: account.chain_id,
			token_contract: _token_contract,
			token_id: _token_id,
			creator: account.creator,
			signer: account.signer,
			create_time: account.create_time
		}
	)

	assert self._initialize(_account, new_account_detail), "APE101"
	self.get_account[_token_contract][_token_id] = _account

	log TokenBoundAccounts(_account, _token_contract, _token_id)
	return True


@external
def change_admin(_new_admin: address) -> bool:
    assert msg.sender == self.admin, "APE010"

    old_admin: address = self.admin
    self.admin = _new_admin
    log ChangeAdmin(old_admin, _new_admin)

    return True


@external
def change_library(_new_library: address):
    assert msg.sender == self.admin, "APE010"

    old_library: address = self.library
    self.library = _new_library
    log ChangeLibrary(old_library, _new_library)


@external
def withdraw(_token: address, _amount: uint256) -> bool:
    assert msg.sender == self.admin, "APE010"

    raw_call(
        _token,
        _abi_encode(
            msg.sender,
            _amount,
            method_id=method_id("transfer(address,uint256)")
        )
    )

    return True





