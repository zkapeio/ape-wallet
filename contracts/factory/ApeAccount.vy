# @version 0.3.7

interface SignatureChecker:
    def is_valid_signature_now(
        signer: address,
        hash: bytes32,
        signature: Bytes[65]
    ) -> bool: view

interface ApeFactory:
    def storage_accounts(_account: address, _token: address, _token_id: uint256) -> bool: nonpayable

interface SecurityManager:
    def is_lock(_account: address) -> bool: view
    def daily_withdrawl_limit_for_native(_account: address) -> uint256: view

interface ERC721:
    def ownerOf(_token_id: uint256) -> address: view


event Received:
    _sender: indexed(address)
    _value: uint256
    _calldata: bytes32

event Initialize:
    _creator: indexed(address)
    _contract: indexed(address)
    _token_id: uint256
    _chain_id: uint256

event AuthoriseProxy:
    _old_proxy: indexed(address)
    _new_proxy: indexed(address)
    _status: bool

event AuthoriseSigner:
    _old_signer: indexed(address)
    _new_signer: indexed(address)
    _status: bool

event TokenBoundAccounts:
    _account: indexed(address)
    _token_contract: indexed(address)
    _token_id: indexed(uint256)

event Execute:
    _to: indexed(address)
    _value: indexed(uint256)
    _data: indexed(Bytes[max_value(uint16)])


DAY: constant(uint256) = 86400
IERC1271_ISVALIDSIGNATURE_SELECTOR: public(constant(bytes4)) = 0x1626BA7E

is_initialized: bool
token_contract: address
token_id: uint256
chain_id: uint256
is_created: bool
start_time: uint256

day: public(uint256)
daily_transfer: public(HashMap[uint256, uint256])
creator: public(address)
signer: public(address)
factory: public(address)
signature_checker: public(address)
proxy: public(address)
nonce: public(uint256)
security: public(address)


@payable
@external
def __default__():
    log Received(msg.sender, msg.value, empty(bytes32))


@internal
def _check_daily_limit(_value: uint256):

    dt0: uint256 = block.timestamp - self.start_time

    if dt0 >= DAY:
        self.day = dt0 / DAY

    daily_limit: uint256 = SecurityManager(self.security).daily_withdrawl_limit_for_native(self)
    self.daily_transfer[self.day] += _value

    assert self.daily_transfer[self.day] <= daily_limit, "Ape: transfer limit"


@view
@external
def token() -> (uint256, address, uint256):
    return self.chain_id, self.token_contract, self.token_id


@view
@internal
def _owner() -> address:
    if self.chain_id != chain.id or self.token_contract == empty(address):
        return empty(address)
    
    return ERC721(self.token_contract).ownerOf(self.token_id)


@view
@external
def owner() -> address:
    return self._owner()


@view
@external
def isValidSignature(_hash: bytes32, _signature: Bytes[65]) -> bytes4:

    is_owner_valid: bool = False

    if self._owner() != empty(address):
        is_owner_valid = SignatureChecker(self.signature_checker).is_valid_signature_now(self._owner(), _hash, _signature)
    is_signer_valid: bool = SignatureChecker(self.signature_checker).is_valid_signature_now(self.signer, _hash, _signature)

    if is_owner_valid or is_signer_valid:
        return IERC1271_ISVALIDSIGNATURE_SELECTOR

    return empty(bytes4)


@view
@external
def supportsInterface(interface_id: bytes4) -> bool:

    return interface_id in [
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
def onERC1155BatchReceived(_operator: address, _from: address, _ids: DynArray[uint256, 65535], _values: DynArray[uint256, 65535], _data: Bytes[1024]) -> bytes4:
    return method_id("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)", output_type=bytes4)


@external
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
) -> bool:
    assert not self.is_initialized, "Already initialized"
    
    self.creator = _creator
    self.signer = _signer
    self.factory = _factory
    self.proxy = _proxy

    self.token_contract = _contract
    self.token_id = _token_id
    log TokenBoundAccounts(self, _contract, _token_id)

    self.signature_checker = _signature
    self.security = _security
    self.chain_id = _chain_id
    self.is_initialized = True

    self.start_time = block.timestamp

    log Initialize(_creator, _contract, _token_id, _chain_id)
    return True


@external
def authorise_proxy(_new_proxy: address) -> bool:
    assert msg.sender == self.proxy, "Only proxy"
    
    old_proxy: address = self.proxy

    self.proxy = _new_proxy

    log AuthoriseProxy(old_proxy, _new_proxy, True)
    return True


@external
def authorise_signer(_new_signer: address) -> bool:
    assert msg.sender == self.proxy, "Only proxy"

    self.signer = _new_signer

    log AuthoriseSigner(empty(address), _new_signer, True)
    return True


@external
def token_bound_accounts(_token: address, _token_id: uint256) -> bool:
    assert self.token_contract == empty(address), "Token already TBAs"
    assert msg.sender == self.proxy, "Only proxy"
    
    self.token_contract = _token
    self.token_id = _token_id
    assert ApeFactory(self.factory).storage_accounts(self, _token, _token_id, default_return_value=True) # dev: fail

    log TokenBoundAccounts(self, _token, _token_id)
    return True


@external
def execute(_target: address, _value: uint256, _data: Bytes[max_value(uint16)]) -> bool:
    assert msg.sender in [self._owner(), self.proxy], "Only owner or proxy"
    assert not SecurityManager(self.security).is_lock(self), "account locked"

    if _value != 0:
        self._check_daily_limit(_value)

    success: bool = False
    return_data: Bytes[32] = b""

    success, return_data = raw_call(_target, _data, max_outsize=32, value=_value, revert_on_failure=False)
    
    if len(return_data) != 0:
        assert convert(return_data, bool), "Invalid call"
        
    assert success, "account: call fail"

    self.nonce += 1

    log Execute(_target, _value, _data)
    return True


