# @version 0.3.7


interface ApeAccount:
    def isValidSignature(_hash: bytes32, _signature: Bytes[65]) -> bytes4: view

interface SecurityManager:
    def get_guardian_count(_account: address) -> uint256: view
    def is_guardian(_account: address, _guardian: address) -> bool: view
    def signature() -> address: view

interface OracleManager:
    def in_token(_token: address, _eth_amount: uint256) -> uint256: view
    def in_eth(_token: address, _token_amount: uint256) -> uint256: view

interface SignatureChecker:
    def recover_sig(_hash: bytes32, _signature: Bytes[65]) -> address: view


event AddAuthoriseRelayer:
    relayer: indexed(address)
    exists: bool

event RemoveAuthoriseRelayer:
    relayer: indexed(address)
    exists: bool

event AddedToWhitelist:
    wallet: indexed(address)
    target: indexed(address)
    period: uint256

event RemovedForWhitelist:
    wallet: indexed(address)
    target: indexed(address)

event TranscationExecuted:
     wallet: indexed(address)
     success: bool
     return_data: Bytes[max_value(uint16)]

event Refund:
     wallet: indexed(address)
     refund_address: indexed(address)
     refund_token: address
     refund_amount: uint256

event ChangeOwner:
    old_owner: indexed(address)
    new_owner: indexed(address)

event ChangeProxy:
    old_proxy: indexed(address)
    new_proxy: indexed(address)

event ChangeOracle:
    old_oracle: indexed(address)
    new_oracle: indexed(address)


struct MultiCall:
    target: address
    allow_failure: bool
    value: uint256
    call_data: Bytes[max_value(uint16)]

struct Result:
    success: bool
    return_data: Bytes[max_value(uint8)]

struct ExecuteParameters:
    owner: address
    account: address
    transaction_to: address
    transaction_calldata: Bytes[max_value(uint16)]
    transaction_value: uint256
    nonce: uint256
    gas_price: uint256
    gas_limit: uint256
    deadline: uint256
    refund_token: address
    refund_address: address
    signature: Bytes[16575]

NATIVE_TOKEN: constant(address) = empty(address)
EMPTY_BYTES: constant(bytes32) = empty(bytes32)
IERC1271_ISVALIDSIGNATURE_SELECTOR: public(constant(bytes4)) = 0x1626BA7E

EXECUTE_PARAMETERS_TYPEHASH: constant(bytes32) = keccak256(
    "ExecuteParameters(address owner,address account,address transaction_to,uint256 transaction_value,uint256 nonce,uint256 gas_price,uint256 gas_limit,uint256 deadline,address refund_token,address refund_address)"
)
EIP712_TYPEHASH: constant(bytes32) = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")

DOMAIN_SEPARATOR: immutable(bytes32)
NAME: immutable(String[64])
VERSION: constant(String[8]) = "v1.0.0"

owner: public(address)
authorise_relayer: HashMap[address, bool]

whitelist_period: public(uint256)
whitelist: HashMap[address, HashMap[address, uint256]]

proxy: public(address)
oracle: public(address)
security: public(address)
sig_checker: public(address)
expired_hash: public(HashMap[bytes32, bool])


@external
def __init__(_relayer: address, _whitelist_period: uint256, _proxy: address, _oracle: address, _security: address):
    self.owner = msg.sender
    self.authorise_relayer[_relayer] = True
    self.whitelist_period = _whitelist_period

    self.proxy = _proxy
    self.oracle = _oracle
    self.security = _security

    self.sig_checker = SecurityManager(_security).signature()

    name: String[64] = concat("Ape Wallet Base Manager", " v1")
    NAME = name

    DOMAIN_SEPARATOR = keccak256(
        _abi_encode(EIP712_TYPEHASH, keccak256(name), keccak256(VERSION), chain.id, self)
    )


@view
@external
def is_authorise_relayer(_relayer: address) -> bool:
    return self._is_authorise_relayer(_relayer)


@view
@external
def is_whitelist(_wallet: address, _target: address) -> bool:
    return self._is_whitelist(_wallet, _target)
    

@view
@internal
def _is_authorise_relayer(_relayer: address) -> bool:
    return self.authorise_relayer[_relayer]


@view
@internal
def _is_whitelist(_wallet: address, _target: address) -> bool:
    assert _wallet != _target, "Ape: Cannot whitelist wallet"

    _iw: bool = False
    if self.whitelist[_wallet][_target] != 0:
        _iw = True
    return _iw


@pure
@internal
def _execute_parameters_hash(_param: ExecuteParameters) -> bytes32:

    param_hash: bytes32 = keccak256(
        _abi_encode(
            EXECUTE_PARAMETERS_TYPEHASH,
            _param.owner,
            _param.account,
            _param.transaction_to,
            _param.transaction_value,
            _param.nonce,
            _param.gas_price,
            _param.gas_limit,
            _param.deadline,
            _param.refund_token,
            _param.refund_address
        )
    )

    digest: bytes32 = keccak256(
        concat(
            b"\x19\x01",
            DOMAIN_SEPARATOR,
            param_hash
        )
    )

    return digest


@view
@internal
def _get_method_id(_data: Bytes[max_value(uint16)]) -> bytes4:
    assert len(_data) != 0, "Ape: empty data"

    method: bytes4 = convert(slice(_data, 0, 4), bytes4)
    return method


@view
@internal
def _get_guardian_approvals_count(_account: address) -> uint256:

    gac: uint256 = SecurityManager(self.security).get_guardian_count(_account)
    return convert(ceil(convert(gac, decimal) / convert(2, decimal)), uint256)


@view
@internal
def _recover_sig(_hash: bytes32, _signature: Bytes[16575], _slice: uint256) -> address:
    
    _data: Bytes[65] = slice(_signature, _slice, 65)
    signer: address = SignatureChecker(self.sig_checker).recover_sig(_hash, _data)

    return signer


@view
@internal
def _get_required_signatures_from_account(_account: address, _data: Bytes[max_value(uint16)]) -> (uint256, uint256):

    if len(_data) != 0:
        method: bytes4 = self._get_method_id(_data)

        if method == method_id("config_guardian_addition(address,address)", output_type=bytes4) or \
            method == method_id("config_guardian_revoke(address,address)", output_type=bytes4) or \
            method == method_id("finalize_recovery(address)", output_type=bytes4):
            # anyone 
            return (0, 5)

        if method == method_id("add_guardian(address,address)", output_type=bytes4) or \
            method == method_id(
                "add_guardian_with_permit((address,address,address,uint256,uint256,uint256,uint256,uint256,bytes),(address,address,address,uint256,uint256,uint256,uint256,uint256,bytes)))", 
                output_type=bytes4) or \
            method == method_id("cancel_guardian_addition(address,address)", output_type=bytes4) or \
            method == method_id("revoke_guardian(address,address)", output_type=bytes4) or \
            method == method_id("cancel_guardian_revoke(address,address)", output_type=bytes4) or \
            method == method_id(
                "execute_recovery_with_permit(address,(address,address,address,address,uint256,uint256,uint256,bytes)[])", 
                output_type=bytes4) or \
            method == method_id("token_bound_accounts(address,address,uint256)", output_type=bytes4) or \
            method == method_id("authorise_proxy(address,address)", output_type=bytes4):
            # only owner
            return (1, 1)

        if method == method_id("execute_recovery(address,address)", output_type=bytes4):
            gac: uint256 = self._get_guardian_approvals_count(_account)
            assert gac > 0, "Ape: insufficient guardian"
            # owner+guardian or more guardian
            return (gac, 3)
        
        if method == method_id("cancel_account_recovery(address)", output_type=bytes4):
            gac: uint256 = SecurityManager(self.security).get_guardian_count(_account)
            return (convert(ceil(convert((gac+1)/2, decimal)), uint256), 3)
        
        if method == method_id("lock(address)", output_type=bytes4) or \
            method == method_id("unlock(address)", output_type=bytes4) or \
            method == method_id("daily_withdrawl_limit(address,uint256)", output_type=bytes4):
            # any guardian 
            return (1, 2)
    
    gac: uint256 = self._get_guardian_approvals_count(_account)

    # owner + more guardian
    return (gac + 1, 4)


@view
@internal
def _check_and_valid_signature(_account: address, _hash: bytes32, _signature: Bytes[16575], _option: uint256) -> bool:
    
    if len(_signature) == 0:
        return True

    for i in range(255):
        if i >= (len(_signature) / 65):
            break
        
        signer: address = self._recover_sig(_hash, _signature, i*65)
        
        if i == 0:
            _data: Bytes[65] = slice(_signature, 0, 65)
            if _option == 1 or _option == 4:
                if IERC1271_ISVALIDSIGNATURE_SELECTOR == ApeAccount(_account).isValidSignature(_hash, _data):
                    continue
                return False
            elif _option == 3:
                if IERC1271_ISVALIDSIGNATURE_SELECTOR == ApeAccount(_account).isValidSignature(_hash, _data):
                    continue

        if signer == empty(address):
            return False
        
        is_guardian: bool = SecurityManager(self.security).is_guardian(_account, signer)

        if not is_guardian:
            return False

    return True


@internal
def _refund(
    _account: address,
    _calldata: Bytes[max_value(uint16)],
    _start_gas: uint256,
    _gas_price: uint256,
    _gas_limit: uint256,
    _refund_token: address,
    _refund_address: address
) -> bool:
    
    if _gas_price > 0:
        assert _refund_address != empty(address), "Ape: empty refund address"

        refund_amount: uint256 = 0

        # empty(address) is ETH
        if _refund_token == empty(address):

            gas_consumed: uint256 = _start_gas - msg.gas + 23000
            refund_amount = min(gas_consumed, _gas_limit) * min(_gas_price, tx.gasprice)
            
            raw_call(
                self.proxy,
                _abi_encode(
                    _account,
                    _refund_address,
                    refund_amount,
                    _calldata,
                    method_id=method_id("execute(address,address,uint256,bytes)")
                )
            )

        else:
            gas_consumed: uint256 = _start_gas - msg.gas + 37500
            
            # Here it is also necessary to calculate how many tokens the gas price can be exchanged for
            # Then the final gas fee to be paid is obtained by gaslimit * token price
            token_gas_price: uint256 = OracleManager(self.oracle).in_token(_refund_token, tx.gasprice)
            # token_gas_price: uint256 = tx.gasprice
            refund_amount = min(gas_consumed, _gas_limit) + min(_gas_price, token_gas_price)

            success: bool = False
            response: Bytes[32] = b""

            success, response = raw_call(
                self.proxy,
                _abi_encode(
                    _account,
                    _refund_token,
                    empty(uint256),
                    _abi_encode(
                        _refund_address,
                        refund_amount,
                        method_id=method_id("transfer(address,uint256)")
                    ),
                    method_id=method_id("execute(address,address,uint256,bytes)")
                ),
                max_outsize=32,
                revert_on_failure=False
            )

            if len(response) != 0:
                assert convert(response, bool), "Ape: call fail"

            assert success, "Ape: refund transfer fail"

        log Refund(_account, _refund_address, _refund_token, refund_amount)

    return True


@external
def add_authorise_relayer(_relayer: address):
    assert self.authorise_relayer[msg.sender] or msg.sender == self.owner, "Ape: sender not authorized"
    
    self.authorise_relayer[_relayer] = True
    log AddAuthoriseRelayer(_relayer, True)


@external
def remove_authorise_relayer(_relayer: address):
    assert self.authorise_relayer[msg.sender] or msg.sender == self.owner, "Ape: sender not authorized"

    self.authorise_relayer[_relayer] = False
    log RemoveAuthoriseRelayer(_relayer, False)


@external
def add_whitelist(_wallet: address, _target: address):
    assert _wallet != _target, "Ape: cannot whitelist wallet"
    assert not self._is_whitelist(_wallet, _target), "Ape: target already whitelisted"
    assert self.authorise_relayer[msg.sender] or msg.sender == self.owner, "Ape: sender not authorized"

    whitelistAfter: uint256 = block.timestamp + self.whitelist_period
    self.whitelist[_wallet][_target] = whitelistAfter

    log AddedToWhitelist(_wallet, _target, whitelistAfter)


@external
def remove_whitelist(_wallet: address, _target: address):
    assert self.authorise_relayer[msg.sender] or msg.sender == self.owner, "Ape: sender not authorized"

    self.whitelist[_wallet][_target] = 0
    
    log RemovedForWhitelist(_wallet, _target)


@external
def change_owner(_new_owner: address):
    assert msg.sender == self.owner, "Ape: only owner"
    
    old_owner: address = self.owner
    self.owner = _new_owner
    log ChangeOwner(old_owner, _new_owner)


@external
def change_proxy(_new_proxy: address):
    assert msg.sender == self.owner, "Ape: only owner"
    
    old_proxy: address = self.proxy
    self.proxy = _new_proxy
    log ChangeProxy(old_proxy, _new_proxy)
    

@external
def change_oracle(_new_oracle: address):
    assert msg.sender == self.owner, "Ape: only owner"
    
    old_oracle: address = self.oracle
    self.oracle = _new_oracle
    log ChangeOracle(old_oracle, _new_oracle)


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


@external
def multi_call(_transactions: DynArray[MultiCall, 30]) -> DynArray[Result, 30]:
    assert self._is_authorise_relayer(msg.sender), "Ape: sender not be authorise"
    assert len(_transactions) != 0, "empty call"

    results: DynArray[Result, 30] = []
    return_data: Bytes[max_value(uint8)] = b""
    success: bool = empty(bool)

    for i in range(30):
        if i >= len(_transactions):
            break

        if _transactions[i].allow_failure == False:
            return_data = raw_call(
                self,
                _transactions[i].call_data,
                max_outsize=255,
                is_delegate_call=True
            )
            success = True

            results.append(Result({success: success, return_data: return_data}))

        else:
            success, return_data = raw_call(
                _transactions[i].target,
                _transactions[i].call_data,
                max_outsize=255,
                is_delegate_call=True,
                revert_on_failure=False
            )

            results.append(Result({success: success, return_data: return_data}))

    return results


@external
def execute(_param: ExecuteParameters) -> bool:
    assert self._is_authorise_relayer(msg.sender), "Ape: sender not be authorise"
    assert block.timestamp <= _param.deadline, "expired deadline"

    # gas = 21k + non zero byte * 16 + zero byte * 4
    #     ~= 21k + len(msg.data) * [1/3 * 16 + 2/3 * 4]
    start_gas: uint256 = msg.gas + 21000 + len(msg.data) * 8
    assert start_gas >= _param.gas_limit, "not enough gas provided"

    digest: bytes32 = self._execute_parameters_hash(_param)
    assert not self.expired_hash[digest], "Ape: expired hash"

    number_of_sig: uint256 = 0
    option: uint256 = 0

    number_of_sig, option = self._get_required_signatures_from_account(_param.account, _param.transaction_calldata)
    assert number_of_sig > 0 or option == 5, "Ape: wrong signature"
    assert number_of_sig * 65 == len(_param.signature), "Ape: Insufficient signature"
    assert self._check_and_valid_signature(_param.account, digest, _param.signature, option), "Ape: signature fail"

    refund_success: bool = self._refund(
        _param.account,
        b"",
        start_gas,
        _param.gas_price,
        _param.gas_limit,
        _param.refund_token,
        _param.refund_address
    )

    assert refund_success, "Ape: refund fail"

    success: bool = False
    return_data: Bytes[32] = b""

    success, return_data = raw_call(
        self.proxy,
        _abi_encode(
            _param.account,
            _param.transaction_to,
            _param.transaction_value,
            _param.transaction_calldata,
            method_id=method_id("execute(address,address,uint256,bytes)")
        ),
        max_outsize=32,
        revert_on_failure=False
    )
    assert success, "Ape: call fail"

    log TranscationExecuted(_param.account, success, return_data)
    return success

