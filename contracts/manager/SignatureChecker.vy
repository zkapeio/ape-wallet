# @version 0.3.7


IERC1271_ISVALIDSIGNATURE_SELECTOR: public(constant(bytes4)) = 0x1626BA7E
_MALLEABILITY_THRESHOLD: constant(bytes32) = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
_SIGNATURE_INCREMENT: constant(bytes32) = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


@external
@payable
def __init__():
    pass


@view
@internal
def _is_valid_ERC1271_signature_now(_signer: address, _hash: bytes32, _signature: Bytes[65]) -> bool:

    success: bool = empty(bool)
    return_data: Bytes[32] = b""

    success, return_data = \
        raw_call(_signer, _abi_encode(_hash, _signature, method_id=IERC1271_ISVALIDSIGNATURE_SELECTOR), max_outsize=32, is_static_call=True, revert_on_failure=False)
    return (success and (len(return_data) == 32) and (convert(return_data, bytes32) == convert(IERC1271_ISVALIDSIGNATURE_SELECTOR, bytes32)))


@pure
@internal
def _recover_sig(_hash: bytes32, _signature: Bytes[65]) -> address:

    sig_length: uint256 = len(_signature)

    if (sig_length == 65):
        r: uint256 = extract32(_signature, 0, output_type=uint256)
        s: uint256 = extract32(_signature, 32, output_type=uint256)
        v: uint256 = convert(slice(_signature, 64, 1), uint256)
        return self._try_recover_vrs(_hash, v, r, s)
    elif (sig_length == 64):
        r: uint256 = extract32(_signature, 0, output_type=uint256)
        vs: uint256 = extract32(_signature, 32, output_type=uint256)
        return self._try_recover_r_vs(_hash, r, vs)
    else:
        return empty(address)


@pure
@internal
def _recover_vrs(_hash: bytes32, _v: uint256, _r: uint256, _s: uint256) -> address:

    return self._try_recover_vrs(_hash, _v, _r, _s)


@pure
@internal
def _try_recover_r_vs(_hash: bytes32, _r: uint256, vs: uint256) -> address:

    s: uint256 = vs & convert(_SIGNATURE_INCREMENT, uint256)
    v: uint256 = unsafe_add(shift(vs, -255), 27)
    return self._try_recover_vrs(_hash, v, _r, s)


@pure
@internal
def _try_recover_vrs(_hash: bytes32, _v: uint256, _r: uint256, _s: uint256) -> address:

    if (_s > convert(_MALLEABILITY_THRESHOLD, uint256)):
        raise "ECDSA: invalid signature 's' value"

    signer: address = ecrecover(_hash, _v, _r, _s)
    if (signer == empty(address)):
        raise "ECDSA: invalid signature"

    return signer


@view
@external
def is_valid_signature_now(_signer: address, _hash: bytes32, _signature: Bytes[65]) -> bool:

    recovered: address = self._recover_sig(_hash, _signature)
    if (recovered == _signer):
        return True

    return self._is_valid_ERC1271_signature_now(_signer, _hash, _signature)


@view
@external
def is_valid_ERC1271_signature_now(_signer: address, _hash: bytes32, _signature: Bytes[65]) -> bool:

    return self._is_valid_ERC1271_signature_now(_signer, _hash, _signature)


@view
@external
def recover_sig(_hash: bytes32, _signature: Bytes[65]) -> address:
    return self._recover_sig(_hash, _signature)