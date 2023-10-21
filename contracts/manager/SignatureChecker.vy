# @version 0.3.9


IERC1271_ISVALIDSIGNATURE_SELECTOR: public(constant(bytes4)) = 0x1626BA7E
_MALLEABILITY_THRESHOLD: constant(bytes32) = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
_SIGNATURE_INCREMENT: constant(bytes32) = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


@payable
@external
def __init__():
    pass


@view
@internal
def _is_valid_ERC1271_signature_now(signer: address, hash: bytes32, signature: Bytes[65]) -> bool:

    success: bool = empty(bool)
    return_data: Bytes[32] = b""

    success, return_data = \
        raw_call(signer, _abi_encode(hash, signature, method_id=IERC1271_ISVALIDSIGNATURE_SELECTOR), max_outsize=32, is_static_call=True, revert_on_failure=False)
    return (success and (len(return_data) == 32) and (convert(return_data, bytes32) == convert(IERC1271_ISVALIDSIGNATURE_SELECTOR, bytes32)))


@pure
@internal
def _recover_sig(hash: bytes32, signature: Bytes[65]) -> address:

    sig_length: uint256 = len(signature)
    if (sig_length == 65):
        r: uint256 = extract32(signature, empty(uint256), output_type=uint256)
        s: uint256 = extract32(signature, 32, output_type=uint256)
        v: uint256 = convert(slice(signature, 64, 1), uint256)
        return self._try_recover_vrs(hash, v, r, s)
    elif (sig_length == 64):
        r: uint256 = extract32(signature, empty(uint256), output_type=uint256)
        vs: uint256 = extract32(signature, 32, output_type=uint256)
        return self._try_recover_r_vs(hash, r, vs)
    else:
        return empty(address)


@pure
@internal
def _recover_vrs(hash: bytes32, v: uint256, r: uint256, s: uint256) -> address:

    return self._try_recover_vrs(hash, v, r, s)


@pure
@internal
def _try_recover_r_vs(hash: bytes32, r: uint256, vs: uint256) -> address:

    s: uint256 = vs & convert(_SIGNATURE_INCREMENT, uint256)
    v: uint256 = unsafe_add(vs >> 255, 27)
    return self._try_recover_vrs(hash, v, r, s)


@pure
@internal
def _try_recover_vrs(hash: bytes32, v: uint256, r: uint256, s: uint256) -> address:
    assert s <= convert(_MALLEABILITY_THRESHOLD, uint256), "ECDSA: invalid signature `s` value"

    signer: address = ecrecover(hash, v, r, s)
    assert signer != empty(address), "ECDSA: invalid signature"

    return signer


@view
@external
def is_valid_signature_now(signer: address, hash: bytes32, signature: Bytes[65]) -> bool:

    recovered: address = self._recover_sig(hash, signature)
    if (recovered == signer):
        return True

    return self._is_valid_ERC1271_signature_now(signer, hash, signature)


@view
@external
def is_valid_ERC1271_signature_now(signer: address, hash: bytes32, signature: Bytes[65]) -> bool:
    return self._is_valid_ERC1271_signature_now(signer, hash, signature)


@view
@external
def recover_sig(_hash: bytes32, _signature: Bytes[65]) -> address:
    return self._recover_sig(_hash, _signature)

