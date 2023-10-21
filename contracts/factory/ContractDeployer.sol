// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract CreateZksyncContract {

    function create2(bytes32 _salt, bytes memory _bytecode) external returns (address addr) {
        assembly {
            addr := create2(0, add(_bytecode, 32), mload(_bytecode), _salt)
        }
        require(addr != address(0), "Failed to create contract");

        return addr;
    }
}
