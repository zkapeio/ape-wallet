// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;
// import "@openzeppelin/contracts/access/Ownable.sol";

interface IBaseManager {
    function is_authorise_relayer(address _addr) external view returns (bool);
}

// contract MulticallManager is Ownable {
//     struct Call {
//         address target;
//         bytes callData;
//     }

//     struct Call3 {
//         address target;
//         bool allowFailure;
//         bytes callData;
//     }

//     struct Call3Value {
//         address target;
//         bool allowFailure;
//         uint256 value;
//         bytes callData;
//     }

//     struct Result {
//         bool success;
//         bytes returnData;
//     }

//     IBaseManager public base;

//     constructor(IBaseManager _base) {
//         base = _base;
//     }

//     modifier onlyAuthoriseRelayer() {
//         require(base.is_authorise_relayer(msg.sender));
//         _;
//     }

//     function aggregate(
//         Call[] calldata calls
//     )
//         public
//         payable
//         onlyAuthoriseRelayer
//         returns (uint256 blockNumber, bytes[] memory returnData)
//     {
//         blockNumber = block.number;
//         uint256 length = calls.length;
//         returnData = new bytes[](length);
//         Call calldata call;
//         for (uint256 i = 0; i < length; ) {
//             bool success;
//             call = calls[i];
//             (success, returnData[i]) = call.target.call(call.callData);
//             require(success, "Multicall3: call failed");
//             unchecked {
//                 ++i;
//             }
//         }
//     }

//     function tryAggregate(
//         bool requireSuccess,
//         Call[] calldata calls
//     ) public payable onlyAuthoriseRelayer returns (Result[] memory returnData) {
//         uint256 length = calls.length;
//         returnData = new Result[](length);
//         Call calldata call;
//         for (uint256 i = 0; i < length; ) {
//             Result memory result = returnData[i];
//             call = calls[i];
//             (result.success, result.returnData) = call.target.call(
//                 call.callData
//             );
//             if (requireSuccess)
//                 require(result.success, "Multicall3: call failed");
//             unchecked {
//                 ++i;
//             }
//         }
//     }

//     function tryBlockAndAggregate(
//         bool requireSuccess,
//         Call[] calldata calls
//     )
//         public
//         payable
//         onlyAuthoriseRelayer
//         returns (
//             uint256 blockNumber,
//             bytes32 blockHash,
//             Result[] memory returnData
//         )
//     {
//         blockNumber = block.number;
//         blockHash = blockhash(block.number);
//         returnData = tryAggregate(requireSuccess, calls);
//     }

//     function blockAndAggregate(
//         Call[] calldata calls
//     )
//         public
//         payable
//         onlyAuthoriseRelayer
//         returns (
//             uint256 blockNumber,
//             bytes32 blockHash,
//             Result[] memory returnData
//         )
//     {
//         (blockNumber, blockHash, returnData) = tryBlockAndAggregate(
//             true,
//             calls
//         );
//     }

//     function aggregate3(
//         Call3[] calldata calls
//     ) public payable onlyAuthoriseRelayer returns (Result[] memory returnData) {
//         uint256 length = calls.length;
//         returnData = new Result[](length);
//         Call3 calldata calli;

//         for (uint256 i = 0; i < length; ) {
//             Result memory result = returnData[i];
//             calli = calls[i];
//             (result.success, result.returnData) = calli.target.call(
//                 calli.callData
//             );
//             assembly {
//                 // Revert if the call fails and failure is not allowed
//                 // `allowFailure := calldataload(add(calli, 0x20))` and `success := mload(result)`
//                 if iszero(or(calldataload(add(calli, 0x20)), mload(result))) {
//                     // set "Error(string)" signature: bytes32(bytes4(keccak256("Error(string)")))
//                     mstore(
//                         0x00,
//                         0x08c379a000000000000000000000000000000000000000000000000000000000
//                     )
//                     // set data offset
//                     mstore(
//                         0x04,
//                         0x0000000000000000000000000000000000000000000000000000000000000020
//                     )
//                     // set length of revert string
//                     mstore(
//                         0x24,
//                         0x0000000000000000000000000000000000000000000000000000000000000017
//                     )
//                     // set revert string: bytes32(abi.encodePacked("Multicall3: call failed"))
//                     mstore(
//                         0x44,
//                         0x4d756c746963616c6c333a2063616c6c206661696c6564000000000000000000
//                     )
//                     revert(0x00, 0x64)
//                 }
//             }
//             unchecked {
//                 ++i;
//             }
//         }
//     }

//     function aggregate3Value(
//         Call3Value[] calldata calls
//     ) public payable onlyAuthoriseRelayer returns (Result[] memory returnData) {
//         uint256 valAccumulator;
//         uint256 length = calls.length;
//         returnData = new Result[](length);
//         Call3Value calldata calli;
//         for (uint256 i = 0; i < length; ) {
//             Result memory result = returnData[i];
//             calli = calls[i];
//             uint256 val = calli.value;
//             // Humanity will be a Type V Kardashev Civilization before this overflows - andreas
//             // ~ 10^25 Wei in existence << ~ 10^76 size uint fits in a uint256
//             unchecked {
//                 valAccumulator += val;
//             }
//             (result.success, result.returnData) = calli.target.call{value: val}(
//                 calli.callData
//             );
//             assembly {
//                 // Revert if the call fails and failure is not allowed
//                 // `allowFailure := calldataload(add(calli, 0x20))` and `success := mload(result)`
//                 if iszero(or(calldataload(add(calli, 0x20)), mload(result))) {
//                     // set "Error(string)" signature: bytes32(bytes4(keccak256("Error(string)")))
//                     mstore(
//                         0x00,
//                         0x08c379a000000000000000000000000000000000000000000000000000000000
//                     )
//                     // set data offset
//                     mstore(
//                         0x04,
//                         0x0000000000000000000000000000000000000000000000000000000000000020
//                     )
//                     // set length of revert string
//                     mstore(
//                         0x24,
//                         0x0000000000000000000000000000000000000000000000000000000000000017
//                     )
//                     // set revert string: bytes32(abi.encodePacked("Multicall3: call failed"))
//                     mstore(
//                         0x44,
//                         0x4d756c746963616c6c333a2063616c6c206661696c6564000000000000000000
//                     )
//                     revert(0x00, 0x84)
//                 }
//             }
//             unchecked {
//                 ++i;
//             }
//         }
//         // Finally, make sure the msg.value = SUM(call[0...i].value)
//         require(msg.value == valAccumulator, "Multicall3: value mismatch");
//     }

//     /// @notice Returns the block hash for the given block number
//     /// @param blockNumber The block number
//     function getBlockHash(
//         uint256 blockNumber
//     ) public view onlyAuthoriseRelayer returns (bytes32 blockHash) {
//         blockHash = blockhash(blockNumber);
//     }

//     /// @notice Returns the block number
//     function getBlockNumber()
//         public
//         view
//         onlyAuthoriseRelayer
//         returns (uint256 blockNumber)
//     {
//         blockNumber = block.number;
//     }

//     /// @notice Returns the block coinbase
//     function getCurrentBlockCoinbase()
//         public
//         view
//         onlyAuthoriseRelayer
//         returns (address coinbase)
//     {
//         coinbase = block.coinbase;
//     }

//     /// @notice Returns the block gas limit
//     function getCurrentBlockGasLimit()
//         public
//         view
//         onlyAuthoriseRelayer
//         returns (uint256 gaslimit)
//     {
//         gaslimit = block.gaslimit;
//     }

//     /// @notice Returns the block timestamp
//     function getCurrentBlockTimestamp()
//         public
//         view
//         onlyAuthoriseRelayer
//         returns (uint256 timestamp)
//     {
//         timestamp = block.timestamp;
//     }

//     /// @notice Returns the (ETH) balance of a given address
//     function getEthBalance(
//         address addr
//     ) public view onlyAuthoriseRelayer returns (uint256 balance) {
//         balance = addr.balance;
//     }

//     /// @notice Returns the block hash of the last block
//     function getLastBlockHash()
//         public
//         view
//         onlyAuthoriseRelayer
//         returns (bytes32 blockHash)
//     {
//         unchecked {
//             blockHash = blockhash(block.number - 1);
//         }
//     }

//     /// @notice Gets the base fee of the given block
//     /// @notice Can revert if the BASEFEE opcode is not implemented by the given chain
//     function getBasefee()
//         public
//         view
//         onlyAuthoriseRelayer
//         returns (uint256 basefee)
//     {
//         basefee = block.basefee;
//     }

//     /// @notice Returns the chain id
//     function getChainId()
//         public
//         view
//         onlyAuthoriseRelayer
//         returns (uint256 chainid)
//     {
//         chainid = block.chainid;
//     }

//     function setBase(IBaseManager _base) public onlyOwner {
//         base = _base;
//     }

//     function isAuthoriseRelayer(address _addr) public view returns (bool) {
//         return base.is_authorise_relayer(_addr);
//     }
// }
