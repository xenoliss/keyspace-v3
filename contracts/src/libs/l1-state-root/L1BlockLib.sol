// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockLib} from "../BlockLib.sol";
import {StorageProofLib} from "../StorageProofLib.sol";

library L1BlockLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Address of the L1Block oracle on OP Stack chains.
    address constant L1BLOCK_PREDEPLOY_ADDRESS = 0x4200000000000000000000000000000000000015;

    /// @notice Storage slot where the L1 block hash is stored on the L1Block oracle.
    bytes32 constant L1BLOCK_HASH_SLOT = bytes32(uint256(2));

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the L2 block header hash does not match the hash retrieved using `blockhash`.
    ///
    /// @param blockHeaderHash The hash of the L2 block header being verified.
    /// @param blockHash The actual block hash retrieved using `blockhash`.
    error InvalidL2BlockHeader(bytes32 blockHeaderHash, bytes32 blockHash);

    /// @notice Thrown when the L1 block hash extracted from the proof does not match the expected value.
    ///
    /// @param l1Blockhash The L1 block hash extracted from the proof.
    /// @param expectedL1BlockHash The expected L1 block hash based on the proof data.
    error L1BlockHashMismatch(bytes32 l1Blockhash, bytes32 expectedL1BlockHash);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STRUCTURES                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice An L1 state root proof that relies on the OPStack's L1Block predeployed contract.
    struct L1BlockProof {
        /// @dev The L1 block header to verify, encoded in RLP format.
        bytes l1BlockHeaderRlp;
        /// @dev The L2 block header, encoded in RLP format.
        bytes l2BlockHeaderRlp;
        /// @dev The Merkle proof for the L1Block oracle account on the L2 chain.
        bytes[] l1BlockAccountProof;
        /// @dev The Merkle proof for the L1 block hash storage slot in the L1Block oracle account.
        bytes[] l1BlockStorageProof;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Extracts the L1 state root (and corresponding L1 block timestamp) from a serialized `L1BlockProof`.
    ///
    /// @param proof The serialized proof data.
    ///
    /// @return l1BlockTimestamp The timestamp L1 block.
    /// @return l1StateRoot The L1 state root.
    function verify(bytes memory proof) internal view returns (uint256 l1BlockTimestamp, bytes32 l1StateRoot) {
        // Decode the `L1BlockProof` proof.
        L1BlockProof memory l1BlockProof = abi.decode(proof, (L1BlockProof));

        // Parse the L1 block header from the provided RLP data.
        BlockLib.BlockHeader memory l1BlockHeader = BlockLib.parseBlockHeader(l1BlockProof.l1BlockHeaderRlp);

        // Parse the L2 block header from the provided RLP data.
        BlockLib.BlockHeader memory l2BlockHeader = BlockLib.parseBlockHeader(l1BlockProof.l2BlockHeaderRlp);

        // Retrieve the block hash for the specified L2 block number using `blockhash`.
        bytes32 blockHash = blockhash(l2BlockHeader.number);

        // Verify that the L2 block header hash matches the retrieved block hash.
        // NOTE: Because blockHeader.hash is guaranteed to not be 0, this also ensure that the provided
        //       `blockHeader.number` is not too old.
        require(
            blockHash == l2BlockHeader.hash,
            InvalidL2BlockHeader({blockHeaderHash: l2BlockHeader.hash, blockHash: blockHash})
        );

        // Extract the L1 block hash from the L2 state root using the provided account and storage proofs.
        (, bytes32 l1Blockhash) = StorageProofLib.extractAccountStorageValue({
            stateRoot: l2BlockHeader.stateRoot,
            account: L1BLOCK_PREDEPLOY_ADDRESS,
            accountProof: l1BlockProof.l1BlockAccountProof,
            slot: L1BLOCK_HASH_SLOT,
            storageProof: l1BlockProof.l1BlockStorageProof
        });

        // Verify that the extracted L1 block hash matches the one provided in the L1 block header.
        require(
            l1Blockhash == l1BlockHeader.hash,
            L1BlockHashMismatch({l1Blockhash: l1Blockhash, expectedL1BlockHash: l1BlockHeader.hash})
        );

        // Return the verified L1 block timestamp and state root.
        l1BlockTimestamp = l1BlockHeader.timestamp;
        l1StateRoot = l1BlockHeader.stateRoot;
    }
}
