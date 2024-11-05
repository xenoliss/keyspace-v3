// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockHeader, BlockLib} from "./BlockLib.sol";
import {Config} from "./ConfigLib.sol";
import {L1BlockHashProof, L1ProofLib} from "./L1ProofLib.sol";
import {StorageProofLib} from "./StorageProofLib.sol";

// TODO: Merge the lib within the Keystore abstract contract.

/// @dev A proof from which a Kesytore config hash can be extracted.
struct KeystoreProof {
    /// @dev The L1 block header, RLP-encoded.
    bytes l1BlockHeaderRlp;
    /// @dev The L1 block hash proof.
    L1BlockHashProof l1BlockHashProof;
    /// @dev The Keystore account proof on the master chain.
    bytes[] masterKeystoreAccountProof;
    /// @dev The Keystore storage proof on the master chain.
    bytes[] masterKeystoreStorageProof;
    /// @dev The state root of the master L2.
    bytes32 l2StateRoot;
    /// @dev The L2 state root specific proof.
    bytes l2StateRootProof;
}

/// @dev The proofs provided to a Keystore record controller to authorize an update.
struct ControllerProofs {
    /// @dev A proof provided to the Keystore record `controller` to authorize an update.
    bytes updateProof;
    /// @dev OPTIONAL: A safeguard proof provided to the Keystore record `controller` to ensure the new Keystore config
    ///                is as expected.
    bytes updatedConfigProof;
}

library KeystoreLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the provided new nonce is not strictly equal the current nonce incremented by one.
    ///
    /// @param currentNonce The current nonce of the Keystore record.
    /// @param newNonce The provided new nonce.
    error NonceNotIncrementedByOne(uint256 currentNonce, uint256 newNonce);

    /// @notice Thrown when the Keystore record controller prevents the update.
    error UnauthorizedUpdate();

    /// @notice Thrown when the updated Keystore record value does not verify against the provided proof
    ///         for the updated value.
    error UnexpectedUpdate();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Authorizes a Keystore config update.
    ///
    /// @param currentConfig The current Keystore config.
    /// @param newConfig The new Keystore config.
    /// @param l1BlockData OPTIONAL: An L1 block header, RLP-encoded, and a proof of its validity.
    ///                              If present, it is expected to be `abi.encode(l1BlockHeaderRlp, l1BlockHashProof)`.
    ///                              This OPTIONAL L1 block header is meant to be provided to the Keystore record
    ///                              controller `authorize` method to perform authorization based on the L1 state.
    /// @param controllerProofs The `ControllerProofs` struct containing the necessary proofs to authorize the update.
    /// @param authorizeUpdate The config update authorization logic.
    function verifyNewConfig(
        Config memory currentConfig,
        Config calldata newConfig,
        bytes calldata l1BlockData,
        ControllerProofs calldata controllerProofs,
        function(bytes memory, bytes calldata, BlockHeader memory, bytes calldata) returns (bool) authorizeUpdate
    ) internal {
        // Ensure the nonce is strictly incrementing.
        require(
            newConfig.nonce == currentConfig.nonce + 1,
            NonceNotIncrementedByOne({currentNonce: currentConfig.nonce, newNonce: newConfig.nonce})
        );

        // If provided, parse the L1 block header and ensure it's valid.
        BlockHeader memory l1BlockHeader;
        if (l1BlockData.length > 0) {
            (bytes memory l1BlockHeaderRlp, L1BlockHashProof memory l1BlockHashProof) =
                abi.decode(l1BlockData, (bytes, L1BlockHashProof));

            l1BlockHeader = BlockLib.parseBlockHeader(l1BlockHeaderRlp);
            L1ProofLib.verify({proof: l1BlockHashProof, expectedL1BlockHash: l1BlockHeader.hash});
        }

        // Ensure the config update is authorized.
        require(
            authorizeUpdate(currentConfig.data, newConfig.data, l1BlockHeader, controllerProofs.updateProof),
            UnauthorizedUpdate()
        );

        // If provided, ensure the updated config proof is valid.
        if (controllerProofs.updatedConfigProof.length > 0) {
            require(
                authorizeUpdate(newConfig.data, newConfig.data, l1BlockHeader, controllerProofs.updatedConfigProof),
                UnexpectedUpdate()
            );
        }
    }

    /// @notice Extracts the Keystore config hash from the master chain.
    ///
    /// @dev The following proving steps are performed to exract a Keystore config hash from the master chain:
    ///      1. Prove the validity of the provided `blockHeaderRlp` against the L1 block hash returned by the
    ///         `l1BlockHashOracle`.
    ///      2. Verify the master `l2StateRoot` using the specific master L2 state root validation logic.
    ///      3. From the master `l2StateRoot`, prove the Keystore storage root on the master chain.
    ///      4. From the Keystore storage root on the master chain, prove the config hash.
    /// @param configHashSlot The storage slot of the config hash.
    /// @param keystoreProof The `keystoreProof` struct.
    /// @param verifyMasterL2StateRoot The specific master L2 state root validation logic.
    function extractKeystoreConfigHash(
        bytes32 configHashSlot,
        KeystoreProof memory keystoreProof,
        function(bytes32, BlockHeader memory, bytes memory) view verifyMasterL2StateRoot
    ) internal view returns (uint256 l1BlockTimestamp, bytes32 configHash) {
        // Parse the provided L1 block header.
        BlockHeader memory l1BlockHeader = BlockLib.parseBlockHeader(keystoreProof.l1BlockHeaderRlp);
        l1BlockTimestamp = l1BlockHeader.timestamp;

        // Ensure the provided L1 block header can be used (i.e the block hash is valid).
        L1ProofLib.verify({proof: keystoreProof.l1BlockHashProof, expectedL1BlockHash: l1BlockHeader.hash});

        // Call the specific master L2 state root validation logic.
        verifyMasterL2StateRoot(keystoreProof.l2StateRoot, l1BlockHeader, keystoreProof.l2StateRootProof);

        // From the master L2 state root, extract the `MasterKeystore` storage root.
        bytes32 masterKeystoreStorageRoot = StorageProofLib.extractAccountStorageRoot({
            stateRoot: keystoreProof.l2StateRoot,
            account: address(this),
            accountProof: keystoreProof.masterKeystoreAccountProof
        });

        // From the `MasterKeystore` storage root, extract the config hash at the computed `recordSlot`.
        configHash = StorageProofLib.extractSlotValue({
            storageRoot: masterKeystoreStorageRoot,
            slot: keccak256(abi.encodePacked(configHashSlot)),
            storageProof: keystoreProof.masterKeystoreStorageProof
        });
    }
}
