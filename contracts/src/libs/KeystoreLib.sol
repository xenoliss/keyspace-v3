// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockHeader, IRecordController} from "../interfaces/IRecordController.sol";

import {BlockLib} from "./BlockLib.sol";
import {Config, ConfigLib} from "./ConfigLib.sol";
import {L1BlockHashProof, L1ProofLib} from "./L1ProofLib.sol";
import {StorageProofLib} from "./StorageProofLib.sol";

/// @dev A proof from which a Kesytore config hash can be extracted.
struct KeystoreProof {
    /// @dev The L1 block header, RLP-encoded.
    bytes l1BlockHeaderRlp;
    /// @dev The L1 block hash proof.
    L1BlockHashProof l1BlockHashProof;
    /// @dev The `AnchorStateRegistry` account proof on L1.
    bytes[] anchorStateRegistryAccountProof;
    /// @dev The storage proof of the master L2 OutputRoot stored in the `AnchorStateRegistry` contract on L1.
    bytes[] anchorStateRegistryStorageProof;
    /// @dev The `MasterKeystore` account proof.
    bytes[] masterKeystoreAccountProof;
    /// @dev The `MasterKeystore` record storage proof.
    bytes[] masterKeystoreRecordStorageProof;
    /// @dev The state root of the master L2.
    bytes32 l2StateRoot;
    /// @dev The storage root of the `MessagePasser` contract on the master L2.
    bytes32 l2MessagePasserStorageRoot;
    /// @dev The block hash of the master L2.
    bytes32 l2BlockHash;
}

/// @dev The proofs provided to a Keystore record controller to authorize an update.
struct ControllerProofs {
    /// @dev A proof provided to the Keystore record `controller` to authorize an update.
    bytes updateProof;
    /// @dev OPTIONAL: A safeguard proof provided to the Keystore record `controller` to ensure the updated record value
    ///                is as expected.
    bytes updatedValueProof;
}

library KeystoreLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The slot where the OutputRoot is stored in the `AnchorStateRegistry` L1 contract.
    ///
    /// @dev This is computed as keccak256(abi.encodePacked(bytes32(0), bytes32(uint256(1)))). This slot corresponds
    ///      to calling `anchors(0)` on the `AnchorStateRegistry` contract.
    bytes32 constant ANCHOR_STATE_REGISTRY_SLOT = 0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49;

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

    /// @notice Thrown when the provided OutputRoot preimages do not has to the expected OutputRoot.
    error InvalidL2OutputRootPreimages();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    function verifyNewConfig(
        Config memory currentConfig,
        Config calldata newConfig,
        bytes calldata l1BlockData,
        ControllerProofs calldata controllerProofs
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

        // Authorize the update from the controller.
        require(
            IRecordController(currentConfig.controller).authorize({
                currentConfigData: currentConfig.data,
                newConfigData: newConfig.data,
                l1BlockHeader: l1BlockHeader,
                proof: controllerProofs.updateProof
            }),
            UnauthorizedUpdate()
        );

        // If provided, ensure the updated value proof is valid.
        if (controllerProofs.updatedValueProof.length > 0) {
            require(
                IRecordController(newConfig.controller).authorize({
                    currentConfigData: newConfig.data,
                    newConfigData: newConfig.data,
                    l1BlockHeader: l1BlockHeader,
                    proof: controllerProofs.updatedValueProof
                }),
                UnexpectedUpdate()
            );
        }
    }

    function extractKeystoreConfigHash(
        address anchorStateRegistry,
        address masterKeystore,
        bytes32 configHashSlot,
        KeystoreProof memory keystoreProof
    ) internal view returns (uint256 l1BlockTimestamp, bytes32 configHash) {
        BlockHeader memory header = BlockLib.parseBlockHeader(keystoreProof.l1BlockHeaderRlp);
        l1BlockTimestamp = header.timestamp;

        // Ensure the provided L1 block header can be used (i.e the block hash is valid).
        L1ProofLib.verify({proof: keystoreProof.l1BlockHashProof, expectedL1BlockHash: header.hash});

        // Get the OutputRoot that was submitted to the AnchorStateRegistry contract on L1.
        bytes32 outputRoot = StorageProofLib.extractAccountStorageValue({
            stateRoot: header.stateRoot,
            account: anchorStateRegistry,
            accountProof: keystoreProof.anchorStateRegistryAccountProof,
            slot: ANCHOR_STATE_REGISTRY_SLOT,
            storageProof: keystoreProof.anchorStateRegistryStorageProof
        });

        // Ensure the provided preimages of the `outputRoot` are valid.
        _validateOutputRootPreimages({
            l2StateRoot: keystoreProof.l2StateRoot,
            l2MessagePasserStorageRoot: keystoreProof.l2MessagePasserStorageRoot,
            l2BlockHash: keystoreProof.l2BlockHash,
            outputRoot: outputRoot
        });

        // From the master L2 state root, extract the `MasterKeystore` storage root.
        bytes32 masterKeystoreStorageRoot = StorageProofLib.extractAccountStorageRoot({
            stateRoot: keystoreProof.l2StateRoot,
            account: masterKeystore,
            accountProof: keystoreProof.masterKeystoreAccountProof
        });

        // From the `MasterKeystore` storage root, extract the config hash at the computed `recordSlot`.
        configHash = StorageProofLib.extractSlotValue({
            storageRoot: masterKeystoreStorageRoot,
            slot: keccak256(abi.encodePacked(configHashSlot)),
            storageProof: keystoreProof.masterKeystoreRecordStorageProof
        });
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures the proof's preimages values correctly hash to the expected `outputRoot`.
    ///
    /// @dev Reverts if the proof's preimages values do not hash to the expected `outputRoot`.
    ///
    /// @param l2StateRoot The L2 state root.
    /// @param l2MessagePasserStorageRoot The storage root of the `MessagePasser` contract on the L2.
    /// @param l2BlockHash The block hash of the L2.
    /// @param outputRoot The outputRoot to validate.
    function _validateOutputRootPreimages(
        bytes32 l2StateRoot,
        bytes32 l2MessagePasserStorageRoot,
        bytes32 l2BlockHash,
        bytes32 outputRoot
    ) private pure {
        bytes32 version = bytes32(0);
        bytes32 recomputedOutputRoot =
            keccak256(abi.encodePacked(version, l2StateRoot, l2MessagePasserStorageRoot, l2BlockHash));

        require(recomputedOutputRoot == outputRoot, InvalidL2OutputRootPreimages());
    }
}
