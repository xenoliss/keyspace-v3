// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockHeader, IRecordController} from "../interfaces/IRecordController.sol";

import {BlockLib} from "./BlockLib.sol";
import {L1BlockHashProof, L1ProofLib} from "./L1ProofLib.sol";
import {StorageProofLib} from "./StorageProofLib.sol";
import {ValueHashLib, ValueHashPreimages} from "./ValueHashLib.sol";

/// @dev A proof from which a Keystore record ValueHash can be extracted.
struct KeystoreRecordProof {
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

/// @dev A timestamped ValueHash.
struct TimestampedValueHash {
    /// @dev The ValueHash.
    bytes32 valueHash;
    /// @dev The corresponding L1 block timestamp proving this ValueHash.
    uint256 timestamp;
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

    /// @notice Thrown when the provided OutputRoot preimages do not has to the expected OutputRoot.
    error InvalidL2OutputRootPreimages();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The slot where the OutputRoot is stored in the `AnchorStateRegistry` L1 contract.
    ///
    /// @dev This is computed as keccak256(abi.encodePacked(bytes32(0), bytes32(uint256(1)))). This slot corresponds
    ///      to calling `anchors(0)` on the `AnchorStateRegistry` contract.
    bytes32 constant ANCHOR_STATE_REGISTRY_SLOT = 0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49;

    /// @notice The `MasterKeystore` records mapping slot.
    bytes32 constant MASTER_KEYSTORE_RECORDS_SLOT = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Authorizes a Keystore record update.
    ///
    /// @dev Reverts if the authorization fails.
    ///
    /// @param id The identifiee of the Keystore record being updated.
    /// @param currentValueHash The current ValueHash of the Keystore record.
    /// @param currentValueHashPreimages The preimages of the current ValueHash in the Keystore record.
    /// @param newValueHash The new ValueHash to store in the Keystore record.
    /// @param newValueHashPreimages The preimages of the new ValueHash.
    /// @param l1BlockData OPTIONAL: An L1 block header, RLP-encoded, and a proof of its validity.
    ///                              If present, it is expected to be `abi.encode(l1BlockHeaderRlp, l1BlockHashProof)`.
    ///                              This OPTIONAL L1 block header is meant to be provided to the Keystore record
    ///                              controller `authorize` method to perform authorization based on the L1 state.
    /// @param controllerProofs The `ControllerProofs` struct containing the necessary proofs to authorize the update.
    function verifyNewValueHash(
        bytes32 id,
        bytes32 currentValueHash,
        ValueHashPreimages calldata currentValueHashPreimages,
        bytes32 newValueHash,
        ValueHashPreimages calldata newValueHashPreimages,
        bytes calldata l1BlockData,
        ControllerProofs calldata controllerProofs
    ) internal {
        // Ensure that the current and new ValueHash preimages are correct.
        ValueHashLib.verify({preimages: currentValueHashPreimages, valueHash: currentValueHash});
        ValueHashLib.verify({preimages: newValueHashPreimages, valueHash: newValueHash});

        // Ensure the nonce is strictly incrementing.
        require(
            newValueHashPreimages.nonce == currentValueHashPreimages.nonce + 1,
            NonceNotIncrementedByOne({
                currentNonce: currentValueHashPreimages.nonce,
                newNonce: newValueHashPreimages.nonce
            })
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
            IRecordController(currentValueHashPreimages.controller).authorize({
                id: id,
                currentValue: currentValueHashPreimages.data,
                newValueHash: newValueHash,
                l1BlockHeader: l1BlockHeader,
                proof: controllerProofs.updateProof
            }),
            UnauthorizedUpdate()
        );

        // If provided, ensure the updated value proof is valid.
        if (controllerProofs.updatedValueProof.length > 0) {
            require(
                IRecordController(newValueHashPreimages.controller).authorize({
                    id: id,
                    currentValue: newValueHashPreimages.data,
                    newValueHash: newValueHash,
                    l1BlockHeader: l1BlockHeader,
                    proof: controllerProofs.updatedValueProof
                }),
                UnexpectedUpdate()
            );
        }
    }

    /// @notice Extracts a `MasterKeystore` record ValueHash from a given `keystoreRecordProof`.
    ///
    /// @dev The current implementation is compatible only with OpStack chains due to the specifics of the
    ///      `AnchorStateRegistry` contract and how the `l2StateRoot` is proved from the L2 OutputRoot.
    /// @dev The following proving steps are performed to exract a `MasterKeystore` record ValueHash:
    ///      1. Prove the validity of the provided `blockHeaderRlp` against the L1 block hash returned by the
    ///         `l1BlockHashOracle`.
    ///      2. From the L1 state root hash (within the `blockHeaderRlp`), prove the storage root of the
    ///         `AnchorStateRegistry` contract on L1.
    ///      3. From the storage root of the `AnchorStateRegistry`, prove the L2 OutputRoot stored at slot
    ///         `ANCHOR_STATE_REGISTRY_SLOT`. This slot corresponds to calling `anchors(0)` on the `AnchorStateRegistry`
    ///         contract.
    ///      4. From the proved L2 OutputRoot, verify the provided `l2StateRoot`. This is done by recomputing the L2
    ///         OutputRoot using the `l2StateRoot`, `l2MessagePasserStorageRoot`, and `l2BlockHash`
    ///         parameters. For more details, see the link:
    ///         https://github.com/ethereum-optimism/optimism/blob/d141b53e4f52a8eb96a552d46c2e1c6c068b032e/op-service/eth/output.go#L49-L63
    ///      5. From the `l2StateRoot`, prove the `MasterKeystore` storage root.
    ///      6. From the `MasterKeystore` storage root, prove the `MasterKeystore` record ValueHash.
    /// @dev If no ValueHash was set on the `MasterKeystore` the Keystore identifier is
    ///
    /// @param id The identifier for the Keystore record.
    /// @param anchorStateRegistry The AnchorStateRegistry address on L1.
    /// @param masterKeystore The `MasterKeystore` address.
    /// @param keystoreRecordProof The KeystoreRecordProof struct.
    ///
    /// @return timestampedValueHash The extracted Keystore record ValueHash timestamped.
    function extractKeystoreRecordValueHash(
        bytes32 id,
        address anchorStateRegistry,
        address masterKeystore,
        KeystoreRecordProof memory keystoreRecordProof
    ) internal view returns (TimestampedValueHash memory timestampedValueHash) {
        BlockHeader memory header = BlockLib.parseBlockHeader(keystoreRecordProof.l1BlockHeaderRlp);
        timestampedValueHash.timestamp = header.timestamp;

        // Ensure the provided L1 block header can be used (i.e the block hash is valid).
        L1ProofLib.verify({proof: keystoreRecordProof.l1BlockHashProof, expectedL1BlockHash: header.hash});

        // Get the OutputRoot that was submitted to the AnchorStateRegistry contract on L1.
        bytes32 outputRoot = StorageProofLib.extractAccountStorageValue({
            stateRoot: header.stateRoot,
            account: anchorStateRegistry,
            accountProof: keystoreRecordProof.anchorStateRegistryAccountProof,
            slot: ANCHOR_STATE_REGISTRY_SLOT,
            storageProof: keystoreRecordProof.anchorStateRegistryStorageProof
        });

        // Ensure the provided preimages of the `outputRoot` are valid.
        _validateOutputRootPreimages({
            l2StateRoot: keystoreRecordProof.l2StateRoot,
            l2MessagePasserStorageRoot: keystoreRecordProof.l2MessagePasserStorageRoot,
            l2BlockHash: keystoreRecordProof.l2BlockHash,
            outputRoot: outputRoot
        });

        // From the master L2 state root, extract the `MasterKeystore` storage root.
        bytes32 masterKeystoreStorageRoot = StorageProofLib.extractAccountStorageRoot({
            stateRoot: keystoreRecordProof.l2StateRoot,
            account: masterKeystore,
            accountProof: keystoreRecordProof.masterKeystoreAccountProof
        });

        // From the `MasterKeystore` storage root, extract the ValueHash at the computed `recordSlot`.
        bytes memory recordSlot = abi.encode(id, MASTER_KEYSTORE_RECORDS_SLOT);
        timestampedValueHash.valueHash = StorageProofLib.extractSlotValue({
            storageRoot: masterKeystoreStorageRoot,
            slot: keccak256(abi.encodePacked(recordSlot)),
            storageProof: keystoreRecordProof.masterKeystoreRecordStorageProof
        });

        // If no ValueHash was set on the `MasterKeystore` contract, then use the Keystore identifier.
        if (timestampedValueHash.valueHash == 0) {
            timestampedValueHash.valueHash = id;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         PRIVATE FUNCTIONS                                      //
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
