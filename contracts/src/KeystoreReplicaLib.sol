// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockHeader} from "./interfaces/IRecordController.sol";

import {BlockLib} from "./libs/BlockLib.sol";
import {ControllerProofs, KeystoreLib, KeystoreRecordProof, TimestampedValueHash} from "./libs/KeystoreLib.sol";
import {L1ProofLib} from "./libs/L1ProofLib.sol";
import {StorageProofLib} from "./libs/StorageProofLib.sol";
import {ValueHashLib, ValueHashPreimages} from "./libs/ValueHashLib.sol";

import {MasterKeystoreLib} from "./MasterKeystoreLib.sol";

/// @dev Storage layout used by the `KeystoreReplicaLib`.
///
/// @custom:storage-location erc7201:storage.keystore-replica-lib
struct KeystoreReplicaLibStorage {
    /// @dev The address of the `AnchorStateRegistry` contract on L1.
    address anchorStateRegistry;
    /// @dev The address of the `MasterKeystore` contract.
    address masterKeystore;
    /// @dev The confirmed Keystore record ValueHash.
    TimestampedValueHash confirmedValueHash;
    /// @dev Preconfirmed Keystore record ValueHashes history.
    bytes32[] preconfirmedValueHashesHistory;
}

library KeystoreReplicaLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Slot for the `KeystoreReplicaLibStorage` struct in storage.
    ///
    /// @dev Computed as specified in ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201):
    ///      keccak256(abi.encode(uint256(keccak256("storage.keystore-replica-lib")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant KEYSTORE_REPLICA_LIB_STORAGE_LOCATION =
        0xbb2c68d544ae37c54c269beca80439c6209dddaa719ab9fade692ae7ae538800;

    /// @notice The slot where the OutputRoot is stored in the `AnchorStateRegistry` L1 contract.
    ///
    /// @dev This is computed as keccak256(abi.encodePacked(bytes32(0), bytes32(uint256(1)))). This slot corresponds
    ///      to calling `anchors(0)` on the `AnchorStateRegistry` contract.
    bytes32 constant ANCHOR_STATE_REGISTRY_SLOT = 0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when trying to confirm a Keystore record but the extracted confirmed ValueHash from the
    ///         `MasterKeystore` has a confirmation timestamp below the current confirmed ValueHash.
    ///
    /// @param currentConfirmedValueHashTimestamp The current confirmed ValueHash timestamp.
    /// @param newConfirmedValueHashTimestamp The new confirmed ValueHash timestamp.
    error ConfirmedValueHashOutdated(uint256 currentConfirmedValueHashTimestamp, uint256 newConfirmedValueHashTimestamp);

    /// @notice Thrown when trying to preconfirm a Keystore record update but the confirmed ValueHash was not found at
    ///         the provided lookup index.
    ///
    /// @param index The index where the confirmed ValueHash was expeted in the Keystore history.
    /// @param valueHashAtIndex The ValueHash found at the `index` in the Keystore history.
    /// @param confirmedValueHash The expected confirmed ValueHash.
    error ConfirmedValueHashNotFound(uint256 index, bytes32 valueHashAtIndex, bytes32 confirmedValueHash);

    /// @notice Thrown when the provided OutputRoot preimages do not has to the expected OutputRoot.
    error InvalidL2OutputRootPreimages();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              EVENTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Emitted when a Keystore record is confirmed.
    ///
    /// @param confirmedValueHash The confirmed record ValueHash.
    event RecordConfirmed(bytes32 indexed confirmedValueHash);

    /// @notice Emitted when a Keystore record is preconfirmed.
    ///
    /// @param newValueHash The preconfirmed new record ValueHash.
    event RecordPreconfirmed(bytes32 indexed newValueHash);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       INTERNAL FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Helper function to get a storage reference to the `KeystoreReplicaLibStorage` struct.
    ///
    /// @return $ A storage reference to the `KeystoreReplicaLibStorage` struct.
    function s() internal pure returns (KeystoreReplicaLibStorage storage $) {
        bytes32 position = KEYSTORE_REPLICA_LIB_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := position
        }
    }

    /// @notice Initializes the `KeystoreReplicaLib` storage.
    ///
    /// @param anchorStateRegistry The address of the `AnchorStateRegistry` contract on L1.
    /// @param masterKeystore The address of the `MasterKeystore` contract.
    function initialize(address anchorStateRegistry, address masterKeystore) internal {
        require(anchorStateRegistry != address(0), "InvalidAnchorStateRegistryAddress");
        require(masterKeystore != address(0), "InvaliMasterKeystoreAddress");
        require(s().anchorStateRegistry == address(0), "AlreadyInitialized");

        s().anchorStateRegistry = anchorStateRegistry;
        s().masterKeystore = masterKeystore;
    }

    /// @notice Confirms a Keystore ValueHash from the `MasterKeystore`.
    ///
    /// @dev Confirming a record registers the confirmed ValueHash along with its L1 block timestamp.
    ///      It also guarantees that the Keystore record has a non empty and coherent history.
    ///
    /// @param newConfirmedValueHashPreimages The preimages of the new confirmed ValueHash.
    /// @param currentValueHashPreimages The preimages of the current ValueHash.
    /// @param keystoreRecordProof The Keystore record proof from which to extract the new confirmed ValueHash.
    function confirmRecord(
        ValueHashPreimages calldata newConfirmedValueHashPreimages,
        ValueHashPreimages calldata currentValueHashPreimages,
        KeystoreRecordProof calldata keystoreRecordProof
    ) internal {
        // Read the currently confirmed ValueHash from storage.
        TimestampedValueHash memory currentConfirmedValueHash = s().confirmedValueHash;

        // Extract the new confirmed ValueHash from the provided `keystoreRecordProof`.
        TimestampedValueHash memory newConfirmedValueHash = _extractKeystoreRecordValueHash({
            anchorStateRegistry: s().anchorStateRegistry,
            masterKeystore: s().masterKeystore,
            valueHashSlot: MasterKeystoreLib.MASTER_KEYSTORE_LIB_STORAGE_LOCATION,
            keystoreRecordProof: keystoreRecordProof
        });

        // Ensure we are going forward when proving the new confirmed ValueHash.
        require(
            newConfirmedValueHash.timestamp > currentConfirmedValueHash.timestamp,
            ConfirmedValueHashOutdated({
                currentConfirmedValueHashTimestamp: currentConfirmedValueHash.timestamp,
                newConfirmedValueHashTimestamp: newConfirmedValueHash.timestamp
            })
        );

        // Ensure that the active history is coherent with the new confirmed ValueHash.
        _ensureHistoryIsCoherent({
            newConfirmedValueHash: newConfirmedValueHash.valueHash,
            newConfirmedValueHashPreimages: newConfirmedValueHashPreimages,
            currentValueHashPreimages: currentValueHashPreimages
        });

        // Finally update the confirmed ValueHash.
        s().confirmedValueHash = newConfirmedValueHash;

        emit RecordConfirmed(newConfirmedValueHash.valueHash);
    }

    /// @notice Preconfirms an update to a Keystore record.
    ///
    /// @param newValueHash The new ValueHash to store in the Keystore record.
    /// @param confirmedValueHashIndex The index of the confirmed ValueHash within the Keystore history.
    /// @param currentValueHashPreimages The current ValueHash preimages.
    /// @param newValueHashPreimages The new ValueHash preimages.
    /// @param l1BlockData OPTIONAL: An L1 block header, RLP-encoded, and a proof of its validity.
    ///                              If present, it is expected to be `abi.encode(l1BlockHeaderRlp, l1BlockHashProof)`.
    ///                              This OPTIONAL L1 block header is meant to be provided to the Keystore record
    ///                              controller `authorize` method to perform authorization based on the L1 state.
    /// @param controllerProofs The `ControllerProofs` struct containing the necessary proofs to authorize the update.
    function preconfirmRecord(
        bytes32 newValueHash,
        uint256 confirmedValueHashIndex,
        ValueHashPreimages calldata currentValueHashPreimages,
        ValueHashPreimages calldata newValueHashPreimages,
        bytes calldata l1BlockData,
        ControllerProofs calldata controllerProofs
    ) internal {
        // Get a storage reference to the ValueHashes history.
        bytes32[] storage history = s().preconfirmedValueHashesHistory;

        // Get the record confirmed ValueHash.
        TimestampedValueHash memory confirmedValueHash = s().confirmedValueHash;

        // Use the latest preconfirmed ValueHash as the current one.
        bytes32 valueHashAtIndex = history[confirmedValueHashIndex];
        require(
            valueHashAtIndex == confirmedValueHash.valueHash,
            ConfirmedValueHashNotFound({
                index: confirmedValueHashIndex,
                valueHashAtIndex: valueHashAtIndex,
                confirmedValueHash: confirmedValueHash.valueHash
            })
        );

        // Check if the `newValueHash` update is authorized.
        KeystoreLib.verifyNewValueHash({
            currentValueHash: history[history.length - 1],
            currentValueHashPreimages: currentValueHashPreimages,
            newValueHash: newValueHash,
            newValueHashPreimages: newValueHashPreimages,
            l1BlockData: l1BlockData,
            controllerProofs: controllerProofs
        });

        // Add the `newValueHash` to the history.
        history.push(newValueHash);

        emit RecordPreconfirmed(newValueHash);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

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
    ///
    /// @param anchorStateRegistry The AnchorStateRegistry address on L1.
    /// @param masterKeystore The `MasterKeystore` address.
    /// @param valueHashSlot The storage slot where the record ValueHash is stored.
    /// @param keystoreRecordProof The KeystoreRecordProof struct.
    ///
    /// @return timestampedValueHash The extracted Keystore record ValueHash timestamped.
    function _extractKeystoreRecordValueHash(
        address anchorStateRegistry,
        address masterKeystore,
        bytes32 valueHashSlot,
        KeystoreRecordProof memory keystoreRecordProof
    ) private view returns (TimestampedValueHash memory timestampedValueHash) {
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
        timestampedValueHash.valueHash = StorageProofLib.extractSlotValue({
            storageRoot: masterKeystoreStorageRoot,
            slot: keccak256(abi.encodePacked(valueHashSlot)),
            storageProof: keystoreRecordProof.masterKeystoreRecordStorageProof
        });
    }

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

    /// @notice Ensures that the Keystore history is coherent with the provided `newConfirmedValueHash`.
    ///
    /// @dev If the Keystore history does not contain `newConfirmedValueHash`, it is reseted and initialized with the
    ///      provided `newConfirmedValueHash`.
    ///
    /// @param newConfirmedValueHash The new confirmed ValueHash.
    /// @param newConfirmedValueHashPreimages The preimages of the new confirmed ValueHash.
    /// @param currentValueHashPreimages The preimages of the current ValueHash.
    function _ensureHistoryIsCoherent(
        bytes32 newConfirmedValueHash,
        ValueHashPreimages calldata newConfirmedValueHashPreimages,
        ValueHashPreimages calldata currentValueHashPreimages
    ) private {
        // Get a storage reference to the Keystore history.
        bytes32[] storage history = s().preconfirmedValueHashesHistory;

        // If the history is empty, push the new confirmed ValueHash into it.
        uint256 historyLen = history.length;
        if (historyLen == 0) {
            history.push(newConfirmedValueHash);
            return;
        }

        // Ensure the ValueHashes preimages are correct.
        bytes32 currentValueHash = history[historyLen - 1];
        ValueHashLib.verify({preimages: currentValueHashPreimages, valueHash: currentValueHash});
        ValueHashLib.verify({preimages: newConfirmedValueHashPreimages, valueHash: newConfirmedValueHash});

        // If the new confirmed ValueHash has a nonce above our current ValueHash, reset the history.
        if (newConfirmedValueHashPreimages.nonce > currentValueHashPreimages.nonce) {
            _resetHistory({confirmedValueHash: newConfirmedValueHash});
        }
        // Otherwise, the history MUST already contain the new confirmed ValueHash. If it does not, reset it.
        else {
            // Using the nonce difference, compute the index where the confirmed ValueHash should appear in the
            // Keystore history.
            // NOTE: This is possible because, within a Keystore history, each ValueHash nonce strictly increments by
            //       one from the previous ValueHash nonce.
            uint256 nonceDiff = currentValueHashPreimages.nonce - newConfirmedValueHashPreimages.nonce;
            uint256 confirmedValueHashIndex = historyLen - 1 - nonceDiff;

            // If the confirmed ValueHash is not found at that index, reset the history.
            if (history[confirmedValueHashIndex] != newConfirmedValueHash) {
                _resetHistory({confirmedValueHash: newConfirmedValueHash});
            }
        }
    }

    /// @notice Resets a Keystore record history and initializes it with provided `confirmedValueHash`.
    ///
    /// @param confirmedValueHash The confirmed ValueHash to start form.
    function _resetHistory(bytes32 confirmedValueHash) private {
        delete s().preconfirmedValueHashesHistory;
        s().preconfirmedValueHashesHistory.push(confirmedValueHash);
    }
}
