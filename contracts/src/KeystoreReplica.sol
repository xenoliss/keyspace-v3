// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {ControllerProofs, KeystoreLib, KeystoreRecordProof, TimestampedValueHash} from "./libs/KeystoreLib.sol";
import {ValueHashLib, ValueHashPreimages} from "./libs/ValueHashLib.sol";

import {MasterKeystore} from "./MasterKeystore.sol";

contract KeystoreReplica {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when trying to read a Keystore record that has never been confirmed.
    ///
    /// @param id The Keystore identifier.
    error RecordNotConfirmed(bytes32 id);

    /// @notice Thrown when trying to confirm a Keystore record but the extracted confirmed ValueHash from the
    ///         `MasterKeystore` has a confirmation timestamp below the current confirmed ValueHash.
    ///
    /// @param id The Keystore identifier.
    /// @param currentConfirmedValueHashTimestamp The current confirmed ValueHash timestamp.
    /// @param newConfirmedValueHashTimestamp The new confirmed ValueHash timestamp.
    error ConfirmedValueHashOutdated(
        bytes32 id, uint256 currentConfirmedValueHashTimestamp, uint256 newConfirmedValueHashTimestamp
    );

    /// @notice Thrown when trying to preconfirm a Keystore record update but the confirmed ValueHash was not found at
    ///         the provided lookup index.
    ///
    /// @param id The Keystore identifier.
    /// @param index The index where the confirmed ValueHash was expeted in the Keystore history.
    /// @param valueHashAtIndex The ValueHash found at the `index` in the Keystore history.
    /// @param confirmedValueHash The expected confirmed ValueHash.
    error ConfirmedValueHashNotFound(bytes32 id, uint256 index, bytes32 valueHashAtIndex, bytes32 confirmedValueHash);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              EVENTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Emitted when a Keystore record is confirmed.
    ///
    /// @param account The account address.
    /// @param id The Keystore identifier.
    /// @param confirmedValueHash The confirmed ValueHash.
    event RecordConfirmed(address indexed account, bytes32 indexed id, bytes32 indexed confirmedValueHash);

    /// @notice Emitted when a Keystore record is preconfirmed.
    ///
    /// @param account The account address.
    /// @param id The Keystore identifier.
    /// @param newValueHash The preconfirmed new ValueHash.
    event RecordPreconfirmed(address indexed account, bytes32 indexed id, bytes32 indexed newValueHash);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The address of the `AnchorStateRegistry` contract on L1.
    address public immutable anchorStateRegistry;

    /// @notice The address of the `MasterKeystore` contract.
    address public immutable masterKeystore;

    /// @notice The matser chain id.
    uint256 public immutable masterChainId;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STORAGE                                             //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The confirmed Keystore records.
    ///
    /// @dev This MUST be keyed by account to fulfill the ERC-4337 validation phase storage rules.
    mapping(address account => mapping(bytes32 id => TimestampedValueHash timestampedValueHash)) private
        _confirmedRecords;

    /// @notice Preconfirmed Keystore records per Keystore identifier.
    ///
    /// @dev This MUST be keyed by account to fulfill the ERC-4337 validation phase storage rules.
    mapping(address account => mapping(bytes32 id => bytes32[] valueHashes)) private _preconfirmedRecords;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          CONSTRUCTOR                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Deploys a `KeystoreReplica` contract.
    ///
    /// @param anchorStateRegistry_ The address of the `AnchorStateRegistry` contract on L1.
    /// @param masterKeystore_ The address of the `MasterKeystore` contract.
    /// @param masterChainId_ The master chain id.
    constructor(address anchorStateRegistry_, address masterKeystore_, uint256 masterChainId_) {
        anchorStateRegistry = anchorStateRegistry_;
        masterKeystore = masterKeystore_;
        masterChainId = masterChainId_;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          VIEW FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Returns the current ValueHash for the provided Keystore identifier.
    ///
    /// @param account The account address.
    /// @param id The Keystore identifier.
    ///
    /// @return currentValueHash The current Keystore record ValueHash.
    /// @return confirmedValueHashTimestamp The corresponding confirmed ValueHash timestamp.
    function records(address account, bytes32 id)
        external
        view
        returns (bytes32 currentValueHash, uint256 confirmedValueHashTimestamp)
    {
        // On the master chain, the `KeystoreReplica` is just a passthrough.
        if (block.chainid == masterChainId) {
            currentValueHash = MasterKeystore(masterKeystore).records({account: account, id: id});
            return (currentValueHash, confirmedValueHashTimestamp);
        }

        // Read the currently confirmed ValueHash from storage.
        TimestampedValueHash memory currentConfirmedValueHash = _confirmedRecords[account][id];
        require(currentConfirmedValueHash.valueHash != 0, RecordNotConfirmed({id: id}));

        // Set the current ValueHash to be the latest in its history.
        // NOTE: Because there is a non zero confirmed ValueHash then the history is guaranteed to be non empty.
        bytes32[] storage history = _preconfirmedRecords[account][id];
        currentValueHash = history[history.length - 1];

        // Set the confirmed ValueHash timestamp.
        confirmedValueHashTimestamp = currentConfirmedValueHash.timestamp;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Confirms a Keystore ValueHash from the `MasterKeystore`.
    ///
    /// @dev Confirming a record registers the confirmed ValueHash along with its L1 block timestamp.
    ///      It also guarantees that the Keystore record has a non empty and coherent history.
    ///
    /// @param account The account address.
    /// @param id The identifier for the Keystore record.
    /// @param newConfirmedValueHashPreimages The preimages of the new confirmed ValueHash.
    /// @param currentValueHashPreimages The preimages of the current ValueHash.
    /// @param keystoreRecordProof The Keystore record proof from which to extract the new confirmed ValueHash.
    function confirmRecord(
        address account,
        bytes32 id,
        ValueHashPreimages calldata newConfirmedValueHashPreimages,
        ValueHashPreimages calldata currentValueHashPreimages,
        KeystoreRecordProof calldata keystoreRecordProof
    ) external {
        // Read the currently confirmed ValueHash from storage.
        TimestampedValueHash memory currentConfirmedValueHash = _confirmedRecords[account][id];

        // Extract the new confirmed ValueHash from the provided `keystoreRecordProof`.
        TimestampedValueHash memory newConfirmedValueHash = KeystoreLib.extractKeystoreRecordValueHash({
            id: id,
            anchorStateRegistry: anchorStateRegistry,
            masterKeystore: masterKeystore,
            keystoreRecordProof: keystoreRecordProof
        });

        // Ensure we are going forward when proving the new confirmed ValueHash.
        require(
            newConfirmedValueHash.timestamp > currentConfirmedValueHash.timestamp,
            ConfirmedValueHashOutdated({
                id: id,
                currentConfirmedValueHashTimestamp: currentConfirmedValueHash.timestamp,
                newConfirmedValueHashTimestamp: newConfirmedValueHash.timestamp
            })
        );

        // Ensure that the active history is coherent with the new confirmed ValueHash.
        _ensureHistoryIsCoherent({
            account: account,
            id: id,
            newConfirmedValueHash: newConfirmedValueHash.valueHash,
            newConfirmedValueHashPreimages: newConfirmedValueHashPreimages,
            currentValueHashPreimages: currentValueHashPreimages
        });

        // Finally update the confirmed ValueHash.
        _confirmedRecords[account][id] = newConfirmedValueHash;

        emit RecordConfirmed({account: account, id: id, confirmedValueHash: newConfirmedValueHash.valueHash});
    }

    /// @notice Preconfirms an update to a Keystore record.
    ///
    /// @param account The account address.
    /// @param id The identifier for the Keystore record.
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
        address account,
        bytes32 id,
        bytes32 newValueHash,
        uint256 confirmedValueHashIndex,
        ValueHashPreimages calldata currentValueHashPreimages,
        ValueHashPreimages calldata newValueHashPreimages,
        bytes calldata l1BlockData,
        ControllerProofs calldata controllerProofs
    ) external {
        // Get a storage reference to the Keystore history.
        bytes32[] storage history = _preconfirmedRecords[account][id];

        // Get the record confirmed ValueHash.
        TimestampedValueHash memory confirmedValueHash = _confirmedRecords[account][id];

        // Use the latest preconfirmed ValueHash as the current one.
        bytes32 valueHashAtIndex = history[confirmedValueHashIndex];
        require(
            valueHashAtIndex == confirmedValueHash.valueHash,
            ConfirmedValueHashNotFound({
                id: id,
                index: confirmedValueHashIndex,
                valueHashAtIndex: valueHashAtIndex,
                confirmedValueHash: confirmedValueHash.valueHash
            })
        );

        // Check if the `newValueHash` update is authorized.
        KeystoreLib.verifyNewValueHash({
            id: id,
            currentValueHash: history[history.length - 1],
            currentValueHashPreimages: currentValueHashPreimages,
            newValueHash: newValueHash,
            newValueHashPreimages: newValueHashPreimages,
            l1BlockData: l1BlockData,
            controllerProofs: controllerProofs
        });

        // Add the `newValueHash` to the history.
        history.push(newValueHash);

        emit RecordPreconfirmed({account: account, id: id, newValueHash: newValueHash});
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures that the Keystore history is coherent with the provided `newConfirmedValueHash`.
    ///
    /// @dev If the Keystore history does not contain `newConfirmedValueHash`, it is reseted and initialized with the
    ///      provided `newConfirmedValueHash`.
    ///
    /// @param account The account address.
    /// @param id The identifier for the Keystore record.
    /// @param newConfirmedValueHash The new confirmed ValueHash.
    /// @param newConfirmedValueHashPreimages The preimages of the new confirmed ValueHash.
    /// @param currentValueHashPreimages The preimages of the current ValueHash.
    function _ensureHistoryIsCoherent(
        address account,
        bytes32 id,
        bytes32 newConfirmedValueHash,
        ValueHashPreimages calldata newConfirmedValueHashPreimages,
        ValueHashPreimages calldata currentValueHashPreimages
    ) private {
        // Get a storage reference to the Keystore history.
        bytes32[] storage history = _preconfirmedRecords[account][id];

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
            _resetHistory({account: account, id: id, confirmedValueHash: newConfirmedValueHash});
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
                _resetHistory({account: account, id: id, confirmedValueHash: newConfirmedValueHash});
            }
        }
    }

    /// @notice Resets a Keystore record history and initializes it with provided `confirmedValueHash`.
    ///
    /// @param account The account address.
    /// @param id The identifier for the Keystore record.
    /// @param confirmedValueHash The confirmed ValueHash to start form.
    function _resetHistory(address account, bytes32 id, bytes32 confirmedValueHash) private {
        delete _preconfirmedRecords[account][id];
        _preconfirmedRecords[account][id].push(confirmedValueHash);
    }
}
