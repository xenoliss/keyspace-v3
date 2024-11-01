// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {ControllerProofs, KeystoreLib, KeystoreRecordProof, TimestampedValueHash} from "./libs/KeystoreLib.sol";
import {ValueHashLib, ValueHashPreimages} from "./libs/ValueHashLib.sol";

import {MasterKeystore} from "./MasterKeystore.sol";

contract KeystoreReplica {
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

    /// @notice The active fork for each Keystore identifier.
    ///
    /// @dev Preconfirmations are organized into "forks," which are sequences of successive ValueHashes set for a
    ///      given Keystore record. A new fork is created if a conflict arises between the active fork and the confirmed
    ///      ValueHash (proved from the `MasterKeystore` contract). The active fork for any Keystore record is always
    ///      the most recent one created.
    /// @dev This MUST be keyed by account to fulfill the ERC-4337 validation phase storage rules.
    mapping(address account => mapping(bytes32 id => uint256 activeForkId)) private _activeForkIds;

    /// @notice Preconfirmed Keystore records per fork.
    ///
    /// @dev This MUST be keyed by account to fulfill the ERC-4337 validation phase storage rules.
    mapping(address account => mapping(bytes32 id => mapping(uint256 forkId => bytes32[] valueHashes))) private
        _preconfirmedRecords;

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
        // On the master chain, the KeystoreReplica is just a passthrough.
        if (block.chainid == masterChainId) {
            currentValueHash = MasterKeystore(masterKeystore).records({account: account, id: id});
            return (currentValueHash, confirmedValueHashTimestamp);
        }

        // Read the currently confirmed ValueHash from storage.
        TimestampedValueHash memory currentConfirmedValueHash = _confirmedRecords[account][id];
        require(currentConfirmedValueHash.valueHash != 0, "RecordNotConfirmed");

        // Select the active fork.
        uint256 activeForkId = _activeForkIds[account][id];
        bytes32[] storage activeFork = _preconfirmedRecords[account][id][activeForkId];

        // Set the current ValueHash to be the latest from the active fork.
        // NOTE: Because there is a non zero confirmed ValueHashm then the active fork is guaranteed to be non empty.
        currentValueHash = activeFork[activeFork.length - 1];

        // Set the confirmed ValueHash timestamp.
        confirmedValueHashTimestamp = currentConfirmedValueHash.timestamp;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Confirms a Keystore ValueHash from the `MasterKeystore`.
    ///
    /// @dev Confirming a record registers the confirmed ValueHash along with its L1 block timestamp.
    ///      It also guarantees that the Keystore record has a non empty, coherent, active fork.
    ///
    /// @param account The account address.
    /// @param id The identifier for the Keystore record.
    /// @param confirmedValueHashIndex The index of the confirmed ValueHash within the Keystore active fork.
    /// @param newConfirmedValueHashPreimages The preimages of the new confirmed ValueHash.
    /// @param currentValueHashPreimages The preimages of the current ValueHash.
    /// @param keystoreRecordProof The Keystore record proof from which to extract the new confirmed ValueHash.
    function confirmRecord(
        address account,
        bytes32 id,
        uint256 confirmedValueHashIndex,
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
        require(newConfirmedValueHash.timestamp > currentConfirmedValueHash.timestamp, "ConfirmedValueHashOutdated");

        // Ensure that the active fork is coherent with the new confirmed ValueHash.
        _ensureActiveForkIsCoherent({
            account: account,
            id: id,
            confirmedValueHashIndex: confirmedValueHashIndex,
            newConfirmedValueHash: newConfirmedValueHash.valueHash,
            newConfirmedValueHashPreimages: newConfirmedValueHashPreimages,
            currentValueHashPreimages: currentValueHashPreimages
        });

        // Finally update the confirmed ValueHash.
        _confirmedRecords[account][id] = newConfirmedValueHash;

        // TODO: Emit event.
    }

    /// @notice Preconfirms an update to a Keystore record.
    ///
    /// @param account The account address.
    /// @param id The identifier for the Keystore record.
    /// @param newValueHash The new ValueHash to store in the Keystore record.
    /// @param confirmedValueHashIndex The index of the confirmed ValueHash within the Keystore active fork.
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
        // Select the active fork.
        uint256 activeForkId = _activeForkIds[account][id];
        bytes32[] storage activeFork = _preconfirmedRecords[account][id][activeForkId];

        // Get the record confirmed ValueHash.
        TimestampedValueHash memory confirmedValueHash = _confirmedRecords[account][id];

        // Use the latest preconfirmed ValueHash as the current one.
        bytes32 valueHashAtIndex = activeFork[confirmedValueHashIndex];
        require(valueHashAtIndex == confirmedValueHash.valueHash, "InvalidConfirmedValueHash");

        // Check if the `newValueHash` update is authorized.
        KeystoreLib.verifyNewValueHash({
            id: id,
            currentValueHash: activeFork[activeFork.length - 1],
            currentValueHashPreimages: currentValueHashPreimages,
            newValueHash: newValueHash,
            newValueHashPreimages: newValueHashPreimages,
            l1BlockData: l1BlockData,
            controllerProofs: controllerProofs
        });

        // Add the `newValueHash` to the active fork.
        activeFork.push(newValueHash);

        // TODO: emit event.
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures that the Keystore active fork is coherent with the provided `newConfirmedValueHash`.
    ///
    /// @dev If the Keystore active fork does not contain `newConfirmedValueHash`, a new fork is created starting with
    ///     `newConfirmedValueHash`.
    ///
    /// @param account The account address.
    /// @param id The identifier for the Keystore record.
    /// @param confirmedValueHashIndex The index of the confirmed ValueHash within the Keystore active fork.
    /// @param newConfirmedValueHash The new confirmed ValueHash.
    /// @param newConfirmedValueHashPreimages The preimages of the new confirmed ValueHash.
    /// @param currentValueHashPreimages The preimages of the current ValueHash.
    function _ensureActiveForkIsCoherent(
        address account,
        bytes32 id,
        uint256 confirmedValueHashIndex,
        bytes32 newConfirmedValueHash,
        ValueHashPreimages calldata newConfirmedValueHashPreimages,
        ValueHashPreimages calldata currentValueHashPreimages
    ) private {
        // Select the active fork.
        uint256 activeForkId = _activeForkIds[account][id];
        bytes32[] storage activeFork = _preconfirmedRecords[account][id][activeForkId];
        uint256 activeForkLen = activeFork.length;

        // If the active fork is empty push the new confirmed ValueHash into it.
        if (activeForkLen == 0) {
            activeFork.push(newConfirmedValueHash);
            return;
        }

        // Otherwise, ensure the active fork contains the new confirmed ValueHash.
        // If it does not create a new fork starting from the new confirmed ValueHash.
        bytes32 currentValueHash = activeFork[activeForkLen - 1];

        // Ensure the ValueHashes preimages are correct.
        ValueHashLib.verify({preimages: currentValueHashPreimages, valueHash: currentValueHash});
        ValueHashLib.verify({preimages: newConfirmedValueHashPreimages, valueHash: newConfirmedValueHash});

        // If the nonce of the new confirmed ValueHash is below the current ValueHash nonce (taken form the
        // active fork), ensure the new confirmed ValueHash is effectively part of the active fork.
        if (newConfirmedValueHashPreimages.nonce < currentValueHashPreimages.nonce) {
            // FIXME
            require(activeFork[confirmedValueHashIndex] == newConfirmedValueHash, "NewConfirmedValueHashNotInFork");
        }
        // Otherwise the nonce of the new confirmed ValueHash is above our current ValueHash nonce so we can
        // simply push the new confirmed ValueHash on top of the active fork.
        else {
            activeFork.push(newConfirmedValueHash);
        }
    }
}
