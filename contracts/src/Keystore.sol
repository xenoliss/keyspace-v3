// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {KeystoreRecordProof, KeystoreReplicaLib} from "./KeystoreReplicaLib.sol";
import {ControllerProofs, MasterKeystoreLib, ValueHashPreimages} from "./MasterKeystoreLib.sol";

abstract contract Keystore {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Initializes the Keystore.
    ///
    /// @param masterChainId The master chain id.
    /// @param anchorStateRegistry The address of the `AnchorStateRegistry` contract on L1.
    function initialize(uint256 masterChainId, address anchorStateRegistry) external {
        MasterKeystoreLib.initialize({masterChainId: masterChainId});
        KeystoreReplicaLib.initialize({anchorStateRegistry: anchorStateRegistry, masterKeystore: address(this)});
    }

    /// @notice Updates a Keystore record to a new ValueHash.
    ///
    /// @param currentValueHashPreimages The preimages of the current ValueHash in the Keystore record.
    /// @param newValueHash The new ValueHash to store in the Keystore record.
    /// @param newValueHashPreimages The preimages of the new ValueHash.
    /// @param l1BlockData OPTIONAL: An L1 block header, RLP-encoded, and a proof of its validity.
    ///                              If present, it is expected to be `abi.encode(l1BlockHeaderRlp, l1BlockHashProof)`.
    ///                              This OPTIONAL L1 block header is meant to be provided to the Keystore record
    ///                              controller `authorize` method to perform authorization based on the L1 state.
    /// @param controllerProofs The `ControllerProofs` struct containing the necessary proofs to authorize the update.
    function set(
        ValueHashPreimages calldata currentValueHashPreimages,
        bytes32 newValueHash,
        ValueHashPreimages calldata newValueHashPreimages,
        bytes calldata l1BlockData,
        ControllerProofs calldata controllerProofs
    ) external {
        MasterKeystoreLib.set({
            currentValueHashPreimages: currentValueHashPreimages,
            newValueHash: newValueHash,
            newValueHashPreimages: newValueHashPreimages,
            l1BlockData: l1BlockData,
            controllerProofs: controllerProofs
        });

        // TODO: Call setRecordValue.
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
    ) external {
        KeystoreReplicaLib.confirmRecord({
            newConfirmedValueHashPreimages: newConfirmedValueHashPreimages,
            currentValueHashPreimages: currentValueHashPreimages,
            keystoreRecordProof: keystoreRecordProof
        });

        // TODO: Call setRecordValue if the history changed.
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
    ) external {
        KeystoreReplicaLib.preconfirmRecord({
            newValueHash: newValueHash,
            confirmedValueHashIndex: confirmedValueHashIndex,
            currentValueHashPreimages: currentValueHashPreimages,
            newValueHashPreimages: newValueHashPreimages,
            l1BlockData: l1BlockData,
            controllerProofs: controllerProofs
        });

        // TODO: Call setRecordValue.
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       INTERNAL FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Parses and writes the record raw value directly in the account storage.
    ///
    /// @param valueHash The record ValueHash.
    /// @param confirmedValueHashTimestamp The corresponding confirmed ValueHash timestamp.
    /// @param value The raw record value.
    function setRecordValue(bytes32 valueHash, uint256 confirmedValueHashTimestamp, bytes memory value)
        internal
        virtual;
}
