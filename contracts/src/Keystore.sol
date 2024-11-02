// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {KeystoreRecordProof, KeystoreReplicaLib} from "./KeystoreReplicaLib.sol";
import {ControllerProofs, MasterKeystoreLib, ValueHashPreimages} from "./MasterKeystoreLib.sol";

abstract contract Keystore {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         VIEW FUNCTIONS                                         //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Returns the current ValueHash for the provided Keystore identifier.
    ///
    ///
    /// @return currentValueHash The current Keystore record ValueHash.
    /// @return confirmedValueHashTimestamp The corresponding confirmed ValueHash timestamp.
    function record() external view returns (bytes32 currentValueHash, uint256 confirmedValueHashTimestamp) {
        // If on the master chain directly read the record.
        if (block.chainid == MasterKeystoreLib.s().masterChainId) {
            // TODO: Should we return a specific flag instead of 0?
            return (MasterKeystoreLib.s().record, 0);
        }

        // Otherwise, returns the latest preconfirmed record.
        return KeystoreReplicaLib.record();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Initializes the Keystore.
    ///
    /// @param anchorStateRegistry The address of the `AnchorStateRegistry` contract on L1.
    /// @param masterChainId The master chain id.
    function initialize(address anchorStateRegistry, uint256 masterChainId) external {
        // TODO: Proper initializer.

        require(anchorStateRegistry != address(0), "InvalidAnchorStateRegistryAddress");
        require(masterChainId != 0, "InvalidMasterChainId");
        require(MasterKeystoreLib.s().masterChainId == 0, "AlreadyInitialized");

        MasterKeystoreLib.initialize({masterChainId: masterChainId});
        KeystoreReplicaLib.initialize({anchorStateRegistry: anchorStateRegistry, masterKeystore: address(this)});
    }

    /// @notice Updates a Keystore record to a new ValueHash.
    ///
    /// @param id The identifier of the Keystore record to update.
    /// @param currentValueHashPreimages The preimages of the current ValueHash in the Keystore record.
    /// @param newValueHash The new ValueHash to store in the Keystore record.
    /// @param newValueHashPreimages The preimages of the new ValueHash.
    /// @param l1BlockData OPTIONAL: An L1 block header, RLP-encoded, and a proof of its validity.
    ///                              If present, it is expected to be `abi.encode(l1BlockHeaderRlp, l1BlockHashProof)`.
    ///                              This OPTIONAL L1 block header is meant to be provided to the Keystore record
    ///                              controller `authorize` method to perform authorization based on the L1 state.
    /// @param controllerProofs The `ControllerProofs` struct containing the necessary proofs to authorize the update.
    function set(
        bytes32 id,
        ValueHashPreimages calldata currentValueHashPreimages,
        bytes32 newValueHash,
        ValueHashPreimages calldata newValueHashPreimages,
        bytes calldata l1BlockData,
        ControllerProofs calldata controllerProofs
    ) external {
        MasterKeystoreLib.set({
            id: id,
            currentValueHashPreimages: currentValueHashPreimages,
            newValueHash: newValueHash,
            newValueHashPreimages: newValueHashPreimages,
            l1BlockData: l1BlockData,
            controllerProofs: controllerProofs
        });
    }

    /// @notice Confirms a Keystore ValueHash from the `MasterKeystore`.
    ///
    /// @dev Confirming a record registers the confirmed ValueHash along with its L1 block timestamp.
    ///      It also guarantees that the Keystore record has a non empty and coherent history.
    ///
    /// @param id The identifier for the Keystore record.
    /// @param newConfirmedValueHashPreimages The preimages of the new confirmed ValueHash.
    /// @param currentValueHashPreimages The preimages of the current ValueHash.
    /// @param keystoreRecordProof The Keystore record proof from which to extract the new confirmed ValueHash.
    function confirmRecord(
        bytes32 id,
        ValueHashPreimages calldata newConfirmedValueHashPreimages,
        ValueHashPreimages calldata currentValueHashPreimages,
        KeystoreRecordProof calldata keystoreRecordProof
    ) external {
        KeystoreReplicaLib.confirmRecord({
            id: id,
            newConfirmedValueHashPreimages: newConfirmedValueHashPreimages,
            currentValueHashPreimages: currentValueHashPreimages,
            keystoreRecordProof: keystoreRecordProof
        });
    }

    /// @notice Preconfirms an update to a Keystore record.
    ///
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
        bytes32 id,
        bytes32 newValueHash,
        uint256 confirmedValueHashIndex,
        ValueHashPreimages calldata currentValueHashPreimages,
        ValueHashPreimages calldata newValueHashPreimages,
        bytes calldata l1BlockData,
        ControllerProofs calldata controllerProofs
    ) external {
        KeystoreReplicaLib.preconfirmRecord({
            id: id,
            newValueHash: newValueHash,
            confirmedValueHashIndex: confirmedValueHashIndex,
            currentValueHashPreimages: currentValueHashPreimages,
            newValueHashPreimages: newValueHashPreimages,
            l1BlockData: l1BlockData,
            controllerProofs: controllerProofs
        });
    }
}
