// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {ControllerProofs, KeystoreLib} from "./libs/KeystoreLib.sol";
import {ValueHashPreimages} from "./libs/ValueHashLib.sol";

// TODO: Use ERC-7201
struct MasterKeystoreLibStorage {
    /// @notice The matser chain id.
    uint256 masterChainId;
    /// @notice The Keystore record.
    bytes32 record;
}

library MasterKeystoreLib {
    // TODO: Use ERC-7201
    bytes32 constant MASTER_KEYSTORE_LIB_STORAGE_LOCATION = keccak256("master-keystore-lib.storage");

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              EVENTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Emitted when a Keystore record is updated.
    ///
    /// @param newValueHash The new ValueHash stored in the record.
    event KeystoreRecordSet(bytes32 indexed newValueHash);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           MODIFIERS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures the call is performed on the master chain.
    modifier onlyOnMasterChain() {
        require(block.chainid == s().masterChainId, "NotOnMasterChain");
        _;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       INTERNAL FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Helper function to get a storage reference to the `MasterKeystoreLibStorage` struct.
    ///
    /// @return $ A storage reference to the `MasterKeystoreLibStorage` struct.
    function s() internal pure returns (MasterKeystoreLibStorage storage $) {
        bytes32 position = MASTER_KEYSTORE_LIB_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := position
        }
    }

    /// @notice Initializes the `MasterKeystoreLib` storage.
    ///
    /// @param masterChainId The master chain id.
    function initialize(uint256 masterChainId) internal {
        s().masterChainId = masterChainId;
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
    ) internal onlyOnMasterChain {
        // Read the current ValueHash for the provided Keystore identifier.
        // If none is set, uses the identifier as the current ValueHash.
        bytes32 currentValueHash = s().record;
        if (currentValueHash == 0) {
            currentValueHash = id;
        }

        // Check if the `newValueHash` update is authorized.
        KeystoreLib.verifyNewValueHash({
            id: id,
            currentValueHash: currentValueHash,
            currentValueHashPreimages: currentValueHashPreimages,
            newValueHash: newValueHash,
            newValueHashPreimages: newValueHashPreimages,
            l1BlockData: l1BlockData,
            controllerProofs: controllerProofs
        });

        s().record = newValueHash;

        emit KeystoreRecordSet(newValueHash);
    }
}
