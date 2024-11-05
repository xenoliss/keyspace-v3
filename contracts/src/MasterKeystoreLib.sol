// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {ControllerProofs, KeystoreLib} from "./libs/KeystoreLib.sol";
import {ValueHashPreimages} from "./libs/ValueHashLib.sol";

/// @dev Storage layout used by the `MasterKeystoreLib`.
///
/// @custom:storage-location erc7201:storage.master-keystore-lib
struct MasterKeystoreLibStorage {
    /// @dev The Keystore record ValueHash.
    bytes32 valueHash;
    /// @dev The matser chain id.
    uint256 masterChainId;
}

library MasterKeystoreLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Slot for the `MasterKeystoreLibStorage` struct in storage.
    ///
    /// @dev Computed as specified in ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201):
    ///      keccak256(abi.encode(uint256(keccak256("storage.master-keystore-lib")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant MASTER_KEYSTORE_LIB_STORAGE_LOCATION =
        0x16b16e97aa7dd148861050ddf021522cc1ad4613a268b28c0c17eaf576635a00;

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
        require(masterChainId != 0, "InvalidMasterChainId");
        require(s().masterChainId == 0, "AlreadyInitialized");

        s().masterChainId = masterChainId;
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
    ) internal onlyOnMasterChain {
        // Read the current ValueHash for the provided Keystore identifier.
        // If none is set, uses the identifier as the current ValueHash.
        bytes32 currentValueHash = s().valueHash;
        if (currentValueHash == 0) {
            currentValueHash = 0;
        }

        // Check if the `newValueHash` update is authorized.
        KeystoreLib.verifyNewValueHash({
            currentValueHash: currentValueHash,
            currentValueHashPreimages: currentValueHashPreimages,
            newValueHash: newValueHash,
            newValueHashPreimages: newValueHashPreimages,
            l1BlockData: l1BlockData,
            controllerProofs: controllerProofs
        });

        s().valueHash = newValueHash;

        emit KeystoreRecordSet(newValueHash);
    }
}
