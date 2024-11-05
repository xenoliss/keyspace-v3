// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockHeader, IRecordController} from "../interfaces/IRecordController.sol";

import {BlockLib} from "./BlockLib.sol";
import {L1BlockHashProof, L1ProofLib} from "./L1ProofLib.sol";
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

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Authorizes a Keystore record update.
    ///
    /// @dev Reverts if the authorization fails.
    ///
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
                    currentValue: newValueHashPreimages.data,
                    newValueHash: newValueHash,
                    l1BlockHeader: l1BlockHeader,
                    proof: controllerProofs.updatedValueProof
                }),
                UnexpectedUpdate()
            );
        }
    }
}
