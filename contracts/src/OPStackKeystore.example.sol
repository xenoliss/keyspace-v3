// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockHeader} from "./libs/BlockLib.sol";
import {StorageProofLib} from "./libs/StorageProofLib.sol";

import {Keystore} from "./Keystore.sol";

/// @dev OPStack specfic proof used to verify a master L2 state root.
struct OPStrackProof {
    /// @dev The `AnchorStateRegistry` account proof on L1.
    bytes[] anchorStateRegistryAccountProof;
    /// @dev The storage proof of the master L2 OutputRoot stored in the `AnchorStateRegistry` contract on L1.
    bytes[] anchorStateRegistryStorageProof;
    /// @dev The storage root of the `MessagePasser` contract on the master L2.
    bytes32 l2MessagePasserStorageRoot;
    /// @dev The block hash of the master L2.
    bytes32 l2BlockHash;
}

contract OPStackKeystore is Keystore {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The AnchorStateRegistry contract address on L1 used to prove L2 state roots.
    address constant ANCHOR_STATE_REGISTRY_ADDR = 0x4C8BA32A5DAC2A720bb35CeDB51D6B067D104205;

    /// @notice The slot where the OutputRoot is stored in the `AnchorStateRegistry` L1 contract.
    ///
    /// @dev This is computed as keccak256(abi.encodePacked(bytes32(0), bytes32(uint256(1)))). This slot corresponds
    ///      to calling `anchors(0)` on the `AnchorStateRegistry` contract.
    bytes32 constant ANCHOR_STATE_REGISTRY_SLOT = 0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the provided OutputRoot preimages do not has to the expected OutputRoot.
    error InvalidL2OutputRootPreimages();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          CONSTRUCTOR                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    constructor(uint256 masterChainId) Keystore(masterChainId) {}

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       INTERNAL FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Hook called whenever a new Keystore config is defined as the current one.
    ///
    /// @dev On the master chain this is called whenever `setConfig` succeeds.
    ///      On replica chains this is called:
    ///         - whenever a preconfirmation succeeds
    ///         - when confirming a new config if the preconfirmed configs list was reseted
    ///
    /// @param configHash The config hash.
    /// @param configData The raw config data.
    function _newConfigHook(bytes32 configHash, bytes memory configData) internal virtual override {
        // Do nothing.
    }

    /// @notice Verifies if the provided `masterL2StateRoot` is valid given an L1 block header and a raw `proof`.
    ///
    /// @dev The following steps are performed to verify the provided `masterL2StateRoot`:
    ///      1. From the L1 state root hash (within the `l1BlockHeader`), prove the storage root of the
    ///         `AnchorStateRegistry` contract on L1.
    ///      2. From the storage root of the `AnchorStateRegistry`, prove the L2 OutputRoot stored at slot
    ///         `ANCHOR_STATE_REGISTRY_SLOT`. This slot corresponds to calling `anchors(0)` on the `AnchorStateRegistry`
    ///         contract.
    ///      3. From the proved L2 OutputRoot, verify the provided `l2StateRoot`. This is done by recomputing the L2
    ///         OutputRoot using the `l2StateRoot`, `l2MessagePasserStorageRoot`, and `l2BlockHash`
    ///         parameters. For more details, see the link:
    ///         https://github.com/ethereum-optimism/optimism/blob/d141b53e4f52a8eb96a552d46c2e1c6c068b032e/op-service/eth/output.go#L49-L63
    /// @param masterL2StateRoot The master L2 state root to verify
    /// @param l1BlockHeader The L1 block header used for verification.
    /// @param proof The raw proof.
    function _verifyMasterL2StateRoot(bytes32 masterL2StateRoot, BlockHeader memory l1BlockHeader, bytes memory proof)
        internal
        pure
        override
    {
        OPStrackProof memory p = abi.decode(proof, (OPStrackProof));

        // Get the OutputRoot that was submitted to the AnchorStateRegistry contract on L1.
        bytes32 outputRoot = StorageProofLib.extractAccountStorageValue({
            stateRoot: l1BlockHeader.stateRoot,
            account: ANCHOR_STATE_REGISTRY_ADDR,
            accountProof: p.anchorStateRegistryAccountProof,
            slot: ANCHOR_STATE_REGISTRY_SLOT,
            storageProof: p.anchorStateRegistryStorageProof
        });

        // Ensure the provided preimages of the `outputRoot` are valid.
        _validateOutputRootPreimages({
            masterL2StateRoot: masterL2StateRoot,
            l2MessagePasserStorageRoot: p.l2MessagePasserStorageRoot,
            l2BlockHash: p.l2BlockHash,
            outputRoot: outputRoot
        });
    }

    /// @notice Authorizes (or not) a Keystore config update.
    ///
    /// @dev The `l1BlockHeader` is OPTIONAL. If using this parameter, the implementation MUST check that the provided
    ///      L1 block header is not the default one. This can be done by using `require(l1BlockHeader.number > 0)`.
    ///
    /// @param currentConfigData The current Keystore config data.
    /// @param newConfigData The new Keystore config data.
    /// @param l1BlockHeader OPTIONAL: The L1 block header to access and prove L1 state.
    /// @param proof A proof authorizing the update.
    ///
    /// @return True if the update is authorized, otherwise false.
    function _authorizeUpdate(
        bytes memory currentConfigData,
        bytes calldata newConfigData,
        BlockHeader memory l1BlockHeader,
        bytes calldata proof
    ) internal view virtual override returns (bool) {
        // Verifies that `newConfigData` is valid based on `currentConfigData`, `l1BlockHeader` and `proof`
        return true;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures the proof's preimages values correctly hash to the expected `outputRoot`.
    ///
    /// @dev Reverts if the proof's preimages values do not hash to the expected `outputRoot`.
    ///
    /// @param masterL2StateRoot The master L2 state root.
    /// @param l2MessagePasserStorageRoot The storage root of the `MessagePasser` contract on the L2.
    /// @param l2BlockHash The block hash of the L2.
    /// @param outputRoot The outputRoot to validate.
    function _validateOutputRootPreimages(
        bytes32 masterL2StateRoot,
        bytes32 l2MessagePasserStorageRoot,
        bytes32 l2BlockHash,
        bytes32 outputRoot
    ) private pure {
        bytes32 version = bytes32(0);
        bytes32 recomputedOutputRoot =
            keccak256(abi.encodePacked(version, masterL2StateRoot, l2MessagePasserStorageRoot, l2BlockHash));

        require(recomputedOutputRoot == outputRoot, InvalidL2OutputRootPreimages());
    }
}
