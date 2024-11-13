// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Keystore} from "../Keystore.sol";
import {BlockLib, L1ProofLib, StorageProofLib} from "../KeystoreLibs.sol";

/// @dev OPStack specfic proof used to verify a master L2 state root.
struct OPStrackProof {
    /// @dev The L1 block header, RLP-encoded.
    bytes l1BlockHeaderRlp;
    /// @dev The L1 block hash proof.
    L1ProofLib.L1BlockHashProof l1BlockHashProof;
    /// @dev The Keystore account proof on the master chain.
    bytes[] masterKeystoreAccountProof;
    /// @dev The Keystore storage proof on the master chain.
    bytes[] masterKeystoreStorageProof;
    /// @dev The `AnchorStateRegistry` account proof on L1.
    bytes[] anchorStateRegistryAccountProof;
    /// @dev The storage proof of the master L2 OutputRoot stored in the `AnchorStateRegistry` contract on L1.
    bytes[] anchorStateRegistryStorageProof;
    /// @dev The state root of the master L2.
    bytes32 l2StateRoot;
    /// @dev The storage root of the `MessagePasser` contract on the master L2.
    bytes32 l2MessagePasserStorageRoot;
    /// @dev The block hash of the master L2.
    bytes32 l2BlockHash;
}

abstract contract OPStackKeystore is Keystore {
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

    /// @inheritdoc Keystore
    ///
    /// @dev The following proving steps are performed to extract a Keystore config hash from the master chain:
    ///      1. Prove the validity of the provided `blockHeaderRlp` against the L1 block hash returned by the
    ///         `l1BlockHashOracle`.
    ///      2. From the L1 state root hash (within the `l1BlockHeader`), prove the storage root of the
    ///         `AnchorStateRegistry` contract on L1 and then prove the L2 OutputRoot stored at slot
    ///         `ANCHOR_STATE_REGISTRY_SLOT`. This slot corresponds to calling `anchors(0)` on the `AnchorStateRegistry`
    ///         contract.
    ///      3. From the proved L2 OutputRoot, verify the provided `l2StateRoot`. This is done by recomputing the L2
    ///         OutputRoot using the `l2StateRoot`, `l2MessagePasserStorageRoot`, and `l2BlockHash`
    ///         parameters. For more details, see the link:
    ///         https://github.com/ethereum-optimism/optimism/blob/d141b53e4f52a8eb96a552d46c2e1c6c068b032e/op-service/eth/output.go#L49-L63
    ///      4. From the master chain `l2StateRoot`, prove the Keystore storage root and prove the stored config hash.
    ///
    /// @param keystoreProof The proof required to extract the Keystore config hash.
    ///
    /// @return l1BlockTimestamp The timestamp of the L1 block associated with the proven config hash.
    /// @return isSet Whether the config hash is set or not.
    /// @return configHash The config hash extracted from the Keystore on the master chain.
    function _extractConfigHashFromMasterChain(bytes memory keystoreProof)
        internal
        view
        override
        returns (uint256 l1BlockTimestamp, bool isSet, bytes32 configHash)
    {
        OPStrackProof memory proof = abi.decode(keystoreProof, (OPStrackProof));

        // Parse the provided L1 block header.
        BlockLib.BlockHeader memory l1BlockHeader = BlockLib.parseBlockHeader(proof.l1BlockHeaderRlp);
        l1BlockTimestamp = l1BlockHeader.timestamp;

        // 1. Ensure the provided L1 block header can be used (i.e the block hash is valid).
        L1ProofLib.verify({proof: proof.l1BlockHashProof, expectedL1BlockHash: l1BlockHeader.hash});

        // 2. Get the OutputRoot that was submitted to the AnchorStateRegistry contract on L1.
        (, bytes32 outputRoot) = StorageProofLib.extractAccountStorageValue({
            stateRoot: l1BlockHeader.stateRoot,
            account: ANCHOR_STATE_REGISTRY_ADDR,
            accountProof: proof.anchorStateRegistryAccountProof,
            slot: ANCHOR_STATE_REGISTRY_SLOT,
            storageProof: proof.anchorStateRegistryStorageProof
        });

        // 3. Ensure the provided preimages of the `outputRoot` are valid.
        _validateOutputRootPreimages({
            masterL2StateRoot: proof.l2StateRoot,
            l2MessagePasserStorageRoot: proof.l2MessagePasserStorageRoot,
            l2BlockHash: proof.l2BlockHash,
            outputRoot: outputRoot
        });

        // 4. Get the config hash stored in the Keystore on the master chain.
        (isSet, configHash) = StorageProofLib.extractAccountStorageValue({
            stateRoot: proof.l2StateRoot,
            account: address(this),
            accountProof: proof.masterKeystoreAccountProof,
            slot: keccak256(abi.encodePacked(MASTER_KEYSTORE_STORAGE_LOCATION)),
            storageProof: proof.masterKeystoreStorageProof
        });
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
