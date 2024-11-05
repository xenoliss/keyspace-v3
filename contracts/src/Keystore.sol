// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockHeader} from "./interfaces/IRecordController.sol";

import {Config, ConfigLib} from "./libs/ConfigLib.sol";
import {ControllerProofs, KeystoreLib, KeystoreProof} from "./libs/KeystoreLib.sol";

/// @dev Storage layout used to store the Keystore data.
///
/// @custom:storage-location erc7201:storage.keystore
struct KeystoreStorage {
    /// @dev The hash of the `config`.
    bytes32 configHash;
    /// @dev The Keystore config.
    ///      This config is always a "confirmed" config:
    ///         - Set on the master chain when calling `setConfig`
    ///         - Set on replica chains when confirming a config via `confirmConfig`
    Config config;
}

/// @dev Storage layout used to store the Replica Keystore data.
///
/// @custom:storage-location erc7201:storage.replica-keystore
struct ReplicaKeystoreStorage {
    /// @dev The timestamp of the L1 block used to confirm the latest config.
    uint256 confirmedConfigTimestamp;
    /// @dev Preconfirmed Keystore config hashes.
    bytes32[] preconfirmedConfigHashes;
    /// @dev The latest preconfirmed config.
    Config currentConfig;
}

abstract contract Keystore {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Slot for the `KeystoreStorage` struct in storage.
    ///
    /// @dev Computed as specified in ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201):
    ///      keccak256(abi.encode(uint256(keccak256("storage.keystore")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant KEYSTORE_STORAGE_LOCATION = 0x0b1fbc087a704d887481e0b979aef52eae0ecf245d706bc2883fac5de20f5300;

    /// @notice Slot for the `ReplicaKeystoreStorage` struct in storage.
    ///
    /// @dev Computed as specified in ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201):
    ///      keccak256(abi.encode(uint256(keccak256("storage.replica-keystore")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant REPLICA_KEYSTORE_STORAGE_LOCATION =
        0x2a7ceb0f25ad818347491d440a6684c9d8983f80d8537fafb95351de9528f200;

    /// @notice The master chain id.
    uint256 public immutable masterChainId;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the call is not performed on the master chain.
    error NotOnMasterChain();

    /// @notice Thrown when the call is not performed on a replica chain.
    error NotOnReplicaChain();

    /// @notice Thrown when trying to confirm a Keystore config but the extracted confirmed config hash, from the
    ///         master chain, has a confirmation timestamp below the current confirmed config timestamp.
    ///
    /// @param currentConfirmedConfigTimestamp The current confirmed config timestamp.
    /// @param newConfirmedConfigTimestamp The new confirmed config timestamp.
    error ConfirmedConfigOutdated(uint256 currentConfirmedConfigTimestamp, uint256 newConfirmedConfigTimestamp);

    /// @notice Thrown when trying to preconfirm a Keystore config but the config hash found at index
    ///         `confirmedConfigHashIndex` in the preconfirmed config list does not match with the expected confirmed
    ///         config hash.
    ///
    /// @param confirmedConfigHashIndex The index where the confirmed config hash was expeted to be found in the
    ///                                 preconfirmed config.
    /// @param preConfirmedConfigHashAtIndex The preconfirmed config hash found at the `confirmedConfigHashIndex` in
    ///                                      preconfirmed config list.
    /// @param expectedConfirmedConfigHash The expected confirmed config hash.
    error ConfirmedConfigHashNotFound(
        uint256 confirmedConfigHashIndex, bytes32 preConfirmedConfigHashAtIndex, bytes32 expectedConfirmedConfigHash
    );

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              EVENTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Emitted when a Keystore config is updated on the master chain.
    ///
    /// @param newConfigHash The new config hash.
    event KeystoreConfigSet(bytes32 indexed newConfigHash);

    /// @notice Emitted when a Keystore config is confirmed on a replica chain.
    ///
    /// @param newConfigHash The new config hash.
    event KeystoreConfigConfirmed(bytes32 indexed newConfigHash);

    /// @notice Emitted when a Keystore config is preconfirmed on a replica chain.
    ///
    /// @param newConfigHash The new config hash.
    event KeystoreConfigPreconfirmed(bytes32 indexed newConfigHash);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           MODIFIERS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures the call is performed on the master chain.
    modifier onlyOnMasterChain() {
        require(block.chainid == masterChainId, NotOnMasterChain());
        _;
    }

    /// @notice Ensures the call is performed on a replica chain.
    modifier onlyOnReplicaChain() {
        require(block.chainid != masterChainId, NotOnReplicaChain());
        _;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          CONSTRUCTOR                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Creates the Keystore.
    ///
    /// @param masterChainId_ The master chain id.
    constructor(uint256 masterChainId_) {
        masterChainId = masterChainId_;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Set a Keystore config on the master chain.
    ///
    /// @dev Reverts if not called on the master chain.
    ///
    /// @param newConfig The Keystore config to store.
    /// @param l1BlockData OPTIONAL: An L1 block header, RLP-encoded, and a proof of its validity.
    ///                              If present, it is expected to be `abi.encode(l1BlockHeaderRlp, l1BlockHashProof)`.
    ///                              This OPTIONAL L1 block header is meant to be provided to the Keystore record
    ///                              controller `authorize` method to perform authorization based on the L1 state.
    /// @param controllerProofs The `ControllerProofs` struct containing the necessary proofs to authorize the update.
    function setConfig(
        Config calldata newConfig,
        bytes calldata l1BlockData,
        ControllerProofs calldata controllerProofs
    ) external onlyOnMasterChain {
        // NOTE: On the master chain the current config can not be empty since it is set during initialization.
        Config memory currentConfig = _s().config;

        // Check if the update to `newConfig` is authorized.
        KeystoreLib.verifyNewConfig({
            currentConfig: currentConfig,
            newConfig: newConfig,
            l1BlockData: l1BlockData,
            controllerProofs: controllerProofs
        });

        // Store the new config in storage.
        bytes32 newConfigHash = ConfigLib.hash(newConfig);
        _setConfirmedConfig({confirmedConfigHash: newConfigHash, confirmedConfig: newConfig});

        // Run the new config hook logic.
        _newConfigHook({configHash: newConfigHash, configData: newConfig.data});

        emit KeystoreConfigSet(newConfigHash);
    }

    /// @notice Confirms a Keystore config from the master chain.
    ///
    /// @dev Reverts if not called on a replica chain.
    ///
    /// @param newConfirmedConfig The config to confirm.
    /// @param keystoreProof The Keystore proof from which to extract the new confirmed config hash.
    function confirmConfig(Config calldata newConfirmedConfig, KeystoreProof calldata keystoreProof)
        external
        onlyOnReplicaChain
    {
        // Extract the new confirmed config hash from the provided `keystoreProof`.
        (uint256 newConfirmedConfigTimestamp, bytes32 newConfirmedConfigHash) = KeystoreLib.extractKeystoreConfigHash({
            configHashSlot: KEYSTORE_STORAGE_LOCATION,
            keystoreProof: keystoreProof,
            verifyMasterL2StateRoot: _verifyMasterL2StateRoot
        });

        // Ensure the `newConfirmedConfig` matches with the extracted `newConfirmedConfigHash`.
        ConfigLib.verify({config: newConfirmedConfig, configHash: newConfirmedConfigHash});

        // Ensure we are going forward when proving the new confirmed config hash.
        uint256 confirmedConfigTimestamp = _sReplica().confirmedConfigTimestamp;
        require(
            confirmedConfigTimestamp > confirmedConfigTimestamp,
            ConfirmedConfigOutdated({
                currentConfirmedConfigTimestamp: confirmedConfigTimestamp,
                newConfirmedConfigTimestamp: confirmedConfigTimestamp
            })
        );

        // Ensure the preconfirmed configs are valid, given the new confirmed config hash.
        bool resetedPreconfirmedConfigs = _ensurePreconfirmedConfigsAreValid({
            newConfirmedConfigHash: newConfirmedConfigHash,
            newConfirmedConfig: newConfirmedConfig
        });

        // Store the new confirmed config in storage.
        _setConfirmedConfig({confirmedConfigHash: newConfirmedConfigHash, confirmedConfig: newConfirmedConfig});

        // Update the confirmed config timestamp.
        _sReplica().confirmedConfigTimestamp = newConfirmedConfigTimestamp;

        // Run the new config hook logic if the preconfirmed configs list was reseted.
        if (resetedPreconfirmedConfigs) {
            _newConfigHook({configHash: newConfirmedConfigHash, configData: newConfirmedConfig.data});
        }

        emit KeystoreConfigConfirmed(newConfirmedConfigHash);
    }

    /// @notice Preconfirms a Keystore config.
    ///
    /// @param confirmedConfigHashIndex The index of the config hash within the preconfirmed configs list.
    /// @param newConfig The new config to preconfirm.
    /// @param l1BlockData OPTIONAL: An L1 block header, RLP-encoded, and a proof of its validity.
    ///                              If present, it is expected to be `abi.encode(l1BlockHeaderRlp, l1BlockHashProof)`.
    ///                              This OPTIONAL L1 block header is meant to be provided to the Keystore record
    ///                              controller `authorize` method to perform authorization based on the L1 state.
    /// @param controllerProofs The `ControllerProofs` struct containing the necessary proofs to authorize the update.
    function preconfirmConfig(
        uint256 confirmedConfigHashIndex,
        Config calldata newConfig,
        bytes calldata l1BlockData,
        ControllerProofs calldata controllerProofs
    ) external onlyOnReplicaChain {
        // Get the current confirmed hash from storage.
        bytes32 confirmedConfigHash = _s().configHash;

        // Get the config hash from the preconfirmed configs list at the provided `confirmedConfigHashIndex`.
        // NOTE: This will always revert if `confirmConfig` was never called on this chain as this is the only
        //       way to pre-populate the preconfirmed configs list.
        bytes32 preConfirmedConfigHashAtIndex = _sReplica().preconfirmedConfigHashes[confirmedConfigHashIndex];

        // Ensure the config hash from the preconfirmed configs list is effectively the expected `confirmedConfigHash`.
        require(
            preConfirmedConfigHashAtIndex == confirmedConfigHash,
            ConfirmedConfigHashNotFound({
                confirmedConfigHashIndex: confirmedConfigHashIndex,
                preConfirmedConfigHashAtIndex: preConfirmedConfigHashAtIndex,
                expectedConfirmedConfigHash: confirmedConfigHash
            })
        );

        // NOTE: On replica chains the current config can not be empty since we require at least one call to
        //       `confirmConfig` before being able to call `preconfirmConfig`.
        Config memory currentConfig = _sReplica().currentConfig;

        // Check if the update to `newConfig` is authorized.
        KeystoreLib.verifyNewConfig({
            currentConfig: currentConfig,
            newConfig: newConfig,
            l1BlockData: l1BlockData,
            controllerProofs: controllerProofs
        });

        // Preconfirm the new config.
        bytes32 newConfigHash = ConfigLib.hash(newConfig);
        _setPreconfirmedConfig({preconfirmedConfigHash: newConfigHash, preconfirmedConfig: newConfig});

        // Run the new config hook logic.
        _newConfigHook({configHash: newConfigHash, configData: newConfig.data});

        emit KeystoreConfigPreconfirmed(newConfigHash);
    }

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
    function _newConfigHook(bytes32 configHash, bytes memory configData) internal virtual;

    /// @notice Ensures the provided `l2StateRoot` is valid given an L1 block header and a row `proof`.
    ///
    /// @param l2StateRoot The L2 state root to verify
    /// @param l1BlockHeader The L1 block header used for verification.
    /// @param proof The raw proof.
    function _verifyMasterL2StateRoot(bytes32 l2StateRoot, BlockHeader memory l1BlockHeader, bytes memory proof)
        internal
        view
        virtual;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Helper function to get a storage reference to the `KeystoreStorage` struct.
    ///
    /// @return $ A storage reference to the `KeystoreStorage` struct.
    function _s() private pure returns (KeystoreStorage storage $) {
        bytes32 position = KEYSTORE_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := position
        }
    }

    /// @notice Helper function to get a storage reference to the `ReplicaKeystoreStorage` struct.
    ///
    /// @return $ A storage reference to the `ReplicaKeystoreStorage` struct.
    function _sReplica() private pure returns (ReplicaKeystoreStorage storage $) {
        bytes32 position = REPLICA_KEYSTORE_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := position
        }
    }

    /// @notice Ensures that the preconfirmed configs are valid given the provided `newConfirmedConfigHash`.
    ///
    /// @param newConfirmedConfigHash The new confirmed config hash.
    /// @param newConfirmedConfig The new confirmed config.
    ///
    /// @return resetedPreconfirmedConfigs True if the preconfirmed configs list has been reseted, false otherwise.
    function _ensurePreconfirmedConfigsAreValid(bytes32 newConfirmedConfigHash, Config calldata newConfirmedConfig)
        private
        returns (bool resetedPreconfirmedConfigs)
    {
        // Get a storage reference to the Keystore preconfirmed configs list.
        bytes32[] storage preconfirmedConfigHashes = _sReplica().preconfirmedConfigHashes;

        // If the nothing has been preconfirmed yet, push the new confirmed config hash into it.
        // NOTE: This should only ever be the case when the wallet is confirmed for the first time on a replica chain.
        //       Otherwise, the preconfirmed configs list is guaranteed to be at least of length one (corresponding to
        //       the confirmed config hash that was provided).
        uint256 preconfirmedConfigHashesCount = preconfirmedConfigHashes.length;
        if (preconfirmedConfigHashesCount == 0) {
            _setPreconfirmedConfig({
                preconfirmedConfigHash: newConfirmedConfigHash,
                preconfirmedConfig: newConfirmedConfig
            });
            return true;
        }

        // If the new confirmed config has a nonce above our current config, reset the preconfirmed configs.
        Config memory currentConfig = _sReplica().currentConfig;
        if (newConfirmedConfig.nonce > currentConfig.nonce) {
            _resetPreconfirmedConfigs({confirmedConfigHash: newConfirmedConfigHash, confirmedConfig: newConfirmedConfig});
            return true;
        }

        // Otherwise, the preconfirmed configs list MUST already include the new confirmed config hash.
        // If it does not, reset it.

        // Using the nonce difference, compute the index where the confirmed config hash should appear in the
        // preconfirmed configs list.
        // NOTE: This is possible because, each preconfirmed config nonce strictly increments by one from the
        //       previous config nonce.
        uint256 nonceDiff = currentConfig.nonce - newConfirmedConfig.nonce;
        uint256 confirmedConfigHashIndex = preconfirmedConfigHashesCount - 1 - nonceDiff;

        // If the confirmed config hash is not found at that index, reset the preconfirmed configs list.
        if (preconfirmedConfigHashes[confirmedConfigHashIndex] != newConfirmedConfigHash) {
            _resetPreconfirmedConfigs({confirmedConfigHash: newConfirmedConfigHash, confirmedConfig: newConfirmedConfig});
            return true;
        }
    }

    /// @notice Resets the preconfirmed configs.
    ///
    /// @param confirmedConfigHash The confirmed config hash to start form.
    /// @param confirmedConfig The confirmed config to cache as the current one.
    function _resetPreconfirmedConfigs(bytes32 confirmedConfigHash, Config memory confirmedConfig) private {
        delete _sReplica().preconfirmedConfigHashes;
        _setPreconfirmedConfig({preconfirmedConfigHash: confirmedConfigHash, preconfirmedConfig: confirmedConfig});
    }

    /// @notice Sets the confirmed config in storage.
    ///
    /// @param confirmedConfigHash The confirmed config hash.
    /// @param confirmedConfig The confirmed config.
    function _setConfirmedConfig(bytes32 confirmedConfigHash, Config memory confirmedConfig) private {
        KeystoreStorage storage s_ = _s();

        s_.configHash = confirmedConfigHash;
        s_.config = confirmedConfig;
    }

    /// @notice Sets a new preconfirmed config.
    ///
    /// @param preconfirmedConfigHash The preconfirmed config hash.
    /// @param preconfirmedConfig The preconfirmed config.
    function _setPreconfirmedConfig(bytes32 preconfirmedConfigHash, Config memory preconfirmedConfig) private {
        ReplicaKeystoreStorage storage s_ = _sReplica();

        s_.preconfirmedConfigHashes.push(preconfirmedConfigHash);
        s_.currentConfig = preconfirmedConfig;
    }
}
