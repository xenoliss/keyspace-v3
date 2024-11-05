// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

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
    // TODO: Should this be moved in `KeystoreStorage`? Seems more intuitive but it is only used in replica chains.
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

    error ConfirmedConfigOutdated(uint256 currentConfirmedConfigTimestamp, uint256 newConfirmedConfigTimestamp);

    error ConfirmedValueHashNotFound(
        uint256 confirmedConfigHashIndex, bytes32 preConfirmedConfigHashAtIndex, bytes32 expectedConfirmedValueHash
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
        require(block.chainid == masterChainId, "NotOnMasterChain");
        _;
    }

    /// @notice Ensures the call is performed on a replica chain.
    modifier onlyReplicaChain() {
        require(block.chainid != masterChainId, "NotOnReplicaChain");
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

    function setConfig(
        Config calldata newConfig,
        bytes calldata l1BlockData,
        ControllerProofs calldata controllerProofs
    ) external onlyOnMasterChain {
        // NOTE: On the master chain the current config can not be empty since it is set during initialization.
        Config memory currentConfig = s().config;

        // Check if the update to `newConfig` is authorized.
        KeystoreLib.verifyNewConfig({
            currentConfig: currentConfig,
            newConfig: newConfig,
            l1BlockData: l1BlockData,
            controllerProofs: controllerProofs
        });

        // Store the new config in storage.
        bytes32 newConfigHash = ConfigLib.hash(newConfig);
        s().config = newConfig;
        s().configHash = newConfigHash;

        // Run the set config hook logic.
        setConfigHook({confirmedConfigTimestamp: block.timestamp, configHash: newConfigHash, configData: newConfig.data});

        emit KeystoreConfigSet(newConfigHash);
    }

    function confirmConfig(Config calldata newConfig, KeystoreProof calldata keystoreProof) external onlyReplicaChain {
        // Extract the new confirmed config hash from the provided `keystoreProof`.
        (uint256 confirmedConfigTimestamp, bytes32 newConfirmedConfigHash) = KeystoreLib.extractKeystoreConfigHash({
            // FIXME
            anchorStateRegistry: address(0),
            masterKeystore: address(this),
            configHashSlot: KEYSTORE_STORAGE_LOCATION,
            keystoreProof: keystoreProof
        });

        // Ensure the `newConfig` matches with the extracted `newConfirmedConfigHash`.
        ConfigLib.verify({config: newConfig, configHash: newConfirmedConfigHash});

        // Ensure we are going forward when proving the new confirmed config hash.
        require(
            confirmedConfigTimestamp > sReplica().confirmedConfigTimestamp,
            ConfirmedConfigOutdated({
                currentConfirmedConfigTimestamp: sReplica().confirmedConfigTimestamp,
                newConfirmedConfigTimestamp: confirmedConfigTimestamp
            })
        );

        // Ensure the preconfirmed configs are valid, given the new confirmed config hash.
        _ensurePreconfirmedConfigsAreValid({
            newConfirmedConfigHash: newConfirmedConfigHash,
            newConfirmedConfig: newConfig
        });

        // Store the new confirmed config in storage.
        s().config = newConfig;
        s().configHash = newConfirmedConfigHash;
        sReplica().confirmedConfigTimestamp = confirmedConfigTimestamp;

        // TODO: See how to plug the setConfigHook.

        emit KeystoreConfigConfirmed(newConfirmedConfigHash);
    }

    function preconfirmConfig(
        uint256 confirmedConfigHashIndex,
        Config calldata newConfig,
        bytes calldata l1BlockData,
        ControllerProofs calldata controllerProofs
    ) external onlyReplicaChain {
        // Use the latest preconfirmed ValueHash as the current one.
        bytes32 confirmedConfigHash = s().configHash;
        bytes32 preConfirmedConfigHashAtIndex = sReplica().preconfirmedConfigHashes[confirmedConfigHashIndex];
        require(
            preConfirmedConfigHashAtIndex == confirmedConfigHash,
            ConfirmedValueHashNotFound({
                confirmedConfigHashIndex: confirmedConfigHashIndex,
                preConfirmedConfigHashAtIndex: preConfirmedConfigHashAtIndex,
                expectedConfirmedValueHash: confirmedConfigHash
            })
        );

        // TODO: This could be empty.
        Config memory currentConfig = s().config;

        // Check if the update to `newConfig` is authorized.
        KeystoreLib.verifyNewConfig({
            currentConfig: currentConfig,
            newConfig: newConfig,
            l1BlockData: l1BlockData,
            controllerProofs: controllerProofs
        });

        // Preconfirm the new config.
        bytes32 newConfigHash = ConfigLib.hash(newConfig);
        _preconfirm({preconfirmedConfigHash: newConfigHash, preconfirmedConfig: newConfig});

        // Run the set config hook logic.
        setConfigHook({
            confirmedConfigTimestamp: sReplica().confirmedConfigTimestamp,
            configHash: newConfigHash,
            configData: newConfig.data
        });

        emit KeystoreConfigPreconfirmed(newConfigHash);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       INTERNAL FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Helper function to get a storage reference to the `KeystoreStorage` struct.
    ///
    /// @return $ A storage reference to the `KeystoreStorage` struct.
    function s() internal pure returns (KeystoreStorage storage $) {
        bytes32 position = KEYSTORE_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := position
        }
    }

    /// @notice Helper function to get a storage reference to the `ReplicaKeystoreStorage` struct.
    ///
    /// @return $ A storage reference to the `ReplicaKeystoreStorage` struct.
    function sReplica() internal pure returns (ReplicaKeystoreStorage storage $) {
        bytes32 position = REPLICA_KEYSTORE_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := position
        }
    }

    /// @notice Hook called whenever a new Keystore config is defined as the current one.
    ///
    /// @dev On the master chain this is called whenever `setConfig` succeeds.
    ///      On replica chains this is called:
    ///         - whenever a preconfirmation succeeds
    ///         - when confirming a new config if the preconfirmed configs list was reseted
    ///
    /// @param confirmedConfigTimestamp The corresponding confirmed config timestamp.
    /// @param configHash The config hash.
    /// @param configData The raw config data.
    function setConfigHook(uint256 confirmedConfigTimestamp, bytes32 configHash, bytes memory configData)
        internal
        virtual;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures that the preconfirmed configs are valid given provided `newConfirmedConfigHash`.
    ///
    /// @dev If the preconfirmed configs list does not include `newConfirmedConfigHash`, it is reseted and initialized
    ///      with the provided `newConfirmedConfigHash`.
    ///
    /// @param newConfirmedConfigHash The new confirmed config hash.
    /// @param newConfirmedConfig The new confirmed config.
    function _ensurePreconfirmedConfigsAreValid(bytes32 newConfirmedConfigHash, Config calldata newConfirmedConfig)
        private
    {
        // Get a storage reference to the Keystore preconfirmed config hashes.
        bytes32[] storage preconfirmedConfigHashes = sReplica().preconfirmedConfigHashes;

        // If the nothing has been preconfirmed yet, push the new confirmed config hash into it.
        // TODO: Think about this edge case.
        uint256 preconfirmedConfigHashesCount = preconfirmedConfigHashes.length;
        if (preconfirmedConfigHashesCount == 0) {
            _preconfirm({preconfirmedConfigHash: newConfirmedConfigHash, preconfirmedConfig: newConfirmedConfig});
            return;
        }

        // If the new confirmed config has a nonce above our current config, reset the preconfirmed configs.
        Config memory currentConfig = sReplica().currentConfig;
        if (newConfirmedConfig.nonce > currentConfig.nonce) {
            _resetPreconfirmedConfigs({confirmedConfigHash: newConfirmedConfigHash, confirmedConfig: newConfirmedConfig});
        }
        // Otherwise, the preconfirmed configs list MUST already include the new confirmed config hash.
        // If it does not, reset it.
        else {
            // Using the nonce difference, compute the index where the confirmed config hash should appear in the
            // preconfirmed configs list.
            // NOTE: This is possible because, each preconfirmed config nonce strictly increments by one from the
            //       previous config nonce.
            uint256 nonceDiff = currentConfig.nonce - newConfirmedConfig.nonce;
            uint256 confirmedConfigHashIndex = preconfirmedConfigHashesCount - 1 - nonceDiff;

            // If the confirmed config hash is not found at that index, reset the preconfirmed configs list.
            if (preconfirmedConfigHashes[confirmedConfigHashIndex] != newConfirmedConfigHash) {
                _resetPreconfirmedConfigs({
                    confirmedConfigHash: newConfirmedConfigHash,
                    confirmedConfig: newConfirmedConfig
                });
            }
        }
    }

    /// @notice Resets the preconfirmed configs.
    ///
    /// @param confirmedConfigHash The confirmed config hash to start form.
    /// @param confirmedConfig The confirmed config to cache as the current one.
    function _resetPreconfirmedConfigs(bytes32 confirmedConfigHash, Config memory confirmedConfig) private {
        delete sReplica().preconfirmedConfigHashes;
        _preconfirm({preconfirmedConfigHash: confirmedConfigHash, preconfirmedConfig: confirmedConfig});
    }

    /// @notice Pushes the `preconfirmedConfigHash` to the `preconfirmedConfigHashes` list and makes the
    ///         `preconfirmedConfig` the current one.
    ///
    /// @param preconfirmedConfigHash The preconfirmed config hash.
    /// @param preconfirmedConfig The preconfirmed config.
    function _preconfirm(bytes32 preconfirmedConfigHash, Config memory preconfirmedConfig) private {
        sReplica().preconfirmedConfigHashes.push(preconfirmedConfigHash);
        sReplica().currentConfig = preconfirmedConfig;
    }
}
