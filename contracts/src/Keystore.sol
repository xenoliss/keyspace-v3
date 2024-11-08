// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {BlockHeader, BlockLib} from "./libs/BlockLib.sol";
import {Config, ConfigLib} from "./libs/ConfigLib.sol";
import {L1BlockHashProof, L1ProofLib} from "./libs/L1ProofLib.sol";

/// @dev Storage layout of the Keystore on the master chain.
///
/// @custom:storage-location erc7201:storage.MasterKeystore
struct MasterKeystoreStorage {
    /// @dev The hash of the `config`.
    bytes32 configHash;
    /// @dev The Keystore config nonce.
    uint256 configNonce;
}

/// @dev Storage layout of the Keystore on replica chains.
///
/// @custom:storage-location erc7201:storage.ReplicaKeystore
struct ReplicaKeystoreStorage {
    /// @dev The hash of the `confirmedConfig`.
    bytes32 confirmedConfigHash;
    /// @dev The latest preconfirmed config nonce.
    uint256 currentConfigNonce;
    /// @dev The timestamp of the L1 block used to confirm the latest config.
    uint256 confirmedConfigTimestamp;
    /// @dev Preconfirmed Keystore config hashes.
    bytes32[] preconfirmedConfigHashes;
}

abstract contract Keystore {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Slot for the `MasterKeystoreStorage` struct in storage.
    ///
    /// @dev Computed as specified in ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201):
    ///      keccak256(abi.encode(uint256(keccak256("storage.MasterKeystore")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant MASTER_KEYSTORE_STORAGE_LOCATION =
        0xab0db9dff4dd1cc7cbf1b247b1f1845c685dfd323fb0c6da795f47e8940a2c00;

    /// @notice Slot for the `ReplicaKeystoreStorage` struct in storage.
    ///
    /// @dev Computed as specified in ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201):
    ///      keccak256(abi.encode(uint256(keccak256("storage.ReplicaKeystore")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant REPLICA_KEYSTORE_STORAGE_LOCATION =
        0x1db15b34d880056d333fb6d93991f1076dc9f2ab389771578344740e0968e700;

    /// @notice The master chain id.
    uint256 public immutable masterChainId;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the Keystore has already been intiialized.
    error KeystoreAlreadyInitialized();

    /// @notice Thrown when the initial Keystore config does not have a nonce equal to 0.
    error InitialNonceIsNotZero();

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

    /// @notice Thrown when the provided new nonce is not strictly equal the current nonce incremented by one.
    ///
    /// @param currentNonce The current nonce of the Keystore record.
    /// @param newNonce The provided new nonce.
    error NonceNotIncrementedByOne(uint256 currentNonce, uint256 newNonce);

    /// @notice Thrown when confirming the Keystore config on replica chains is required to achieve eventual
    ///         consistency.
    error EventualConsistencyRequired();

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
    /// @param authorizationProof The proof(s) to authorize the update.
    function setConfig(Config calldata newConfig, bytes calldata l1BlockData, bytes calldata authorizationProof)
        external
        onlyOnMasterChain
    {
        // NOTE: On the master chain the current config can not be empty since it is set during initialization.
        uint256 currentConfigNonce = _sMaster().configNonce;

        // Check if the update to `newConfig` is authorized.
        _verifyNewConfig({
            currentConfigNonce: currentConfigNonce,
            newConfig: newConfig,
            l1BlockData: l1BlockData,
            authorizationProof: authorizationProof
        });

        // Store the new config in storage.
        bytes32 newConfigHash = ConfigLib.hash(newConfig);
        _sMaster().configHash = newConfigHash;
        _sMaster().configNonce = newConfig.nonce;

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
    function confirmConfig(Config calldata newConfirmedConfig, bytes calldata keystoreProof)
        external
        onlyOnReplicaChain
    {
        // Extract the new confirmed config hash from the provided `keystoreProof`.
        (uint256 newConfirmedConfigTimestamp, bytes32 newConfirmedConfigHash) =
            _extractConfigHashFromMasterChain(keystoreProof);

        // Ensure the `newConfirmedConfig` matches with the extracted `newConfirmedConfigHash`.
        ConfigLib.verify({configHash: newConfirmedConfigHash, config: newConfirmedConfig});

        // Ensure we are going forward when proving the new confirmed config hash.
        uint256 confirmedConfigTimestamp = _sReplica().confirmedConfigTimestamp;
        require(
            newConfirmedConfigTimestamp > confirmedConfigTimestamp,
            ConfirmedConfigOutdated({
                currentConfirmedConfigTimestamp: confirmedConfigTimestamp,
                newConfirmedConfigTimestamp: newConfirmedConfigTimestamp
            })
        );

        // Ensure the preconfirmed configs are valid, given the new confirmed config hash.
        bool resetedPreconfirmedConfigs = _ensurePreconfirmedConfigsAreValid({
            newConfirmedConfigHash: newConfirmedConfigHash,
            newConfirmedConfig: newConfirmedConfig
        });

        // Store the new confirmed config info in storage.
        _sReplica().confirmedConfigHash = newConfirmedConfigHash;
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
    /// @param authorizationProof The proof(s) to authorize the update.
    function preconfirmConfig(
        uint256 confirmedConfigHashIndex,
        Config calldata newConfig,
        bytes calldata l1BlockData,
        bytes calldata authorizationProof
    ) external onlyOnReplicaChain {
        // Get the current confirmed hash from storage.
        bytes32 confirmedConfigHash = _sReplica().confirmedConfigHash;

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
        uint256 currentConfigNonce = _sReplica().currentConfigNonce;

        // Check if the update to `newConfig` is authorized.
        _verifyNewConfig({
            currentConfigNonce: currentConfigNonce,
            newConfig: newConfig,
            l1BlockData: l1BlockData,
            authorizationProof: authorizationProof
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

    /// @notice Hook triggered whenever a new Keystore config is established as the current one.
    ///
    /// @dev This hook is invoked under different conditions on the master chain and replica chains:
    ///      - On the master chain, it is called when `setConfig` executes successfully.
    ///      - On replica chains, it is called:
    ///         - whenever a preconfirmation operation is successful
    ///         - when confirming a new config, if the list of preconfirmed configs was reset
    ///
    /// @param configHash The new Keystore config hash.
    /// @param configData The new Keystore config data.
    function _newConfigHook(bytes32 configHash, bytes memory configData) internal virtual;

    /// @notice Extracts the Keystore config hash and timestamp from the master chain.
    ///
    /// @param keystoreProof The proof data used to extract the Keystore config hash on the master chain.
    ///
    /// @return l1BlockTimestamp The L1 block timestamp at which the Keystore config was confirmed.
    /// @return configHash The hash of the Keystore config extracted from the master chain.
    function _extractConfigHashFromMasterChain(bytes memory keystoreProof)
        internal
        view
        virtual
        returns (uint256 l1BlockTimestamp, bytes32 configHash);

    /// @notice Returns the the eventual consistency window within which the Keystore config must be confirmed on
    ///         replica chains.
    ///
    /// @return The duration of the eventual consistency window in seconds.
    function _eventualConsistencyWindow() internal view virtual returns (uint256);

    /// @notice Authorizes or rejects a Keystore config update.
    ///
    /// @dev This function MUST revert if the update is unauthorized or invalid.
    /// @dev The `l1BlockHeader` parameter is OPTIONAL; if provided, the implementation MUST verify it is valid by
    ///      ensuring `l1BlockHeader.number > 0`, which confirms it is not a default/empty header.
    ///
    /// @param newConfig The new Keystore config to be authorized.
    /// @param l1BlockHeader OPTIONAL: The L1 block header used for proving L1 state.
    /// @param authorizationProof The proof data required to authorize the config update.
    function _authorizeConfigUpdate(
        Config calldata newConfig,
        BlockHeader memory l1BlockHeader,
        bytes calldata authorizationProof
    ) internal view virtual;

    /// @notice Initializes the Keystore.
    ///
    /// @param config The initial Keystore config.
    function _initialize(Config calldata config) internal {
        // Ensure the Keystore starts at nonce 0.
        require(config.nonce == 0, InitialNonceIsNotZero());

        bytes32 configHash = ConfigLib.hash(config);
        if (block.chainid == masterChainId) {
            require(_sMaster().configHash == 0, KeystoreAlreadyInitialized());
            _sMaster().configHash = configHash;

            // Run the new config hook logic.
            _newConfigHook({configHash: configHash, configData: config.data});
        }

        // TODO: Double check this.
        // NOTE: No intialization is really needed on replica chains as `confirmConfig` must be called before being able
        //       to use the wallet.
    }

    /// @notice Returns the current config hash.
    ///
    /// @return The hash of the current Keystore config.
    function _currentConfigHash() internal view returns (bytes32) {
        if (block.chainid == masterChainId) {
            return _sMaster().configHash;
        }

        uint256 preconfirmedCount = _sReplica().preconfirmedConfigHashes.length;
        return _sReplica().preconfirmedConfigHashes[preconfirmedCount - 1];
    }

    /// @notice Enforces eventual consistency by requiring the confirmed Keystore config to be recent enough.
    ///
    /// @dev Reverts on replica chains if the confirmed Keystore config timestamp is older than the configured eventual
    ///      consistency window.
    function _enforceEventualConsistency() internal view {
        // Early return on the master chain.
        if (block.chainid == masterChainId) {
            return;
        }

        // On replica chains enforce eventual consistency.
        uint256 validUntil = _sReplica().confirmedConfigTimestamp + _eventualConsistencyWindow();
        require(block.timestamp <= validUntil, EventualConsistencyRequired());
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Helper function to get a storage reference to the `MasterKeystoreStorage` struct.
    ///
    /// @return $ A storage reference to the `MasterKeystoreStorage` struct.
    function _sMaster() private pure returns (MasterKeystoreStorage storage $) {
        bytes32 position = MASTER_KEYSTORE_STORAGE_LOCATION;
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

    /// @notice Verifies and authorizes a Keystore config update.
    ///
    /// @param currentConfigNonce The current nonce of the Keystore config, used to ensure updates are sequential.
    /// @param newConfig The new Keystore config to be verified and potentially authorized.
    /// @param l1BlockData OPTIONAL: Encoded L1 block header data and proof of its validity, formatted as
    ///                              `abi.encode(l1BlockHeaderRlp, l1BlockHashProof)`. If provided, this data may be
    ///                              used by the to verify the update against L1 state.
    /// @param authorizationProof The proof data required to authorize the config update.
    function _verifyNewConfig(
        uint256 currentConfigNonce,
        Config calldata newConfig,
        bytes calldata l1BlockData,
        bytes calldata authorizationProof
    ) private view {
        // Ensure the nonce is strictly incrementing.
        require(
            newConfig.nonce == currentConfigNonce + 1,
            NonceNotIncrementedByOne({currentNonce: currentConfigNonce, newNonce: newConfig.nonce})
        );

        // If provided, parse the L1 block header and ensure it's valid.
        BlockHeader memory l1BlockHeader;
        if (l1BlockData.length > 0) {
            (bytes memory l1BlockHeaderRlp, L1BlockHashProof memory l1BlockHashProof) =
                abi.decode(l1BlockData, (bytes, L1BlockHashProof));

            l1BlockHeader = BlockLib.parseBlockHeader(l1BlockHeaderRlp);
            L1ProofLib.verify({proof: l1BlockHashProof, expectedL1BlockHash: l1BlockHeader.hash});
        }

        // Ensure the config update is authorized.
        _authorizeConfigUpdate({
            newConfig: newConfig,
            l1BlockHeader: l1BlockHeader,
            authorizationProof: authorizationProof
        });
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
        uint256 currentConfigNonce = _sReplica().currentConfigNonce;
        if (newConfirmedConfig.nonce > currentConfigNonce) {
            _resetPreconfirmedConfigs({confirmedConfigHash: newConfirmedConfigHash, confirmedConfig: newConfirmedConfig});
            return true;
        }

        // Otherwise, the preconfirmed configs list MUST already include the new confirmed config hash.
        // If it does not, reset it.

        // Using the nonce difference, compute the index where the confirmed config hash should appear in the
        // preconfirmed configs list.
        // NOTE: This is possible because, each preconfirmed config nonce strictly increments by one from the
        //       previous config nonce.
        uint256 nonceDiff = currentConfigNonce - newConfirmedConfig.nonce;
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

    /// @notice Sets a new preconfirmed config.
    ///
    /// @param preconfirmedConfigHash The preconfirmed config hash.
    /// @param preconfirmedConfig The preconfirmed config.
    function _setPreconfirmedConfig(bytes32 preconfirmedConfigHash, Config memory preconfirmedConfig) private {
        _sReplica().preconfirmedConfigHashes.push(preconfirmedConfigHash);
        _sReplica().currentConfigNonce = preconfirmedConfig.nonce;
    }
}
