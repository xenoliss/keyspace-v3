// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {IAccount} from "aa/interfaces/IAccount.sol";
import {UserOperation} from "aa/interfaces/UserOperation.sol";
import {Receiver} from "solady/accounts/Receiver.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";

import {OPStackKeystore} from "../chains/OPStackKeystore.sol";

import {Keystore} from "../Keystore.sol";
import {BlockLib, ConfigLib} from "../KeystoreLibs.sol";

// **Eventual Consistency Strategy**
//
// Our approach enforces eventual consistency (EC) at execution time rather than validation time to prevent wallet
// bricking. By separating EC enforcement across config management, wallet upgrades, and transaction executions, we
// achieve a balance between security and usability. Here's the breakdown:
//
// 1. Config Confirmation and Wallet Upgrades (No EC Required):
//    - `confirmConfig` and `preconfirmConfig` operations do not require EC.
//    - EC is not enforced for wallet upgrades, allowing users to upgrade their wallet to a working implementation even
//      if they're not on the latest Keystore config. This way, the wallet is protected from bricking in cases where
//      proving the Keystore config from the master chain becomes unavailable (due to chain or protocol changes).
//
// 2. EC Enforcement at Execution Time:
//    - While `confirmConfig`, `preconfirmConfig`, and wallet upgrades bypass EC checks, EC is enforced for regular
//      calls. This approach ensures that EC is only enforced when executing non-config transactions, which is aligned
//      with secure wallet usage.
//
// 3. Removing EC at Validation Time:
//    - Eliminating EC enforcement at validation time simplifies UserOp handling, especially in scenarios where an
//      `executeBatch` contains both EC-requiring and non-EC calls.
//    - Validation-time EC enforcement led to complex workarounds, and moving it at execution-time is a gain in
//      flexibility and usability.
//
// 4. Security Considerations:
//    - Execution-time EC remains secure as the UserOp is signed by a trusted wallet signer. However, a revoked but
//      non-preconfirmed signer could potentially steal the user's funds by upgrading to a custom implementation. We
//      believe this tradeoff is worthwhile compared to the alternative risk of bricking all user wallets due to chain
//      or protocol changes.
//
// This design enforces EC where needed, prevents wallet bricking, and minimizes unnecessary EC checks. It strikes a
// balance between wallet integrity crosschain and improved usability.
//
// **Future Improvement: Reducing Security Risks of Wallet Upgrades in Unsynced States**
//
// To further minimize risks associated with a revoked, non-preconfirmed signer upgrading to a custom implementation, we
// propose the following conditions for `upgradeToAndCall` based on the wallet's sync status and deployment timing:
//
// 1. Synced Wallet with Established Deployment:
//    - If the wallet is synced and has been deployed on this chain for an extended period, allow the user to
//      `upgradeToAndCall` to any implementation address. This flexibility is appropriate as the wallet is already
//      stable and active on this chain.
//
// 2. Synced Wallet with Recent Deployment:
//    - If the wallet is synced but was deployed recently, it could indicate deployment on a new chain due to a
//      compromised signer. In this case, restrict `upgradeToAndCall` to implementation addresses whitelisted by the
//      wallet vendor, ensuring safe upgrades in response to potential security events.
//
// 3. Unsynced Wallet:
//    - If the wallet is unsynced, restrict `upgradeToAndCall` to wallet-vendor-whitelisted implementation addresses.
//      This approach limits the possibility of malicious upgrades on chains where the wallet has been active. By
//      requiring the user to preconfirm signer revocations on active chains, we reduce the chance of exploitation in
//      unsynced states.
//
// Implementing these restrictions in the future would further mitigate the security risks of allowing upgrades when the
// wallet is not on the latest Keystore config, providing an additional layer of protection.

/// @dev The Keystore config for this wallet.
struct KeystoreConfig {
    /// @dev The wallet signers.
    mapping(address signer => bool isSigner) signers;
}

/// @dev Storage layout used to store the Wallet data.
///
/// @custom:storage-location erc7201:storage.MultiOwnableWallet
struct WalletStorage {
    /// @dev The mapping of Keystore configs.
    ///      NOTE: Using a mapping allows to set a new entry for each new Keystore config and thus avoid the need to
    ///            to have to properly delete all the previous config.
    ///            `versionedConfigKey = keccak256(abi.encode(configHash, VERSION))`
    mapping(bytes32 versionedConfigKey => KeystoreConfig) keystoreConfig;
}

/// @notice Represents a call to make.
struct Call {
    /// @dev The address to call.
    address target;
    /// @dev The value to send when making the call.
    uint256 value;
    /// @dev The data of the call.
    bytes data;
}

contract MultiOwnableWallet is OPStackKeystore, UUPSUpgradeable, Receiver, IAccount {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The EntryPoint V0.6 address.
    address constant ENTRYPOINT_ADDRESS = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    /// @notice Slot for the `WalletStorage` struct in storage.
    ///
    /// @dev Computed as specified in ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201):
    ///      keccak256(abi.encode(uint256(keccak256("storage.MultiOwnableWallet")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant WALLET_STORAGE_LOCATION = 0xa77adb1dc9bb40c655d8d6905390b0bccb8c0d39c0692125ebfde9aed74bd500;

    /// @notice The wallet eventual consistency window for the Keystore config.
    uint256 constant EVENTUAL_CONSISTENCY_WINDOW = 7 days;

    /// @notice The wallet version.
    string constant VERSION = "v1.0.0";

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the caller is not authorized.
    error UnauthorizedCaller();

    /// @notice Thrown when the Keystore config update is not authorized.
    error UnauthorizedKeystoreConfigUpdate();

    /// @notice Thrown when the Keystore config update is invalid.
    error InvalidKeystoreConfigUpdate();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           MODIFIERS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures the caller is the EntryPoint.
    modifier onlyEntryPoint() {
        require(msg.sender == ENTRYPOINT_ADDRESS, UnauthorizedCaller());

        _;
    }

    /// @notice Ensures the caller is the account itself or an owner.
    modifier onlyOwner() {
        require(msg.sender == address(this) || _isOwner(msg.sender), UnauthorizedCaller());

        _;
    }

    /// @notice Ensures the caller is ether the EntryPoint, the account itself or an owner.
    modifier onlyEntryPointOrOwner() {
        require(
            msg.sender == ENTRYPOINT_ADDRESS || msg.sender == address(this) || _isOwner(msg.sender),
            UnauthorizedCaller()
        );

        _;
    }

    /// @notice Sends to the EntryPoint (i.e. `msg.sender`) the missing funds for this transaction.
    ///
    /// @param missingAccountFunds The minimum value this modifier should send the EntryPoint which
    ///                            MAY be zero, in case there is enough deposit, or the userOp has a
    ///                            paymaster.
    modifier payPrefund(uint256 missingAccountFunds) {
        _;

        assembly ("memory-safe") {
            if missingAccountFunds {
                // Ignore failure (it's EntryPoint's job to verify, not the account's).
                pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          CONSTRUCTOR                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    constructor(uint256 masterChainId) OPStackKeystore(masterChainId) {}

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Initializes the wallet.
    ///
    /// @param config The initial Keystore config.
    function initialize(ConfigLib.Config calldata config) external {
        _initialize(config);
    }

    /// @inheritdoc IAccount
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        override
        onlyEntryPoint
        payPrefund(missingAccountFunds)
        returns (uint256 validationData)
    {
        // TODO: We might still enforce "safe" eventual consistency at validation time with some restrictions.
        //       See if it's worth it.

        return _isValidSignature({hash: userOpHash, signature: userOp.signature}) ? 0 : 1;
    }

    /// @notice Executes the given call from this account.
    ///
    /// @dev Reverts if not called by the Entrypoint or an owner of this account (including itself).
    ///
    /// @param target The address to call.
    /// @param value  The value to send with the call.
    /// @param data   The data of the call.
    function execute(address target, uint256 value, bytes calldata data) external payable onlyEntryPointOrOwner {
        _enforceSafeEventualConsistency({target: target, data: data});
        _call({target: target, value: value, data: data});
    }

    /// @notice Executes batch of `Call`s.
    ///
    /// @dev Reverts if not called by the Entrypoint or an owner of this account (including itself).
    ///
    /// @param calls The list of `Call`s to execute.
    function executeBatch(Call[] calldata calls) external payable virtual onlyEntryPointOrOwner {
        for (uint256 i; i < calls.length; i++) {
            _enforceSafeEventualConsistency({target: calls[i].target, data: calls[i].data});
            _call(calls[i].target, calls[i].value, calls[i].data);
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       INTERNAL FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @inheritdoc Keystore
    function _newConfigHook(bytes32 configHash, bytes memory configData) internal override {
        address[] memory signers = abi.decode(configData, (address[]));

        // Register the new signers.
        bytes32 versionedConfigKey = _versionedConfigKey(configHash);
        mapping(address signer => bool isSigner) storage signers_ =
            _sWallet().keystoreConfig[versionedConfigKey].signers;

        for (uint256 i; i < signers.length; i++) {
            signers_[signers[i]] = true;
        }
    }

    /// @inheritdoc Keystore
    function _authorizeConfigUpdate(
        ConfigLib.Config calldata newConfig,
        BlockLib.BlockHeader memory,
        bytes calldata authorizationProof
    ) internal view override {
        bytes32 newConfigHash = ConfigLib.hash(newConfig);
        (bytes memory sigAuth, bytes memory sigUpdate, uint256 sigUpdateSignerIndex) =
            abi.decode(authorizationProof, (bytes, bytes, uint256));

        // Ensure the update is authorized.
        require(_isValidSignature({hash: newConfigHash, signature: sigAuth}), UnauthorizedKeystoreConfigUpdate());

        // Perform a safeguard check to make sure the update is valid.
        address[] memory signers = abi.decode(newConfig.data, (address[]));
        address sigUpdateSigner = signers[sigUpdateSignerIndex];

        require(
            SignatureCheckerLib.isValidSignatureNow({signer: sigUpdateSigner, hash: newConfigHash, signature: sigUpdate}),
            InvalidKeystoreConfigUpdate()
        );
    }

    /// @inheritdoc Keystore
    function _eventualConsistencyWindow() internal pure override returns (uint256) {
        return EVENTUAL_CONSISTENCY_WINDOW;
    }

    /// @inheritdoc UUPSUpgradeable
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Helper function to get a storage reference to the `WalletStorage` struct.
    ///
    /// @return $ A storage reference to the `WalletStorage` struct.
    function _sWallet() private pure returns (WalletStorage storage $) {
        bytes32 position = WALLET_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := position
        }
    }

    /// @notice Returns true if the provided `addr` is an owner.
    ///
    /// @param addr The address to check.
    ///
    /// @return True if the provided `addr` is an owner, otherwise false.
    function _isOwner(address addr) private view returns (bool) {
        bytes32 currentConfigHash = _currentConfigHash();
        bytes32 versionedConfigKey = _versionedConfigKey(currentConfigHash);
        KeystoreConfig storage config = _sWallet().keystoreConfig[versionedConfigKey];
        return config.signers[addr];
    }

    /// @notice Validates the `signature` against the given `hash`.
    ///
    /// @param hash The hash on which the signature was performed.
    /// @param signature The signature associated with `hash`.
    ///
    /// @return True if the signature is valid, else false.
    function _isValidSignature(bytes32 hash, bytes memory signature) private view returns (bool) {
        (address signer, bytes memory signature_) = abi.decode(signature, (address, bytes));

        // Ensure the signer is registered in the current Keystore config.
        if (!_isOwner(signer)) {
            return false;
        }

        // Check if the signature is valid.
        return SignatureCheckerLib.isValidSignatureNow({signer: signer, hash: hash, signature: signature_});
    }

    /// @notice Executes the given call from this account.
    ///
    /// @dev Reverts if the call reverted.
    /// @dev Implementation taken from
    ///      https://github.com/alchemyplatform/light-account/blob/43f625afdda544d5e5af9c370c9f4be0943e4e90/src/common/BaseLightAccount.sol#L125
    ///
    /// @param target The target call address.
    /// @param value The call value to user.
    /// @param data The raw call data.
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /// @notice Enforces safe eventual consistency.
    ///
    /// @dev "Safe" eventual consistency involves enforcing EC for all actions that are not related to Keystore
    ///      config management or wallet implementation upgrades. See "Eventual Consistency (EC) Strategy" notes.
    ///
    /// @param target The target address.
    /// @param data The raw call data.
    function _enforceSafeEventualConsistency(address target, bytes calldata data) private view {
        // NOTE: Early return on replica chains when eventual consistency should be skipped.
        if (_shouldSkipEventualConsistency({target: target, data: data})) {
            return;
        }

        // Falls back to the Keystore eventual consistency implementation.
        _enforceEventualConsistency();
    }

    /// @notice Check if eventual consistensy should be skipped when perfoming the provided call.
    ///
    /// @param target The target address.
    /// @param data The raw call data.
    ///
    /// @return True if eventual consistency should be skipped for the call, otherwise false.
    function _shouldSkipEventualConsistency(address target, bytes calldata data) private view returns (bool) {
        bytes4 selector = bytes4(data);
        return target == address(this)
            && (
                selector == Keystore.confirmConfig.selector || selector == Keystore.preconfirmConfig.selector
                    || selector == UUPSUpgradeable.upgradeToAndCall.selector
            );
    }

    /// @notice Returns the versionned config key.
    ///
    /// @param configHash The Keystore config hash.
    ///
    /// @return The versionned config key.
    function _versionedConfigKey(bytes32 configHash) private pure returns (bytes32) {
        return keccak256(abi.encode(configHash, VERSION));
    }
}
