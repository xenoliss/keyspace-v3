// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {IAccount} from "aa/interfaces/IAccount.sol";
import {UserOperation} from "aa/interfaces/UserOperation.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";

import {BlockHeader} from "../libs/BlockLib.sol";
import {Config} from "../libs/ConfigLib.sol";

import {Keystore, OPStackKeystore} from "./OPStackKeystore.sol";

/// @dev The Keystore config for this wallet.
struct KeystoreConfig {
    /// @dev The wallet signers.
    // TODO: Allow for non address (i.e P256) signers.
    mapping(address signer => bool isSigner) signers;
}

/// @dev Storage layout used to store the Wallet data.
///
/// @custom:storage-location erc7201:storage.MultiOwnableWallet
struct WalletStorage {
    // TODO: This seems like something all the wallets might do, should we expose this from the Keystore?
    /// @dev The current Keystore config hash.
    bytes32 currentConfigHash;
    /// @dev The mapping of Keystore configs.
    ///      NOTE: Using a mapping allows to set a new entry for each new Keystore config and thus avoid the need to
    ///            to have to properly delete all the previous config.
    mapping(bytes32 configHash => KeystoreConfig) keystoreConfig;
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

contract MultiOwnableWallet is OPStackKeystore, IAccount {
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

    /// @notice The wallet eventual consistency window.
    uint256 constant EVENTUAL_CONSISTENCY_WINDOW = 7 days;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Throwm when the caller is not authorized.
    error Unauthorized();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           MODIFIERS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures the caller is the EntryPoint.
    modifier onlyEntryPoint() virtual {
        require(msg.sender == ENTRYPOINT_ADDRESS, Unauthorized());

        _;
    }

    /// @notice Ensures the caller is ether the EntryPoint, the account itself or an owner.
    modifier onlyEntryPointOrOwner() virtual {
        // Authorize if the sender is the EntryPoint or the account itself.
        if (msg.sender == ENTRYPOINT_ADDRESS || msg.sender == address(this)) {
            _;
        }
        // Otherwise check that the semder is a signer.
        else {
            bytes32 currentConfigHash = _sWallet().currentConfigHash;
            KeystoreConfig storage config = _sWallet().keystoreConfig[currentConfigHash];

            uint256 confirmedConfigTimestamp = _confirmedConfigTimestamp();
            uint256 validUntil = confirmedConfigTimestamp + EVENTUAL_CONSISTENCY_WINDOW;

            // Ensure the sender is a signer AND ensure eventual consistency.
            // NOTE: It is safe to call `block.timestamp` as we know the sender is not the EntryPoint.
            require(config.signers[msg.sender] && block.timestamp <= validUntil, Unauthorized());

            _;
        }

        revert Unauthorized();
    }

    /// @notice Sends to the EntryPoint (i.e. `msg.sender`) the missing funds for this transaction.
    ///
    /// @param missingAccountFunds The minimum value this modifier should send the EntryPoint which
    ///                            MAY be zero, in case there is enough deposit, or the userOp has a
    ///                            paymaster.
    modifier payPrefund(uint256 missingAccountFunds) virtual {
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

    /// @inheritdoc IAccount
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        override
        onlyEntryPoint
        payPrefund(missingAccountFunds)
        returns (uint256 validationData)
    {
        // TODO: Could use transient storage to store if an action (i.e `confirmConfig`) has been performed.

        // Early return if the signature is invalid.
        if (!_isValidSignature({hash: userOpHash, signature: userOp.signature})) {
            return 1;
        }

        // On replica chains ensure eventual consistency by setting the `validUntil`.
        if (block.chainid != masterChainId) {
            uint256 confirmedConfigTimestamp = _confirmedConfigTimestamp();
            uint256 validUntil = confirmedConfigTimestamp + EVENTUAL_CONSISTENCY_WINDOW;
            validationData |= (uint256(validUntil) << 160);
        }
    }

    /// @notice Executes the given call from this account.
    ///
    /// @dev Reverts if not called by the Entrypoint or an owner of this account (including itself).
    ///
    /// @param target The address to call.
    /// @param value  The value to send with the call.
    /// @param data   The data of the call.
    function execute(address target, uint256 value, bytes calldata data) external payable onlyEntryPointOrOwner {
        _call({target: target, value: value, data: data});
    }

    /// @notice Executes batch of `Call`s.
    ///
    /// @dev Reverts if not called by the Entrypoint or an owner of this account (including itself).
    ///
    /// @param calls The list of `Call`s to execute.
    function executeBatch(Call[] calldata calls) external payable virtual onlyEntryPointOrOwner {
        for (uint256 i; i < calls.length; i++) {
            _call(calls[i].target, calls[i].value, calls[i].data);
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       INTERNAL FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @inheritdoc Keystore
    function _newConfigHook(bytes32 configHash, bytes memory configData) internal virtual override {
        address[] memory signers = abi.decode(configData, (address[]));

        _sWallet().currentConfigHash = configHash;

        // Register the new signers.
        mapping(address signer => bool isSigner) storage signers_ = _sWallet().keystoreConfig[configHash].signers;
        for (uint256 i; i < signers.length; i++) {
            signers_[signers[i]] = true;
        }
    }

    /// @inheritdoc Keystore
    function _authorizeUpdate(
        Config memory currentConfig,
        Config calldata newConfig,
        BlockHeader memory l1BlockHeader,
        bytes calldata authorizationProof
    ) internal view virtual override returns (bool) {
        // TODO: Implement this once figured out how to better shape the `_authorizeUpdate` interface.
    }

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

    // TODO: Implement ERC-1271 instead.
    /// @notice Validates the `signature` against the given `hash`.
    ///
    /// @param hash The hash whose signature has been performed on.
    /// @param signature The signature associated with `hash`.
    ///
    /// @return True is the signature is valid, else false.
    function _isValidSignature(bytes32 hash, bytes calldata signature) private view returns (bool) {
        (address signer, bytes memory signature_) = abi.decode(signature, (address, bytes));

        bytes32 currentConfigHash = _sWallet().currentConfigHash;
        KeystoreConfig storage config = _sWallet().keystoreConfig[currentConfigHash];

        // Ensure the signer is registered in the current Keystore config.
        if (!config.signers[signer]) {
            return false;
        }

        // Check if the signature is valid
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
}
