// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";

abstract contract TransientUUPSUpgradeable is UUPSUpgradeable {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the upgrade is not allowed.
    error UpgradeNotAllowed();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       INTERNAL FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Explicitely allow the next upgrade by setting transient storage.
    function _allowUpgrade() internal {
        // TODO: When 0.8.28 is supported, use transient storage variable.

        // Set transient storage to allow upgrade.
        assembly {
            tstore(0, true)
        }
    }

    /// @inheritdoc UUPSUpgradeable
    ///
    /// @dev The uprade is authorized by reading transient storage.
    /// @dev Transient storage is reset.
    function _authorizeUpgrade(address) internal virtual override {
        bool canUpgrade;
        assembly {
            canUpgrade := tload(0)
            tstore(0, false)
        }

        require(canUpgrade, UpgradeNotAllowed());
    }
}
