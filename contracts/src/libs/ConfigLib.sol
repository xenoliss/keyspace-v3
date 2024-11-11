// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

library ConfigLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the provided `configHash` does not match the recomputed `recomputedConfigHash`.
    ///
    /// @param configHash The expected config hash.
    /// @param recomputedConfigHash The recomputed config hash.
    error InvalidConfig(bytes32 configHash, bytes32 recomputedConfigHash);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STRUCTURES                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @dev A Keystore config.
    struct Config {
        /// @dev The nonce associated with the Keystore record.
        uint256 nonce;
        /// @dev The Keystore record authentication data.
        //       NOTE: Wallet implementors are free to put any data here, including binding commitments
        //             if the data gets too big to be fully provided.
        bytes data;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures that the provided `config` hash to `configHash`.
    ///
    /// @dev Reverts if the parameters hashes do not match.
    ///
    /// @param configHash The Keystore config hash.
    /// @param config The Keystore config.
    function verify(bytes32 configHash, Config calldata config) internal pure {
        // Ensure the recomputed config hash matches witht the given `configHash` parameter.
        bytes32 recomputedConfigHash = hash(config);

        require(
            recomputedConfigHash == configHash,
            InvalidConfig({configHash: configHash, recomputedConfigHash: recomputedConfigHash})
        );
    }

    /// @notice Computed the hash of the provided `config`.
    ///
    /// @param config The Keystore config.
    ///
    /// @return The corresponding config hash.
    function hash(Config calldata config) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(config.nonce, config.data));
    }
}
