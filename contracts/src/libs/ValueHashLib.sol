// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

/// @dev The preimages of a ValueHash stored in a Keystore record.
struct ValueHashPreimages {
    /// @dev The address of the controller responsible for authorizing updates.
    address controller;
    /// @dev The nonce associated with the Keystore record.
    uint96 nonce;
    /// @dev The Keystore record authentication data.
    //       NOTE: Wallet implementors are free to put any data here, including binding commitments
    //             if the data gets too big to be fully provided.
    bytes data;
}

library ValueHashLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the provided `valueHash` does not match the recomputed `valueHashFromPreimages`.
    ///
    /// @param valueHash The original ValueHash of the Keystore record.
    /// @param valueHashFromPreimages The recomputed ValueHash from the provided preimages.
    error RecordValueMismatch(bytes32 valueHash, bytes32 valueHashFromPreimages);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures that the provided `preimages` hash to `valueHash`.
    ///
    /// @dev Reverts if the parameters hashes do not match.
    ///
    /// @param preimages The value hash preimages.
    /// @param valueHash The Keystore record value hash.
    function verify(ValueHashPreimages calldata preimages, bytes32 valueHash) internal pure {
        // Ensure the recomputed ValueHash matches witht the given valueHash` parameter.
        bytes32 valueHashFromPreimages = hash(preimages);

        require(
            valueHashFromPreimages == valueHash,
            RecordValueMismatch({valueHash: valueHash, valueHashFromPreimages: valueHashFromPreimages})
        );
    }

    /// @notice Computed the ValueHash for the provided `preimages`.
    ///
    /// @param preimages The value hash preimages.
    ///
    /// @return The corresponding ValueHash.
    function hash(ValueHashPreimages calldata preimages) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(preimages.controller, preimages.nonce, preimages.data));
    }
}
