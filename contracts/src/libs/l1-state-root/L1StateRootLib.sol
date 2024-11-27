// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {EIP4788Lib} from "./EIP4788Lib.sol";
import {L1BlockLib} from "./L1BlockLib.sol";

library L1StateRootLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the generic `L1StateRootProof` has an unsupported type.
    error InvalidProofType(uint8 proofType);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STRUCTURES                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @dev The suported L1 state root proof types.
    enum L1StateRootProofType {
        FromL1Block,
        FromBeaconRoot
    }

    /// @dev An agnostic L1 state root proof.
    struct L1StateRootProof {
        /// @dev The proof type..
        L1StateRootProofType type_;
        /// @dev The proof data to decode.
        bytes data;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Extract the L1 state root (and corresponding timestamp) from a generic L1 state root proof.
    ///
    /// @param proof The generic L1 state root proof.
    function verify(L1StateRootProof memory proof)
        internal
        view
        returns (uint256 l1BlockTimestamp, bytes32 l1StateRoot)
    {
        if (proof.type_ == L1StateRootProofType.FromL1Block) {
            return L1BlockLib.verify(proof.data);
        }

        if (proof.type_ == L1StateRootProofType.FromBeaconRoot) {
            return EIP4788Lib.verify(proof.data);
        }

        revert InvalidProofType(uint8(proof.type_));
    }
}
