// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

library EIP4788Lib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The address of the contract used to fetch beacon roots from the oracle.
    address constant BEACON_ROOTS_ADDRESS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    /// @notice The generalized index of the state root in the beacon state tree.
    uint256 constant EXECUTION_STATE_ROOT_GINDEX = 6434;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the call to fetch the beacon root from the oracle fails.
    ///
    /// @param callData The calldata used in the failed staticcall to the beacon oracle.
    error BeaconRootsOracleCallFailed(bytes callData);

    /// @notice Thrown when the provided beacon root does not match the expected root fetched from the oracle.
    ///
    /// @param expected The expected beacon root.
    /// @param actual The actual beacon root fetched from the oracle.
    error BeaconRootDoesNotMatch(bytes32 expected, bytes32 actual);

    error ExecutionStateRootMerkleProofFailed();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STRUCTURES                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice An L1 state root proof that relies on the `BeaconRoots` contract.
    struct EIP4788Proof {
        /// @dev The beacon root to verify.
        bytes32 beaconRoot;
        /// @dev The timestamp associated with the beacon root.
        uint256 beaconRootTimestamp;
        /// @dev The execution state root to verify.
        bytes32 executionStateRoot;
        /// @dev The Merkle proof for the execution state root.
        bytes32[] executionStateRootProof;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        INTERNAL FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Extract the L1 state root (and corresponding timestamp) from a serialized `EIP4788Proof`.
    ///
    /// @param proof The serialized proof data.
    ///
    /// @return l1BlockTimestamp The timestamp of the beacon root.
    /// @return l1StateRoot The verified execution state root.
    function verify(bytes memory proof) internal view returns (uint256 l1BlockTimestamp, bytes32 l1StateRoot) {
        // Decode the EIP4788Proof proof.
        EIP4788Proof memory eip4788Proof = abi.decode(proof, (EIP4788Proof));

        // Verify the beacon root against the oracle.
        _verifyBeaconRoot({beaconRoot: eip4788Proof.beaconRoot, beaconRootTimestamp: eip4788Proof.beaconRootTimestamp});

        // Verify the execution state root using the provided proof.
        _verifyExecutionRoot({
            beaconRoot: eip4788Proof.beaconRoot,
            executionStateRoot: eip4788Proof.executionStateRoot,
            executionStateRootProof: eip4788Proof.executionStateRootProof
        });

        // Return the verified L1 block timestamp and state root.
        // FIXME: The timestamp might be the timestamp of the previous (parent) block.
        l1BlockTimestamp = eip4788Proof.beaconRootTimestamp;
        l1StateRoot = eip4788Proof.executionStateRoot;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Verifies that a given beacon root matches the one fetched from the oracle for the specified timestamp.
    ///
    /// @param beaconRoot The beacon root to verify.
    /// @param beaconRootTimestamp The timestamp corresponding to the beacon root.
    function _verifyBeaconRoot(bytes32 beaconRoot, uint256 beaconRootTimestamp) private view {
        // Prepare the calldata for the staticcall to the beacon oracle.
        bytes memory calldata_ = abi.encode(beaconRootTimestamp);

        // Perform a staticcall to fetch the beacon root from the oracle.
        (bool success, bytes memory result) = BEACON_ROOTS_ADDRESS.staticcall(calldata_);
        require(success, BeaconRootsOracleCallFailed(calldata_));

        // Ensure the fetched root matches the provided beacon root.
        bytes32 resultRoot = abi.decode(result, (bytes32));
        require(resultRoot == beaconRoot, BeaconRootDoesNotMatch({expected: beaconRoot, actual: resultRoot}));
    }

    /// @notice Verifies the execution state root against the beacon root using a Merkle proof.
    ///
    /// @param beaconRoot The beacon root that anchors the proof.
    /// @param executionStateRoot The execution state root to verify.
    /// @param executionStateRootProof The Merkle proof for the execution state root.
    function _verifyExecutionRoot(
        bytes32 beaconRoot,
        bytes32 executionStateRoot,
        bytes32[] memory executionStateRootProof
    ) private view {
        require(
            _verifyProof({
                proof: executionStateRootProof,
                root: beaconRoot,
                leaf: executionStateRoot,
                index: EXECUTION_STATE_ROOT_GINDEX
            }),
            ExecutionStateRootMerkleProofFailed()
        );
    }

    /// @dev Implementation updated to work with a `memory` proof, taken from
    ///      https://github.com/madlabman/eip-4788-proof/blob/20ec51c3215214a3aa61e1281d4be90c48ede3c9/src/SSZ.sol#L247
    function _verifyProof(bytes32[] memory proof, bytes32 root, bytes32 leaf, uint256 index)
        private
        view
        returns (bool isValid)
    {
        // TODO: verify that the implementation is still valid given the changes made to work with an in memory proof.

        assembly ("memory-safe") {
            let proofLen := mload(proof)

            if proofLen {
                // Initialize `offset` to point to the first proof element in memory.
                let offset := add(proof, 0x20)
                // Left shift by 5 is equivalent to multiplying by 0x20.
                let end := add(offset, shl(5, proofLen))
                // Iterate over proof elements to compute root hash.
                for {} 1 {} {
                    // Slot of `leaf` in scratch space.
                    // If the condition is true: 0x20, otherwise: 0x00.
                    let scratch := shl(5, and(index, 1))
                    index := shr(1, index)
                    if iszero(index) {
                        // revert BranchHasExtraItem()
                        mstore(0x00, 0x5849603f)
                        revert(0x1c, 0x04)
                    }
                    // Store elements to hash contiguously in scratch space.
                    // Scratch space is 64 bytes (0x00 - 0x3f) and both elements are 32 bytes.
                    mstore(scratch, leaf)
                    mstore(xor(scratch, 0x20), mload(offset))
                    // Call sha256 precompile
                    let result := staticcall(gas(), 0x02, 0x00, 0x40, 0x00, 0x20)

                    if eq(result, 0) { revert(0, 0) }

                    // Reuse `leaf` to store the hash to reduce stack operations.
                    leaf := mload(0x00)
                    offset := add(offset, 0x20)
                    if iszero(lt(offset, end)) { break }
                }
            }

            // index != 1
            if gt(sub(index, 1), 0) {
                // revert BranchHasMissingItem()
                mstore(0x00, 0x1b6661c3)
                revert(0x1c, 0x04)
            }
            isValid := eq(leaf, root)
        }
    }
}
