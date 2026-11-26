// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IUnservedAttestor} from "./IUnservedAttestor.sol";

/// @notice STUB. There is no completeness or unserved-channel attestation for flop-receipt-root
///         v0.3.2 yet (issue #4, question 1), so every reclaim fails closed. Replace before any use.
contract UnservedAttestorStub is IUnservedAttestor {
    error UnservedProofUnavailable();

    function verifyUnserved(bytes32, bytes32, uint64, bytes calldata) external pure returns (uint64, uint128) {
        revert UnservedProofUnavailable();
    }
}
