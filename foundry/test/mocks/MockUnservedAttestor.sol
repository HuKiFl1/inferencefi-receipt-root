// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IUnservedAttestor} from "../../src/IUnservedAttestor.sol";

/// @notice TEST ONLY. Returns whatever facts the test set; trusts its caller completely.
contract MockUnservedAttestor is IUnservedAttestor {
    struct Facts {
        uint64 lastFinalizedHeight;
        uint128 owed;
        bool set;
    }

    bytes32 public immutable GENESIS;
    mapping(bytes32 channelId => mapping(uint64 epoch => Facts)) public facts;

    error AttestationMismatch();

    constructor(bytes32 genesis) {
        GENESIS = genesis;
    }

    function set(bytes32 channelId, uint64 epoch, uint64 lastFinalizedHeight, uint128 owed) external {
        facts[channelId][epoch] = Facts(lastFinalizedHeight, owed, true);
    }

    function verifyUnserved(bytes32 genesis, bytes32 channelId, uint64 epoch, bytes calldata)
        external
        view
        returns (uint64, uint128)
    {
        Facts memory f = facts[channelId][epoch];
        if (genesis != GENESIS || !f.set) revert AttestationMismatch();
        return (f.lastFinalizedHeight, f.owed);
    }
}
