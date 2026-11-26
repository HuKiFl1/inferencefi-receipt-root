// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice The missing piece for reclaim. A Settled-only receipt root cannot show that a channel was
///         NOT served: no leaf proves an absence. An implementation must attest, for `genesis` and
///         the checkpoint of `epoch`, that `channelId` has no Settled event and that its last
///         finalized Flop state is at `lastFinalizedHeight` with `owed` OMER due to the provider.
///         It reverts if it cannot. No such attestation exists for flop-receipt-root v0.3.2.
interface IUnservedAttestor {
    function verifyUnserved(bytes32 genesis, bytes32 channelId, uint64 epoch, bytes calldata attestation)
        external
        view
        returns (uint64 lastFinalizedHeight, uint128 owed);
}
