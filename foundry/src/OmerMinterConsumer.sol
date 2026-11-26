// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {FlopReceiptRoot} from "flop-receipt-root/FlopReceiptRoot.sol";
import {IUnservedAttestor} from "./IUnservedAttestor.sol";

/// @title OmerMinterConsumer (reference, IF-F12)
/// @notice One OMER lock per Flop compute channel, settled exactly once:
///         - redeem: the provider proves a Settled leaf of the lock's channel in any accepted epoch;
///         - reclaim: after `lastFinalizedHeight + N + W`, against the latest root only, with an
///           IUnservedAttestor statement, because a Settled-only root cannot prove "unserved".
///         TCLK: whichever terminal call is included first wins; a served redeem still wins after the
///         timeout until a reclaim lands. Payouts follow the Flop waterfall (provider owed, then
///         lender principal, then payer).
/// @dev Computes payouts; moves no tokens. Reference only: not audited, not deployed.
contract OmerMinterConsumer {
    enum ReclaimPolicy {
        ChannelParties,
        Anyone
    }

    enum Status {
        None,
        Locked,
        Redeemed,
        Reclaimed
    }

    struct LockInput {
        bytes32 lockId;
        bytes32 channelId;
        bytes32 agent;
        bytes32 miner;
        bytes32 modelHash;
        address payer;
        address provider;
        address lender;
        uint128 lenderPrincipal;
        uint128 payerDeposit;
        uint128 omerPerGnNum;
        uint128 omerPerGnDen;
        uint128 minFlopBlock;
    }

    struct Payout {
        uint256 owed;
        uint256 toProvider;
        uint256 toLender;
        uint256 toPayer;
        uint256 overrun;
        uint256 lenderShortfall;
    }

    FlopReceiptRoot public immutable ROOTS;
    IUnservedAttestor public immutable ATTESTOR;
    uint256 public immutable EVM_CHAIN_ID;
    /// @notice Flop `N`: blocks without progress before a channel is stale.
    uint64 public immutable STALENESS_BLOCKS;
    /// @notice Flop `W`: challenge window.
    uint64 public immutable CHALLENGE_WINDOW_BLOCKS;
    ReclaimPolicy public immutable RECLAIM_POLICY;

    mapping(bytes32 lockId => LockInput) internal _locks;
    mapping(bytes32 lockId => Status) public status;
    mapping(bytes32 channelId => bytes32 lockId) public lockOfChannel;

    event Opened(bytes32 indexed lockId, bytes32 indexed channelId);
    event Redeemed(bytes32 indexed lockId, bytes32 leaf, uint64 epoch, Payout p);
    event Reclaimed(bytes32 indexed lockId, uint64 epoch, Payout p);

    error BadConfig();
    error WrongChain();
    error BadLock();
    error DuplicateLock();
    error UnknownLock();
    error AlreadySettled();
    error Unauthorized();
    error ChannelMismatch();
    error PartyMismatch();
    error ModelMismatch();
    error SettlementTooOld();
    error NotServed();
    error ProofRejected();
    error RootsFrozen();
    error StaleRoot();
    error TimeoutNotReached();

    constructor(
        FlopReceiptRoot roots,
        IUnservedAttestor attestor,
        uint256 evmChainId,
        uint64 stalenessBlocks,
        uint64 challengeWindowBlocks,
        ReclaimPolicy policy
    ) {
        if (address(roots) == address(0) || address(attestor) == address(0)) revert BadConfig();
        if (stalenessBlocks == 0 || challengeWindowBlocks == 0) revert BadConfig();
        ROOTS = roots;
        ATTESTOR = attestor;
        EVM_CHAIN_ID = evmChainId;
        STALENESS_BLOCKS = stalenessBlocks;
        CHALLENGE_WINDOW_BLOCKS = challengeWindowBlocks;
        RECLAIM_POLICY = policy;
    }

    function lockOf(bytes32 lockId) external view returns (LockInput memory) {
        return _locks[lockId];
    }

    function open(LockInput calldata l) external {
        if (block.chainid != EVM_CHAIN_ID) revert WrongChain();
        if (
            l.lockId == 0 || l.channelId == 0 || l.agent == 0 || l.miner == 0 || l.modelHash == 0
                || l.payer == address(0) || l.provider == address(0) || l.lender == address(0) || l.payer == l.provider
                || l.omerPerGnDen == 0 || uint256(l.lenderPrincipal) + l.payerDeposit > type(uint128).max
        ) revert BadLock();
        if (status[l.lockId] != Status.None || lockOfChannel[l.channelId] != 0) revert DuplicateLock();
        _locks[l.lockId] = l;
        status[l.lockId] = Status.Locked;
        lockOfChannel[l.channelId] = l.lockId;
        emit Opened(l.lockId, l.channelId);
    }

    /// @notice Provider only; any accepted epoch; allowed at any time while the lock is open.
    function redeem(bytes32 lockId, uint64 epoch, FlopReceiptRoot.Settlement calldata s, bytes32[] calldata proof)
        external
        returns (Payout memory p)
    {
        LockInput storage l = _open(lockId);
        if (msg.sender != l.provider) revert Unauthorized();
        if (s.channelId != l.channelId) revert ChannelMismatch();
        if (s.agent != l.agent || s.miner != l.miner) revert PartyMismatch();
        if (s.modelHash != l.modelHash) revert ModelMismatch();
        if (s.settledBlock < l.minFlopBlock) revert SettlementTooOld();
        if (s.aggregateGn == 0) revert NotServed();
        if (!ROOTS.verify(epoch, s, proof)) revert ProofRejected();
        p = _settle(lockId, l, (uint256(s.aggregateGn) * l.omerPerGnNum) / l.omerPerGnDen, Status.Redeemed);
        emit Redeemed(lockId, ROOTS.leafOf(s), epoch, p);
    }

    /// @notice Unserved escrow back to lender and payer once the latest root's checkpoint reaches
    ///         `lastFinalizedHeight + N + W`.
    function reclaim(bytes32 lockId, uint64 epoch, bytes calldata attestation) external returns (Payout memory p) {
        LockInput storage l = _open(lockId);
        if (
            RECLAIM_POLICY == ReclaimPolicy.ChannelParties && msg.sender != l.payer && msg.sender != l.lender
                && msg.sender != l.provider
        ) revert Unauthorized();
        if (ROOTS.frozen()) revert RootsFrozen();
        uint64 last = ROOTS.lastEpoch();
        if (last == 0 || epoch != last) revert StaleRoot();
        (uint64 h, uint128 owed) = ATTESTOR.verifyUnserved(ROOTS.GENESIS(), l.channelId, epoch, attestation);
        (, , uint64 checkpoint, ) = ROOTS.epochs(epoch);
        if (uint256(checkpoint) < uint256(h) + STALENESS_BLOCKS + CHALLENGE_WINDOW_BLOCKS) revert TimeoutNotReached();
        p = _settle(lockId, l, owed, Status.Reclaimed);
        emit Reclaimed(lockId, epoch, p);
    }

    function _open(bytes32 lockId) private view returns (LockInput storage l) {
        if (block.chainid != EVM_CHAIN_ID) revert WrongChain();
        Status st = status[lockId];
        if (st == Status.None) revert UnknownLock();
        if (st != Status.Locked) revert AlreadySettled();
        l = _locks[lockId];
    }

    function _settle(bytes32 lockId, LockInput storage l, uint256 owed, Status to) private returns (Payout memory p) {
        uint256 escrow = uint256(l.lenderPrincipal) + l.payerDeposit;
        p.owed = owed;
        p.toProvider = owed < escrow ? owed : escrow;
        uint256 rest = escrow - p.toProvider;
        p.toLender = l.lenderPrincipal < rest ? l.lenderPrincipal : rest;
        p.toPayer = rest - p.toLender;
        p.overrun = owed - p.toProvider;
        p.lenderShortfall = l.lenderPrincipal - p.toLender;
        status[lockId] = to;
    }
}
