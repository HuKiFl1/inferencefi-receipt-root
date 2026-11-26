// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {FlopReceiptRoot} from "flop-receipt-root/FlopReceiptRoot.sol";
import {ReceiptJobHook} from "./ReceiptJobHook.sol";

/// @title AgentRewardsConsumer (reference, IF-F11)
/// @notice Credits agents for Settled leaves proven against FlopReceiptRoot and tagged to this
///         consumer's pool by the hook. Each leaf hash is spent once. How several leaves of one
///         (channel, epoch) add up is open (flop-receipt-root issue #4), so it is a constructor switch:
///         - PerLeafSum: every leaf adds its amount (amounts are per event).
///         - LatestPerChannel: only the latest leaf by (settledBlock, eventIndex) counts; a later leaf
///           tops the credit up to its own amount (amounts are cumulative).
/// @dev Records credits; moves no tokens. Reference only: not audited, not deployed.
contract AgentRewardsConsumer {
    enum DedupeMode {
        PerLeafSum,
        LatestPerChannel
    }

    enum RewardMetric {
        MinerPaid,
        AggregateGn
    }

    struct Latest {
        uint64 settledBlock;
        uint32 eventIndex;
        uint128 amount;
        bytes32 agent;
        bool set;
    }

    FlopReceiptRoot public immutable ROOTS;
    ReceiptJobHook public immutable HOOK;
    uint256 public immutable EVM_CHAIN_ID;
    bytes32 public immutable POOL_ID;
    DedupeMode public immutable MODE;
    RewardMetric public immutable METRIC;
    /// @notice Epoch `e` stays claimable while `lastEpoch <= e + CLAIM_WINDOW_EPOCHS`.
    uint64 public immutable CLAIM_WINDOW_EPOCHS;

    mapping(bytes32 leaf => bool) public isSpent;
    mapping(bytes32 channelId => mapping(uint64 epoch => Latest)) public latest;
    mapping(bytes32 channelId => mapping(uint64 epoch => uint256)) public channelEpochTotal;
    mapping(bytes32 agent => uint256) public creditedTo;
    uint256 public totalCredited;

    event Credited(bytes32 indexed leaf, bytes32 indexed agent, bytes32 indexed channelId, uint64 epoch, uint256 credit);

    error BadConfig();
    error WrongChain();
    error ProofRejected();
    error NotBoundToPool();
    error EpochExpired();
    error LeafSpent();
    error AgentChanged();
    error StaleLeaf();
    error AmountDecreased();

    constructor(
        FlopReceiptRoot roots,
        ReceiptJobHook hook,
        uint256 evmChainId,
        bytes32 poolId,
        DedupeMode mode,
        RewardMetric metric,
        uint64 claimWindowEpochs
    ) {
        if (address(roots) == address(0) || address(hook.ROOTS()) != address(roots) || hook.EVM_CHAIN_ID() != evmChainId) {
            revert BadConfig();
        }
        if (!hook.isPool(poolId)) revert BadConfig();
        ROOTS = roots;
        HOOK = hook;
        EVM_CHAIN_ID = evmChainId;
        POOL_ID = poolId;
        MODE = mode;
        METRIC = metric;
        CLAIM_WINDOW_EPOCHS = claimWindowEpochs;
    }

    function claim(uint64 epoch, FlopReceiptRoot.Settlement calldata s, bytes32[] calldata proof)
        external
        returns (uint256 credit, uint256 total)
    {
        if (block.chainid != EVM_CHAIN_ID) revert WrongChain();
        if (!ROOTS.verify(epoch, s, proof)) revert ProofRejected();
        bytes32 leaf = ROOTS.leafOf(s);
        if (HOOK.poolOf(HOOK.jobIdOf(s)) != POOL_ID) revert NotBoundToPool();
        if (uint256(ROOTS.lastEpoch()) > uint256(epoch) + CLAIM_WINDOW_EPOCHS) revert EpochExpired();
        if (isSpent[leaf]) revert LeafSpent();

        uint128 amount = METRIC == RewardMetric.MinerPaid ? s.minerPaid : s.aggregateGn;
        credit = amount;
        if (MODE == DedupeMode.LatestPerChannel) {
            Latest storage prev = latest[s.channelId][epoch];
            if (prev.set) {
                if (s.agent != prev.agent) revert AgentChanged();
                bool later = s.settledBlock > prev.settledBlock
                    || (s.settledBlock == prev.settledBlock && s.eventIndex > prev.eventIndex);
                if (!later) revert StaleLeaf();
                if (amount < prev.amount) revert AmountDecreased();
                credit = amount - prev.amount;
            }
            latest[s.channelId][epoch] =
                Latest({settledBlock: s.settledBlock, eventIndex: s.eventIndex, amount: amount, agent: s.agent, set: true});
        }
        isSpent[leaf] = true;
        total = channelEpochTotal[s.channelId][epoch] + credit;
        channelEpochTotal[s.channelId][epoch] = total;
        creditedTo[s.agent] += credit;
        totalCredited += credit;
        emit Credited(leaf, s.agent, s.channelId, epoch, credit);
    }
}
