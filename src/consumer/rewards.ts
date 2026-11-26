import { type Hex, isHex } from "../bytes.js";
import { ErrorCode, fail } from "../errors.js";
import type { FlopReceiptRootModel } from "../format/receiptRoot.js";
import { jobIdOf } from "../format/jobId.js";
import { type Settlement, leafOf } from "../format/settlement.js";
import { type CallContext, requireChain } from "./context.js";
import type { ReceiptJobHookModel } from "./hook.js";

/**
 * How several Settled leaves of one channel in one epoch are counted. The
 * intended unit is open (flop-receipt-root issue #4, question 3), so it is a
 * switch:
 *
 * - `per-leaf-sum`: every leaf is spent once and its amount is added.
 *   Right if amounts are per event.
 * - `latest-per-channel`: only the latest leaf of a (channel, epoch) counts,
 *   ordered by (settledBlock, eventIndex). A later leaf tops the credit up to
 *   its own amount. Right if amounts are cumulative.
 */
export type DedupeMode = "per-leaf-sum" | "latest-per-channel";
export const DEDUPE_MODES: readonly DedupeMode[] = ["per-leaf-sum", "latest-per-channel"];

/** Which settlement field is credited. Also open (issue #4, question 2). */
export type RewardMetric = "minerPaid" | "aggregateGn";

export interface RewardsParams {
  readonly evmChainId: bigint;
  readonly poolId: Hex;
  readonly mode: DedupeMode;
  readonly metric: RewardMetric;
  /** Epoch `e` stays claimable while `lastEpoch <= e + claimWindowEpochs`. */
  readonly claimWindowEpochs: bigint;
}

export interface RewardClaim {
  readonly leaf: Hex;
  readonly credit: bigint;
  readonly channelEpochTotal: bigint;
}

interface Latest {
  readonly settledBlock: bigint;
  readonly eventIndex: bigint;
  readonly amount: bigint;
  readonly agent: Hex;
}

const key = (channelId: Hex, epoch: bigint) => `${channelId}:${epoch}`;

/** AgentRewards (IF-F11) as a consumer of FlopReceiptRoot and the hook's pool binding. */
export class AgentRewardsConsumerModel {
  readonly params: RewardsParams;
  readonly #roots: FlopReceiptRootModel;
  readonly #hook: ReceiptJobHookModel;
  readonly #spent = new Set<Hex>();
  readonly #latest = new Map<string, Latest>();
  readonly #total = new Map<string, bigint>();
  readonly #credited = new Map<Hex, bigint>();

  constructor(roots: FlopReceiptRootModel, hook: ReceiptJobHookModel, params: RewardsParams) {
    if (!isHex(params.poolId, 32)) fail(ErrorCode.INVALID_INPUT, "poolId must be bytes32");
    if (!DEDUPE_MODES.includes(params.mode)) fail(ErrorCode.INVALID_INPUT, `unknown mode ${String(params.mode)}`);
    if (params.metric !== "minerPaid" && params.metric !== "aggregateGn") fail(ErrorCode.INVALID_INPUT, "unknown metric");
    if (typeof params.claimWindowEpochs !== "bigint" || params.claimWindowEpochs < 0n) fail(ErrorCode.INVALID_INPUT, "claimWindowEpochs >= 0");
    if (hook.params.evmChainId !== params.evmChainId) fail(ErrorCode.INVALID_INPUT, "hook is bound to another chain");
    this.#roots = roots;
    this.#hook = hook;
    this.params = params;
  }

  claim(ctx: CallContext, epoch: bigint, s: Settlement, proof: readonly Hex[]): RewardClaim {
    requireChain(ctx, this.params.evmChainId);
    if (!this.#roots.verify(epoch, s, proof)) fail(ErrorCode.ProofRejected, `settlement not proven in epoch ${epoch}`);
    const leaf = leafOf(s);
    const jobId = jobIdOf(s);
    if (this.#hook.poolOf(jobId) !== this.params.poolId) fail(ErrorCode.NotBoundToPool, `job ${jobId} is not bound to pool ${this.params.poolId}`);
    if (this.#roots.lastEpoch > epoch + this.params.claimWindowEpochs) fail(ErrorCode.EpochExpired, `epoch ${epoch} closed at ${this.#roots.lastEpoch}`);
    if (this.#spent.has(leaf)) fail(ErrorCode.LeafSpent, `leaf ${leaf} already claimed`);

    const k = key(s.channelId, epoch);
    const amount = s[this.params.metric];
    const total = this.#total.get(k) ?? 0n;
    let credit = amount;
    if (this.params.mode === "latest-per-channel") {
      const prev = this.#latest.get(k);
      if (prev !== undefined) {
        if (s.agent !== prev.agent) fail(ErrorCode.AgentChanged, "channel agent changed within the epoch");
        const later = s.settledBlock > prev.settledBlock || (s.settledBlock === prev.settledBlock && s.eventIndex > prev.eventIndex);
        if (!later) fail(ErrorCode.StaleLeaf, `(${s.settledBlock}, ${s.eventIndex}) is not after (${prev.settledBlock}, ${prev.eventIndex})`);
        if (amount < prev.amount) fail(ErrorCode.AmountDecreased, `${amount} < ${prev.amount}`);
        credit = amount - prev.amount;
      }
      this.#latest.set(k, { settledBlock: s.settledBlock, eventIndex: s.eventIndex, amount, agent: s.agent });
    }
    this.#spent.add(leaf);
    this.#total.set(k, total + credit);
    this.#credited.set(s.agent, (this.#credited.get(s.agent) ?? 0n) + credit);
    return { leaf, credit, channelEpochTotal: total + credit };
  }

  isSpent(leaf: Hex): boolean {
    return this.#spent.has(leaf);
  }

  channelEpochTotal(channelId: Hex, epoch: bigint): bigint {
    return this.#total.get(key(channelId, epoch)) ?? 0n;
  }

  creditedTo(agent: Hex): bigint {
    return this.#credited.get(agent) ?? 0n;
  }

  totalCredited(): bigint {
    let t = 0n;
    for (const v of this.#credited.values()) t += v;
    return t;
  }
}
