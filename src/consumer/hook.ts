import { type Hex, ZERO32, isHex } from "../bytes.js";
import { ErrorCode, fail } from "../errors.js";
import { type HookData, decodeHookData } from "../format/hookData.js";
import type { FlopReceiptRootModel } from "../format/receiptRoot.js";
import { jobIdOf } from "../format/jobId.js";
import { leafOf } from "../format/settlement.js";
import { type CallContext, requireAddress, requireChain } from "./context.js";

export interface PoolConfig {
  readonly poolId: Hex;
  /** Flop model hashes whose settlements count for this pool (e.g. the tier's reference model). */
  readonly modelHashes: readonly Hex[];
}

export interface HookParams {
  readonly evmChainId: bigint;
  /** Only this caller may tag jobs (the v4 PoolManager, in a real hook). */
  readonly poolManager: Hex;
  readonly pools: readonly PoolConfig[];
}

export interface TaggedJob {
  readonly jobId: Hex;
  readonly epoch: bigint;
  readonly poolId: Hex;
}

/**
 * IF-D8 hook mapping on top of FlopReceiptRoot: a swap's hookData is
 * `(epoch, settlement, proof)` and its jobId is the event key
 * `keccak256(abi.encode(TAG, genesis, channelId, settledBlock, eventIndex))`.
 * The leaf hash stays the proof input. The first pool that tags a jobId owns
 * it on this chain; this is where per-pool binding lives, since the leaf
 * names no pool.
 */
export class ReceiptJobHookModel {
  readonly params: HookParams;
  readonly #roots: FlopReceiptRootModel;
  readonly #pools = new Map<Hex, ReadonlySet<Hex>>();
  readonly #poolOf = new Map<Hex, Hex>();
  readonly #epochOf = new Map<Hex, bigint>();

  constructor(roots: FlopReceiptRootModel, params: HookParams) {
    requireAddress(params.poolManager, "poolManager");
    for (const p of params.pools) {
      if (!isHex(p.poolId, 32) || p.poolId === ZERO32 || this.#pools.has(p.poolId)) fail(ErrorCode.INVALID_INPUT, `bad or repeated pool ${p.poolId}`);
      if (p.modelHashes.length === 0 || !p.modelHashes.every((m) => isHex(m, 32))) fail(ErrorCode.INVALID_INPUT, `pool ${p.poolId} needs model hashes`);
      this.#pools.set(p.poolId, new Set(p.modelHashes));
    }
    this.#roots = roots;
    this.params = params;
  }

  /** The `beforeSwap` body: verify the receipt, bind its jobId to this pool, return it. */
  tag(ctx: CallContext, poolId: Hex, hookData: Hex | HookData): TaggedJob {
    requireChain(ctx, this.params.evmChainId);
    if (ctx.caller !== this.params.poolManager) fail(ErrorCode.NotPoolManager, `caller ${ctx.caller}`);
    const models = this.#pools.get(poolId);
    if (models === undefined) fail(ErrorCode.UnknownPool, `pool ${poolId}`);
    const d = typeof hookData === "string" ? decodeHookData(hookData) : hookData;
    if (!models.has(d.settlement.modelHash)) fail(ErrorCode.ModelNotInPool, `model ${d.settlement.modelHash} not served by pool ${poolId}`);
    if (!this.#roots.verify(d.epoch, d.settlement, d.proof)) fail(ErrorCode.ProofRejected, `settlement not proven in epoch ${d.epoch}`);
    const jobId = jobIdOf(d.settlement);
    const bound = this.#poolOf.get(jobId);
    if (bound !== undefined && bound !== poolId) fail(ErrorCode.JobBoundElsewhere, `job ${jobId} belongs to pool ${bound}`);
    this.#poolOf.set(jobId, poolId);
    this.#epochOf.set(jobId, d.epoch);
    return { jobId, epoch: d.epoch, poolId };
  }

  poolOf(jobId: Hex): Hex | undefined {
    return this.#poolOf.get(jobId);
  }

  epochOf(jobId: Hex): bigint | undefined {
    return this.#epochOf.get(jobId);
  }
}
