import { type Hex, ZERO32 } from "./bytes.js";
import { nullifierOf } from "./commitment.js";
import { ErrorCode, fail } from "./errors.js";
import { type ReceiptClaim, verifyReceipt } from "./receipt.js";
import type { RootRegistry } from "./registry.js";

const min = (a: bigint, b: bigint): bigint => (a < b ? a : b);

export interface RewardsParams {
  /**
   * A receipt for epoch `e` is claimable while the registry's latest epoch is
   * at most `e + claimWindowEpochs`. 0 means "only while e is the latest root".
   */
  readonly claimWindowEpochs: bigint;
}

/** Last credited state per channel: the AgentRewards analogue of Flop's `latest(c)`. */
export interface CreditedState {
  readonly nonce: bigint;
  readonly cumulativeOwed: bigint;
  readonly stateRoot: Hex;
  readonly epoch: bigint;
  readonly provider: Hex;
  readonly payer: Hex;
  readonly escrow: bigint;
}

export interface RewardCredit {
  readonly channelId: Hex;
  readonly epoch: bigint;
  readonly nullifier: Hex;
  /** Newly credited escrow-backed spend: `min(owed, E) − min(lastOwed, E)`. Overrun earns nothing. */
  readonly credit: bigint;
  readonly payer: Hex;
  readonly provider: Hex;
}

/**
 * Model of AgentRewards (IF-F11): each receipt is checked once per epoch and is
 * bound to its epoch. Dedup uses a nullifier set keyed by (domain, channel, epoch).
 * Credits are deltas of cumulative owed, so missing an epoch loses nothing and
 * re-presenting an older state earns nothing.
 */
export class AgentRewardsModel {
  readonly #registry: RootRegistry;
  readonly #params: RewardsParams;
  readonly #spent = new Set<Hex>();
  readonly #credited = new Map<Hex, CreditedState>();
  #total = 0n;

  constructor(registry: RootRegistry, params: RewardsParams) {
    if (typeof params.claimWindowEpochs !== "bigint" || params.claimWindowEpochs < 0n) {
      fail(ErrorCode.INVALID_PARAMS, "claimWindowEpochs must be a bigint >= 0");
    }
    this.#registry = registry;
    this.#params = params;
  }

  /** Atomic: every check runs before any state changes. */
  claim(claim: ReceiptClaim): RewardCredit {
    const c = verifyReceipt(this.#registry, claim);
    const { leaf } = claim;
    const latest = this.#registry.latest()!;
    if (latest.epoch > c.epoch + this.#params.claimWindowEpochs) {
      fail(ErrorCode.EPOCH_EXPIRED, `epoch ${c.epoch} closed; latest is ${latest.epoch}`);
    }
    const nullifier = nullifierOf(leaf);
    if (this.#spent.has(nullifier)) fail(ErrorCode.NULLIFIER_SPENT, `channel ${leaf.channelId} already claimed for epoch ${leaf.epoch}`);

    const last = this.#credited.get(leaf.channelId);
    if (last !== undefined) {
      if (leaf.provider !== last.provider || leaf.payer !== last.payer) fail(ErrorCode.PARTY_MISMATCH, "channel parties changed");
      if (leaf.escrow !== last.escrow) fail(ErrorCode.ESCROW_MISMATCH, "channel escrow changed");
    }
    const lastNonce = last?.nonce ?? 0n;
    const lastOwed = last?.cumulativeOwed ?? 0n;
    const lastRoot = last?.stateRoot ?? ZERO32;
    if (leaf.nonce < lastNonce) fail(ErrorCode.STALE_NONCE, `nonce ${leaf.nonce} < credited ${lastNonce}`);
    if (leaf.nonce === lastNonce) {
      if (leaf.cumulativeOwed === lastOwed && leaf.stateRoot === lastRoot) {
        fail(ErrorCode.STATE_REPLAYED, `nonce ${leaf.nonce} already credited`);
      }
      fail(ErrorCode.CONFLICTING_STATE, `nonce ${leaf.nonce} credited with different content`);
    }
    if (leaf.cumulativeOwed < lastOwed) fail(ErrorCode.OWED_DECREASED, `owed ${leaf.cumulativeOwed} < credited ${lastOwed}`);

    const credit = min(leaf.cumulativeOwed, leaf.escrow) - min(lastOwed, leaf.escrow);
    this.#spent.add(nullifier);
    this.#credited.set(leaf.channelId, {
      nonce: leaf.nonce,
      cumulativeOwed: leaf.cumulativeOwed,
      stateRoot: leaf.stateRoot,
      epoch: leaf.epoch,
      provider: leaf.provider,
      payer: leaf.payer,
      escrow: leaf.escrow,
    });
    this.#total += credit;
    return { channelId: leaf.channelId, epoch: leaf.epoch, nullifier, credit, payer: leaf.payer, provider: leaf.provider };
  }

  isSpent(nullifier: Hex): boolean {
    return this.#spent.has(nullifier);
  }

  credited(channelId: Hex): CreditedState | undefined {
    return this.#credited.get(channelId);
  }

  totalCredited(): bigint {
    return this.#total;
  }
}

/**
 * The gas-cheaper alternative: one bit per (epoch, leaf index), 256 per word,
 * as a Solidity `mapping(uint64 => mapping(uint256 => uint256))` would store it.
 * Safe only if each root lists a channel at most once, which a verifier cannot
 * check from one proof. Kept to show why the default is the nullifier set.
 */
export class EpochClaimBitmap {
  readonly #words = new Map<string, bigint>();

  static locate(index: bigint): { word: bigint; mask: bigint } {
    if (index < 0n) fail(ErrorCode.INVALID_INPUT, "index must be >= 0");
    return { word: index >> 8n, mask: 1n << (index & 255n) };
  }

  isClaimed(epoch: bigint, index: bigint): boolean {
    const { word, mask } = EpochClaimBitmap.locate(index);
    return ((this.#words.get(`${epoch}:${word}`) ?? 0n) & mask) !== 0n;
  }

  setClaimed(epoch: bigint, index: bigint): void {
    const { word, mask } = EpochClaimBitmap.locate(index);
    if (this.isClaimed(epoch, index)) fail(ErrorCode.NULLIFIER_SPENT, `epoch ${epoch} index ${index} already claimed`);
    const key = `${epoch}:${word}`;
    this.#words.set(key, (this.#words.get(key) ?? 0n) | mask);
  }
}
