import { type Hex, U128_MAX, ZERO32, isHex } from "./bytes.js";
import { ErrorCode, fail } from "./errors.js";
import { type ReceiptClaim, verifyReceipt } from "./receipt.js";
import type { RootRegistry } from "./registry.js";
import { type Payouts, reclaimEligible, waterfall } from "./settlement.js";

/** Same choice as Flop's `triggerPolicy`, applied to the reclaim path only. */
export type ReclaimPolicy = "channel-parties" | "anyone";

export interface MinterParams {
  /** N: FLOP blocks without a newer finalized state before a channel is stale. >= 1. */
  readonly stalenessBlocks: bigint;
  /** W: challenge window in FLOP blocks. >= 1. */
  readonly challengeWindowBlocks: bigint;
  readonly reclaimPolicy: ReclaimPolicy;
}

/** OMER locked on the EVM against one FLOP channel. The lock is the escrow. */
export interface LockInput {
  readonly lockId: Hex;
  readonly channelId: Hex;
  readonly provider: Hex;
  readonly payer: Hex;
  readonly lender: Hex;
  /** L: lender/pool principal, repaid before the payer. */
  readonly lenderPrincipal: bigint;
  /** D: the payer's own OMER, first-loss. */
  readonly payerDeposit: bigint;
}

export type LockStatus = "Locked" | "Redeemed" | "Reclaimed";

export interface Settlement extends Payouts {
  readonly path: "redeem" | "reclaim";
  readonly by: Hex;
  readonly jobId: Hex;
  readonly epoch: bigint;
  readonly nonce: bigint;
  readonly owed: bigint;
}

export interface LockView extends LockInput {
  /** E = L + D. */
  readonly escrow: bigint;
  readonly status: LockStatus;
  readonly settlement: Settlement | null;
}

/**
 * Model of OmerMinter redemption (IF-F12) as a TCLK-shaped deal:
 *
 * - redeem (served): the provider presents a spend receipt from any accepted
 *   root, at any time while the lock is open, including after the timeout.
 * - reclaim (unserved): once the latest accepted root shows the channel's
 *   latest state is at least `N + W` FLOP blocks old, a refund becomes eligible.
 * - first included terminal transition wins. The loser fails with ALREADY_SETTLED.
 *
 * Both paths pay the Flop waterfall over the receipt's cumulative owed, so the
 * provider is paid first on either path and nothing is minted.
 */
export class OmerMinterModel {
  readonly #registry: RootRegistry;
  readonly params: MinterParams;
  readonly #locks = new Map<Hex, LockView>();
  readonly #byChannel = new Map<Hex, Hex>();

  constructor(registry: RootRegistry, params: MinterParams) {
    for (const k of ["stalenessBlocks", "challengeWindowBlocks"] as const) {
      if (typeof params[k] !== "bigint" || params[k] < 1n) fail(ErrorCode.INVALID_PARAMS, `${k} must be a bigint >= 1`);
    }
    if (params.reclaimPolicy !== "channel-parties" && params.reclaimPolicy !== "anyone") {
      fail(ErrorCode.INVALID_PARAMS, "unknown reclaimPolicy");
    }
    this.#registry = registry;
    this.params = params;
  }

  open(input: LockInput): LockView {
    for (const k of ["lockId", "channelId", "provider", "payer", "lender"] as const) {
      if (!isHex(input[k], 32) || input[k] === ZERO32) fail(ErrorCode.INVALID_INPUT, `${k} must be non-zero 32-byte hex`);
    }
    if (input.payer === input.provider) fail(ErrorCode.INVALID_INPUT, "payer and provider must differ");
    for (const k of ["lenderPrincipal", "payerDeposit"] as const) {
      if (typeof input[k] !== "bigint" || input[k] < 0n) fail(ErrorCode.INVALID_INPUT, `${k} must be a bigint >= 0`);
    }
    const escrow = input.lenderPrincipal + input.payerDeposit;
    if (escrow > U128_MAX) fail(ErrorCode.INVALID_INPUT, "escrow exceeds uint128");
    if (this.#locks.has(input.lockId)) fail(ErrorCode.DUPLICATE_LOCK, `lock ${input.lockId} exists`);
    if (this.#byChannel.has(input.channelId)) fail(ErrorCode.DUPLICATE_LOCK, `channel ${input.channelId} already backs a lock`);
    const view: LockView = { ...input, escrow, status: "Locked", settlement: null };
    this.#locks.set(input.lockId, view);
    this.#byChannel.set(input.channelId, input.lockId);
    return view;
  }

  lock(lockId: Hex): LockView | undefined {
    return this.#locks.get(lockId);
  }

  /** Served path: TCLK "claim with an accepted preimage". */
  redeem(lockId: Hex, claim: ReceiptClaim, by: Hex): Settlement {
    const lock = this.#open(lockId);
    if (by !== lock.provider) fail(ErrorCode.UNAUTHORIZED, "only the provider redeems; it chooses which receipt to cash");
    const c = verifyReceipt(this.#registry, claim);
    this.#bind(lock, claim);
    if (claim.leaf.nonce === 0n || claim.leaf.cumulativeOwed === 0n) fail(ErrorCode.NOT_SERVED, "receipt shows no spend");
    return this.#settle(lock, "redeem", by, claim, c.epoch);
  }

  /** Unserved path: TCLK "refund after the deadline", here N + W stale FLOP blocks. */
  reclaim(lockId: Hex, claim: ReceiptClaim, by: Hex): Settlement {
    const lock = this.#open(lockId);
    if (this.params.reclaimPolicy === "channel-parties" && by !== lock.payer && by !== lock.lender && by !== lock.provider) {
      fail(ErrorCode.UNAUTHORIZED, "caller is not a channel party");
    }
    const c = verifyReceipt(this.#registry, claim);
    if (claim.jobId !== this.#registry.latestJobId()) fail(ErrorCode.STALE_ROOT, "reclaim must prove against the latest accepted root");
    this.#bind(lock, claim);
    const { stalenessBlocks: n, challengeWindowBlocks: w } = this.params;
    if (!reclaimEligible(c.checkpointHeight, claim.leaf.finalizedHeight, n, w)) {
      fail(ErrorCode.TIMEOUT_NOT_REACHED, `checkpoint ${c.checkpointHeight} < ${claim.leaf.finalizedHeight} + ${n} + ${w}`);
    }
    return this.#settle(lock, "reclaim", by, claim, c.epoch);
  }

  #open(lockId: Hex): LockView {
    const lock = this.#locks.get(lockId);
    if (lock === undefined) fail(ErrorCode.UNKNOWN_LOCK, `lock ${lockId} not found`);
    if (lock.status !== "Locked") fail(ErrorCode.ALREADY_SETTLED, `lock ${lockId} is ${lock.status}`);
    return lock;
  }

  #bind(lock: LockView, { leaf }: ReceiptClaim): void {
    if (leaf.channelId !== lock.channelId) fail(ErrorCode.CHANNEL_MISMATCH, "receipt is for another channel");
    if (leaf.provider !== lock.provider || leaf.payer !== lock.payer) fail(ErrorCode.PARTY_MISMATCH, "receipt parties differ from the lock");
    if (leaf.escrow !== lock.escrow) fail(ErrorCode.ESCROW_MISMATCH, "receipt escrow differs from the lock");
  }

  #settle(lock: LockView, path: Settlement["path"], by: Hex, claim: ReceiptClaim, epoch: bigint): Settlement {
    const payouts = waterfall(lock.escrow, lock.lenderPrincipal, claim.leaf.cumulativeOwed);
    const settlement: Settlement = {
      ...payouts,
      path,
      by,
      jobId: claim.jobId,
      epoch,
      nonce: claim.leaf.nonce,
      owed: claim.leaf.cumulativeOwed,
    };
    this.#locks.set(lock.lockId, { ...lock, status: path === "redeem" ? "Redeemed" : "Reclaimed", settlement });
    return settlement;
  }
}
