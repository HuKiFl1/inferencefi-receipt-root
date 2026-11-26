import { type Hex, U128_MAX, ZERO32, isHex } from "../bytes.js";
import { ErrorCode, fail } from "../errors.js";
import type { FlopReceiptRootModel } from "../format/receiptRoot.js";
import { type Settlement, leafOf } from "../format/settlement.js";
import { type CallContext, requireAddress, requireChain } from "./context.js";
import { type Payouts, earliestReclaimHeight, waterfall } from "./waterfall.js";

export type ReclaimPolicy = "channel-parties" | "anyone";

export interface MinterParams {
  readonly evmChainId: bigint;
  /** Flop `N`: blocks without progress before a channel is stale. */
  readonly stalenessBlocks: bigint;
  /** Flop `W`: challenge window blocks. */
  readonly challengeWindowBlocks: bigint;
  readonly reclaimPolicy: ReclaimPolicy;
}

/**
 * One OMER lock backing one Flop compute channel. `agent`/`miner` are the
 * channel's Flop keys as they appear in its Settled leaf; `payer`,
 * `provider`, `lender` are EVM addresses (the key-to-address mapping is an
 * open question).
 */
export interface LockInput {
  readonly lockId: Hex;
  readonly channelId: Hex;
  readonly agent: Hex;
  readonly miner: Hex;
  readonly modelHash: Hex;
  readonly payer: Hex;
  readonly provider: Hex;
  readonly lender: Hex;
  readonly lenderPrincipal: bigint;
  readonly payerDeposit: bigint;
  /** OMER base units owed per G_n of the Settled leaf: `owed = aggregateGn · num / den` (floor). */
  readonly omerPerGnNum: bigint;
  readonly omerPerGnDen: bigint;
  /** Only settlements at or after this Flop block count, so one finished before the lock cannot redeem it. */
  readonly minFlopBlock: bigint;
}

export type LockStatus = "Locked" | "Redeemed" | "Reclaimed";

export interface Settled extends Payouts {
  readonly lockId: Hex;
  readonly path: "redeem" | "reclaim";
  readonly owed: bigint;
  readonly epoch: bigint;
  /** Leaf hash for a redeem; zero for a reclaim (nothing in the root proves it). */
  readonly leaf: Hex;
}

export interface UnservedFacts {
  /** Height of the channel's last finalized state on Flop (`latest(c).h`). */
  readonly lastFinalizedHeight: bigint;
  /** OMER the provider is owed by that state; 0 if it was never served. */
  readonly owed: bigint;
}

/**
 * The missing piece for reclaim. A Settled-only root cannot show that a
 * channel was NOT served: no leaf proves an absence. Something else has to
 * attest "as of epoch e's checkpoint, channel c has no Settled event and its
 * last finalized state is (h, owed)". Candidates are listed in DESIGN.md §6.
 */
export interface UnservedAttestor {
  verifyUnserved(genesis: Hex, channelId: Hex, epoch: bigint, attestation: Hex): UnservedFacts;
}

/** STUB. No such attestation exists yet, so reclaim fails closed. */
export const UNSERVED_ATTESTOR_STUB: UnservedAttestor = {
  verifyUnserved() {
    fail(ErrorCode.UnservedProofUnavailable, "no completeness / unserved attestation exists for flop-receipt-root v0.3.2");
  },
};

interface Lock extends LockInput {
  status: LockStatus;
}

/**
 * OmerMinter (IF-F12) as a consumer. Redeem is proven by a Settled leaf in any
 * accepted epoch. Reclaim needs an UnservedAttestor and the latest root, and
 * opens at `lastFinalizedHeight + N + W`. TCLK race rule: whichever terminal
 * call lands first settles the lock; a served redeem still wins after the
 * timeout until a reclaim is included. It computes payouts; it moves no tokens.
 */
export class OmerMinterConsumerModel {
  readonly params: MinterParams;
  readonly #roots: FlopReceiptRootModel;
  readonly #attestor: UnservedAttestor;
  readonly #locks = new Map<Hex, Lock>();
  readonly #byChannel = new Map<Hex, Hex>();

  constructor(roots: FlopReceiptRootModel, attestor: UnservedAttestor, params: MinterParams) {
    for (const k of ["stalenessBlocks", "challengeWindowBlocks"] as const) {
      if (typeof params[k] !== "bigint" || params[k] < 1n) fail(ErrorCode.INVALID_INPUT, `${k} must be >= 1`);
    }
    if (params.reclaimPolicy !== "channel-parties" && params.reclaimPolicy !== "anyone") fail(ErrorCode.INVALID_INPUT, "unknown reclaimPolicy");
    this.#roots = roots;
    this.#attestor = attestor;
    this.params = params;
  }

  open(ctx: CallContext, input: LockInput): void {
    requireChain(ctx, this.params.evmChainId);
    for (const k of ["lockId", "channelId", "agent", "miner", "modelHash"] as const) {
      if (!isHex(input[k], 32) || input[k] === ZERO32) fail(ErrorCode.BadLock, `${k} must be non-zero bytes32`);
    }
    for (const k of ["payer", "provider", "lender"] as const) {
      try {
        requireAddress(input[k], k);
      } catch {
        fail(ErrorCode.BadLock, `${k} must be a non-zero address`);
      }
    }
    if (input.payer === input.provider) fail(ErrorCode.BadLock, "payer and provider must differ");
    for (const k of ["lenderPrincipal", "payerDeposit", "omerPerGnNum", "omerPerGnDen", "minFlopBlock"] as const) {
      if (typeof input[k] !== "bigint" || input[k] < 0n || input[k] > U128_MAX) fail(ErrorCode.BadLock, `${k} must fit uint128`);
    }
    if (input.omerPerGnDen === 0n) fail(ErrorCode.BadLock, "omerPerGnDen must be > 0");
    if (input.lenderPrincipal + input.payerDeposit > U128_MAX) fail(ErrorCode.BadLock, "escrow exceeds uint128");
    if (this.#locks.has(input.lockId) || this.#byChannel.has(input.channelId)) fail(ErrorCode.DuplicateLock, "lock id or channel already used");
    this.#locks.set(input.lockId, { ...input, status: "Locked" });
    this.#byChannel.set(input.channelId, input.lockId);
  }

  status(lockId: Hex): LockStatus | undefined {
    return this.#locks.get(lockId)?.status;
  }

  #openLock(ctx: CallContext, lockId: Hex): Lock {
    requireChain(ctx, this.params.evmChainId);
    const lock = this.#locks.get(lockId);
    if (lock === undefined) fail(ErrorCode.UnknownLock, `lock ${lockId}`);
    if (lock.status !== "Locked") fail(ErrorCode.AlreadySettled, `lock ${lockId} is ${lock.status}`);
    return lock;
  }

  #settle(lock: Lock, path: Settled["path"], owed: bigint, epoch: bigint, leaf: Hex): Settled {
    const p = waterfall(lock.lenderPrincipal + lock.payerDeposit, lock.lenderPrincipal, owed);
    lock.status = path === "redeem" ? "Redeemed" : "Reclaimed";
    return { lockId: lock.lockId, path, owed, epoch, leaf, ...p };
  }

  /** Provider only. Any accepted epoch. Allowed at any time while the lock is open, including after the timeout. */
  redeem(ctx: CallContext, lockId: Hex, epoch: bigint, s: Settlement, proof: readonly Hex[]): Settled {
    const lock = this.#openLock(ctx, lockId);
    if (ctx.caller !== lock.provider) fail(ErrorCode.Unauthorized, "only the provider redeems");
    if (s.channelId !== lock.channelId) fail(ErrorCode.ChannelMismatch, "settlement is for another channel");
    if (s.agent !== lock.agent || s.miner !== lock.miner) fail(ErrorCode.PartyMismatch, "settlement parties differ from the lock");
    if (s.modelHash !== lock.modelHash) fail(ErrorCode.ModelMismatch, "settlement is for another model");
    if (s.settledBlock < lock.minFlopBlock) fail(ErrorCode.SettlementTooOld, `settled at ${s.settledBlock} < ${lock.minFlopBlock}`);
    if (s.aggregateGn === 0n) fail(ErrorCode.NotServed, "settlement carries no compute");
    if (!this.#roots.verify(epoch, s, proof)) fail(ErrorCode.ProofRejected, `settlement not proven in epoch ${epoch}`);
    const owed = (s.aggregateGn * lock.omerPerGnNum) / lock.omerPerGnDen;
    return this.#settle(lock, "redeem", owed, epoch, leafOf(s));
  }

  /** Unserved escrow back to lender and payer after `lastFinalizedHeight + N + W`, against the latest root only. */
  reclaim(ctx: CallContext, lockId: Hex, epoch: bigint, attestation: Hex): Settled {
    const lock = this.#openLock(ctx, lockId);
    if (this.params.reclaimPolicy === "channel-parties" && ![lock.payer, lock.lender, lock.provider].includes(ctx.caller)) {
      fail(ErrorCode.Unauthorized, "caller is not a channel party");
    }
    if (this.#roots.frozen) fail(ErrorCode.RootsFrozen, "receipt root contract is frozen");
    const latest = this.#roots.lastEpoch;
    if (latest === 0n || epoch !== latest) fail(ErrorCode.StaleRoot, `reclaim must use the latest epoch ${latest}`);
    const facts = this.#attestor.verifyUnserved(this.#roots.genesis, lock.channelId, epoch, attestation);
    const checkpoint = this.#roots.epochs(epoch)!.toBlock;
    const opensAt = earliestReclaimHeight(facts.lastFinalizedHeight, this.params.stalenessBlocks, this.params.challengeWindowBlocks);
    if (checkpoint < opensAt) fail(ErrorCode.TimeoutNotReached, `checkpoint ${checkpoint} < ${opensAt}`);
    return this.#settle(lock, "reclaim", facts.owed, epoch, ZERO32);
  }
}
