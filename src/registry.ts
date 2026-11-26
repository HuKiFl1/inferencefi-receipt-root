import type { Hex } from "./bytes.js";
import { isHex } from "./bytes.js";
import {
  EMPTY_BLAKE_ROOT,
  EMPTY_KECCAK_ROOT,
  type RootCommitment,
  checkpointOf,
  jobIdOf,
  validateCommitment,
} from "./commitment.js";
import { ErrorCode, fail } from "./errors.js";
import { type ReceiptDomain, sameDomain, validateDomain } from "./leaf.js";

export interface RegistryParams {
  readonly domain: ReceiptDomain;
  readonly hook: Hex;
  /** FLOP finalized heights per epoch. Must be >= 1. */
  readonly epochLength: bigint;
}

/**
 * Model of the EVM root registry the hook, AgentRewards and OmerMinter read.
 * Rules: one immutable root per epoch, epochs strictly increasing (gaps allowed),
 * checkpoint pinned to the epoch's last FLOP finalized height, and an attester
 * check that the caller evaluates (a k-of-n signature check on chain).
 */
export class RootRegistry {
  readonly params: RegistryParams;
  readonly #byJobId = new Map<Hex, RootCommitment>();
  readonly #byEpoch = new Map<bigint, Hex>();
  #latest: Hex | null = null;

  constructor(params: RegistryParams) {
    validateDomain(params.domain);
    if (!isHex(params.hook, 20)) fail(ErrorCode.INVALID_PARAMS, "hook must be a 20-byte address");
    if (typeof params.epochLength !== "bigint" || params.epochLength < 1n) fail(ErrorCode.INVALID_PARAMS, "epochLength must be >= 1");
    this.params = params;
  }

  /** Accepts an attested commitment and returns its jobId. Atomic: a rejection changes nothing. */
  accept(c: RootCommitment, attested: boolean): Hex {
    if (!attested) fail(ErrorCode.UNAUTHORIZED_ATTESTER, "commitment lacks the attester threshold");
    validateCommitment(c);
    if (!sameDomain(c, this.params.domain) || c.hook !== this.params.hook) {
      fail(ErrorCode.DOMAIN_MISMATCH, "commitment is for another chain, pool, hook or FLOP network");
    }
    if (this.#byEpoch.has(c.epoch)) fail(ErrorCode.ROOT_EXISTS, `epoch ${c.epoch} already has a root`);
    const latest = this.latest();
    if (latest !== null && c.epoch < latest.epoch) fail(ErrorCode.EPOCH_REGRESSION, `epoch ${c.epoch} < latest ${latest.epoch}`);
    if (c.checkpointHeight !== checkpointOf(c.epoch, this.params.epochLength)) {
      fail(ErrorCode.CHECKPOINT_MISMATCH, `checkpoint ${c.checkpointHeight} is not the end of epoch ${c.epoch}`);
    }
    const consistent =
      c.leafCount === 0n
        ? c.keccakRoot === EMPTY_KECCAK_ROOT && c.blakeRoot === EMPTY_BLAKE_ROOT
        : c.keccakRoot !== EMPTY_KECCAK_ROOT && c.blakeRoot !== EMPTY_BLAKE_ROOT;
    if (!consistent) {
      fail(ErrorCode.EMPTY_ROOT_MISMATCH, "leafCount 0 if and only if both roots are the empty roots");
    }
    const id = jobIdOf(c);
    this.#byJobId.set(id, c);
    this.#byEpoch.set(c.epoch, id);
    this.#latest = id;
    return id;
  }

  byJobId(jobId: Hex): RootCommitment | undefined {
    return this.#byJobId.get(jobId);
  }

  jobIdAt(epoch: bigint): Hex | undefined {
    return this.#byEpoch.get(epoch);
  }

  latestJobId(): Hex | null {
    return this.#latest;
  }

  latest(): RootCommitment | null {
    return this.#latest === null ? null : this.#byJobId.get(this.#latest)!;
  }
}
