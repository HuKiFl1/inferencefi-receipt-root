import { type Hex, isHex } from "../bytes.js";
import { ErrorCode, fail } from "../errors.js";
import { MAX_PROOF, buildTree, proofFor, processProof, EMPTY_ROOT } from "./merkle.js";
import { type RootMsg, digest712, validateRootMsg } from "./rootmsg.js";
import { type Settlement, leafOf, validateSettlement } from "./settlement.js";

export interface EpochRecord {
  readonly root: Hex;
  readonly fromBlock: bigint;
  readonly toBlock: bigint;
  readonly count: bigint;
}

export interface ReceiptRootParams {
  readonly genesis: Hex;
  readonly startBlock: bigint;
  /** EVM chain the contract is deployed on (part of the EIP-712 domain). */
  readonly chainId: bigint;
  readonly verifyingContract: Hex;
}

/**
 * State-machine model of FlopReceiptRoot v0.3.2. It applies `submit`'s checks
 * in the contract's order. Signature recovery is abstracted to `quorum`: the
 * Solidity side signs for real. `verify` is a view that never throws on bad
 * input, as the contract's.
 */
export class FlopReceiptRootModel {
  readonly params: ReceiptRootParams;
  readonly #epochs = new Map<bigint, EpochRecord>();
  #lastEpoch = 0n;
  #nextFromBlock: bigint;
  #frozen = false;

  constructor(params: ReceiptRootParams) {
    if (!isHex(params.genesis, 32) || !isHex(params.verifyingContract, 20)) fail(ErrorCode.INVALID_INPUT, "bad genesis or contract");
    this.params = params;
    this.#nextFromBlock = params.startBlock;
  }

  get genesis(): Hex {
    return this.params.genesis;
  }
  get lastEpoch(): bigint {
    return this.#lastEpoch;
  }
  get nextFromBlock(): bigint {
    return this.#nextFromBlock;
  }
  get frozen(): boolean {
    return this.#frozen;
  }

  epochs(epoch: bigint): EpochRecord | undefined {
    return this.#epochs.get(epoch);
  }

  digest(m: RootMsg): Hex {
    return digest712(m, this.params.chainId, this.params.verifyingContract);
  }

  submit(m: RootMsg, quorum: boolean): void {
    validateRootMsg(m);
    if (this.#frozen) fail(ErrorCode.IsFrozen, "contract is frozen");
    if (m.genesis !== this.params.genesis) fail(ErrorCode.WrongGenesis, `genesis ${m.genesis}`);
    if (m.epoch !== this.#lastEpoch + 1n) fail(ErrorCode.WrongEpoch, `epoch ${m.epoch}, want ${this.#lastEpoch + 1n}`);
    if (m.fromBlock !== this.#nextFromBlock) fail(ErrorCode.WrongFromBlock, `fromBlock ${m.fromBlock}, want ${this.#nextFromBlock}`);
    if (m.toBlock < m.fromBlock) fail(ErrorCode.BadRange, `${m.fromBlock}..${m.toBlock}`);
    if ((m.count === 0n) !== (m.root === EMPTY_ROOT)) fail(ErrorCode.EmptyRoot, `count ${m.count} with root ${m.root}`);
    if (!quorum) fail(ErrorCode.BelowThreshold, "no attester quorum");
    this.#epochs.set(m.epoch, { root: m.root, fromBlock: m.fromBlock, toBlock: m.toBlock, count: m.count });
    this.#lastEpoch = m.epoch;
    this.#nextFromBlock = m.toBlock + 1n;
  }

  /** Two quorum-signed, different messages for one epoch freeze the contract for good. */
  freeze(a: RootMsg, quorumA: boolean, b: RootMsg, quorumB: boolean): void {
    if (this.#frozen) fail(ErrorCode.IsFrozen, "contract is frozen");
    if (a.epoch !== b.epoch || this.digest(a) === this.digest(b)) fail(ErrorCode.NotEquivocation, "not two different messages for one epoch");
    if (!quorumA || !quorumB) fail(ErrorCode.BelowThreshold, "no attester quorum");
    this.#frozen = true;
  }

  verify(epoch: bigint, s: Settlement, proof: readonly Hex[]): boolean {
    if (this.#frozen || proof.length > MAX_PROOF) return false;
    const e = this.#epochs.get(epoch);
    if (e === undefined || e.root === EMPTY_ROOT || s.genesis !== this.params.genesis) return false;
    if (s.settledBlock < e.fromBlock || s.settledBlock > e.toBlock) return false;
    try {
      return processProof(leafOf(s), proof) === e.root;
    } catch {
      return false;
    }
  }
}

export interface EpochItem {
  readonly settlement: Settlement;
  readonly leaf: Hex;
  readonly proof: readonly Hex[];
}

export interface BuiltEpoch {
  readonly msg: RootMsg;
  readonly items: readonly EpochItem[];
}

export interface EpochInput {
  readonly genesis: Hex;
  readonly epoch: bigint;
  readonly fromBlock: bigint;
  readonly toBlock: bigint;
  readonly toBlockHash: Hex;
  readonly settlements: readonly Settlement[];
}

/**
 * Builds one epoch the way the upstream builder does once rows are fetched
 * and cross-checked: one leaf per settlement event, an exact repeat of an
 * event deduped, sorted-pair root. Unlike upstream it also accepts an empty
 * range (count 0, root 0), which the contract allows.
 */
export function buildEpoch(input: EpochInput): BuiltEpoch {
  const seen = new Map<string, Settlement>();
  for (const s of input.settlements) {
    validateSettlement(s);
    if (s.genesis !== input.genesis) fail(ErrorCode.INVALID_INPUT, `settlement for genesis ${s.genesis}`);
    if (s.settledBlock < input.fromBlock || s.settledBlock > input.toBlock) {
      fail(ErrorCode.INVALID_INPUT, `settlement at ${s.settledBlock} outside ${input.fromBlock}..${input.toBlock}`);
    }
    const key = `${s.channelId}:${s.settledBlock}:${s.eventIndex}`;
    const prev = seen.get(key);
    if (prev !== undefined && leafOf(prev) !== leafOf(s)) fail(ErrorCode.INVALID_INPUT, `two different settlements for event ${key}`);
    seen.set(key, s);
  }
  const settlements = [...seen.values()];
  const leaves = settlements.map(leafOf);
  const msgBase = { genesis: input.genesis, epoch: input.epoch, fromBlock: input.fromBlock, toBlock: input.toBlock, toBlockHash: input.toBlockHash };
  if (leaves.length === 0) return { msg: { ...msgBase, count: 0n, root: EMPTY_ROOT }, items: [] };
  const tree = buildTree(leaves);
  return {
    msg: { ...msgBase, count: BigInt(leaves.length), root: tree.root },
    items: settlements.map((s, i) => ({ settlement: s, leaf: leaves[i]!, proof: proofFor(tree, leaves[i]!) })),
  };
}
