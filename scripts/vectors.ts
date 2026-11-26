/**
 * Deterministic IF-D8 vectors in the flop-receipt-root v0.3.2 format.
 * Every expected outcome below is written by hand; `buildVectors` throws if a
 * model disagrees, so the JSON is a specification, not a recording.
 * All identifiers are synthetic labels.
 */
import {
  AgentRewardsConsumerModel,
  type BuiltEpoch,
  type CallContext,
  ErrorCode,
  FlopReceiptRootModel,
  type Hex,
  LEAF_TYPE,
  LEAF_TYPEHASH,
  type LockInput,
  MAX_PROOF,
  OMER_UNIT,
  OmerMinterConsumerModel,
  ROOT_TYPE,
  ROOT_TYPEHASH,
  ReceiptJobHookModel,
  type RootMsg,
  type Settled,
  type Settlement,
  type UnservedAttestor,
  type UnservedFacts,
  U64_MAX,
  U128_MAX,
  UNSERVED_ATTESTOR_STUB,
  ZERO32,
  buildEpoch,
  buildTree,
  bytesToHex,
  decodeHookData,
  digest712,
  domainSeparator,
  encodeHookData,
  encodeSettlement,
  fail,
  hexToBytes,
  isReceiptRootError,
  keccak256,
  jobIdOf,
  JOB_ID_TAG,
  JOB_ID_TAG_STRING,
  leafOf,
  pairHash,
  processProof,
  proofFor,
  settlementToJson,
  utf8,
  verifyRawProof,
} from "../src/index.js";

export const label = (s: string): Hex => bytesToHex(keccak256(utf8(`inferencefi-receipt-root/v2/test/${s}`)));
export const address = (s: string): Hex => `0x${label(s).slice(-40)}`;

export const GENESIS = label("flop-genesis");
export const EVM_CHAIN_ID = 998n;
export const ROOTS_ADDRESS = address("flop-receipt-root");
export const START_BLOCK = 1_000n;
export const POOL_A = label("pool/A");
export const POOL_B = label("pool/B");
export const MODEL_X = label("model/X");
export const MODEL_Y = label("model/Y");
export const MODEL_Z = label("model/Z");
export const POOL_MANAGER = address("pool-manager");
export const N = 100n;
export const W = 20n;
export const CLAIM_WINDOW = 1n;

export interface SettleOpts {
  readonly ch: string;
  readonly block: bigint;
  readonly idx?: bigint;
  readonly agent?: string;
  readonly miner?: string;
  readonly model?: Hex;
  readonly gn?: bigint;
  readonly paid?: bigint;
  readonly burned?: bigint;
  readonly escrow?: bigint;
}

export function settle(o: SettleOpts): Settlement {
  return {
    genesis: GENESIS,
    channelId: label(`channel/${o.ch}`),
    settledBlock: o.block,
    settledBlockHash: label(`block/${o.block}`),
    eventIndex: o.idx ?? 0n,
    agent: label(`agent/${o.agent ?? o.ch}`),
    miner: label(`miner/${o.miner ?? o.ch}`),
    modelHash: o.model ?? MODEL_X,
    aggregateGn: o.gn ?? 1_000n,
    minerPaid: o.paid ?? 100n,
    burned: o.burned ?? 0n,
    escrow: o.escrow ?? 10_000n,
  };
}

// ---------------------------------------------------------------- JSON helpers

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

function toJson(v: unknown): Json {
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error(`cannot serialize number ${v}`);
    return v;
  }
  if (v === undefined || v === null) return null;
  if (typeof v === "boolean" || typeof v === "string") return v;
  if (Array.isArray(v)) return v.map(toJson);
  if (typeof v === "object") {
    const out: { [k: string]: Json } = {};
    for (const [k, x] of Object.entries(v as object)) if (x !== undefined) out[k] = toJson(x);
    return out;
  }
  throw new Error(`cannot serialize ${typeof v}`);
}

function expectEqual(what: string, got: unknown, want: unknown): void {
  const g = JSON.stringify(toJson(got));
  const w = JSON.stringify(toJson(want));
  if (g !== w) throw new Error(`vector expectation failed: ${what}\n  got:  ${g}\n  want: ${w}`);
}

function outcome(fn: () => void): string {
  try {
    fn();
    return "OK";
  } catch (e) {
    if (isReceiptRootError(e)) return e.code;
    throw e;
  }
}

/** Solidity error signatures, so Foundry can compare the 4-byte selector of a revert. */
const ERROR_SIGNATURES: Record<string, string> = {
  IsFrozen: "IsFrozen()",
  WrongGenesis: "WrongGenesis(bytes32)",
  WrongEpoch: "WrongEpoch(uint64,uint64)",
  WrongFromBlock: "WrongFromBlock(uint64,uint64)",
  BadRange: "BadRange(uint64,uint64)",
  EmptyRoot: "EmptyRoot(uint32)",
  BelowThreshold: "BelowThreshold(uint256,uint256)",
  NotEquivocation: "NotEquivocation()",
};
export function selectorOf(code: string): Hex {
  if (code === "OK") return "0x00000000";
  const sig = ERROR_SIGNATURES[code] ?? `${code}()`;
  return bytesToHex(keccak256(utf8(sig)).subarray(0, 4));
}

const flip = (h: Hex): Hex => `${h.slice(0, -1)}${h.endsWith("0") ? "1" : "0"}` as Hex;

// ---------------------------------------------------------------- static sections

function leafVectors() {
  const boundary: Settlement = {
    ...settle({ ch: "boundary", block: U64_MAX, idx: (1n << 32n) - 1n }),
    aggregateGn: U128_MAX,
    minerPaid: U128_MAX,
    burned: U128_MAX,
    escrow: U128_MAX,
  };
  const cases: { name: string; s: Settlement }[] = [
    { name: "typical", s: settle({ ch: "enc-1", block: 1_234n, idx: 3n, gn: 198_487n, paid: 42_500_000_000_000_000n, escrow: 50_000_000_000_000_000n }) },
    { name: "zero-amounts", s: settle({ ch: "enc-2", block: 0n, gn: 0n, paid: 0n, escrow: 0n }) },
    { name: "force-settled-with-burn", s: settle({ ch: "enc-3", block: 7n, paid: 10n, burned: 90n, escrow: 100n }) },
    { name: "uint-boundaries", s: boundary },
  ];
  return cases.map((c) => ({ name: c.name, settlement: settlementToJson(c.s), encoding: bytesToHex(encodeSettlement(c.s)), leaf: leafOf(c.s) }));
}

function treeVectors() {
  return [1, 2, 3, 4, 5, 7, 8, 9, 17].map((n) => {
    const settlements = Array.from({ length: n }, (_, i) => settle({ ch: `tree-${n}-${i}`, block: 1_000n + BigInt(i), gn: BigInt(i + 1) }));
    const leaves = settlements.map(leafOf);
    const tree = buildTree(leaves);
    return {
      name: `n=${n}`,
      settlements: settlements.map(settlementToJson),
      leaves,
      sortedLeaves: tree.layers[0],
      root: tree.root,
      proofs: leaves.map((l) => proofFor(tree, l)),
    };
  });
}

function proofCases() {
  const leaves = Array.from({ length: 7 }, (_, i) => leafOf(settle({ ch: `pc-${i}`, block: 1_000n + BigInt(i) })));
  const tree = buildTree(leaves);
  const other = buildTree(Array.from({ length: 7 }, (_, i) => leafOf(settle({ ch: `pc-other-${i}`, block: 1_000n + BigInt(i) }))));
  const sorted = tree.layers[0]!;
  const l = sorted[2]!;
  const p = proofFor(tree, l);
  const single = buildTree([leaves[0]!]);
  const node = pairHash(sorted[0]!, sorted[1]!);
  const nodeProof = proofFor(tree, sorted[0]!).slice(1);
  const preimage = `0x${sorted[0]!.slice(2)}${sorted[1]!.slice(2)}` as Hex;
  const preimageDoubleHashed = bytesToHex(keccak256(keccak256(hexToBytes(preimage))));
  const cases = [
    { name: "valid", root: tree.root, leaf: l, proof: p, expect: true },
    { name: "forged-sibling", root: tree.root, leaf: l, proof: [flip(p[0]!), ...p.slice(1)], expect: false },
    { name: "truncated", root: tree.root, leaf: l, proof: p.slice(0, -1), expect: false },
    { name: "extended", root: tree.root, leaf: l, proof: [...p, leaves[0]!], expect: false },
    { name: "reordered", root: tree.root, leaf: l, proof: [p[1]!, p[0]!, ...p.slice(2)], expect: false },
    { name: "other-tree-root", root: other.root, leaf: l, proof: p, expect: false },
    { name: "leaf-not-in-tree", root: tree.root, leaf: other.layers[0]![2]!, proof: p, expect: false },
    { name: "empty-proof-multi-leaf", root: tree.root, leaf: l, proof: [], expect: false },
    { name: "single-leaf-empty-proof", root: single.root, leaf: leaves[0]!, proof: [], expect: true },
    // A 64-byte inner node passes the RAW hash check with the rest of the path.
    // FlopReceiptRoot.verify never takes a raw hash: it computes leafOf(settlement).
    { name: "inner-node-as-raw-leaf", root: tree.root, leaf: node, proof: nodeProof, expect: true },
    // Treating the node's 64-byte preimage as leaf data and double-hashing it, as leafOf does, misses the root.
    { name: "inner-node-preimage-double-hashed", root: tree.root, leaf: preimageDoubleHashed, proof: nodeProof, expect: false },
  ];
  for (const c of cases) expectEqual(`proof case ${c.name}`, verifyRawProof(c.root, c.leaf, c.proof), c.expect);
  return { tree: { leaves, root: tree.root }, nodeAsLeaf: { left: sorted[0]!, right: sorted[1]!, node, preimage }, cases };
}

/**
 * FlopReceiptRoot.verify against quorum-signed roots the tree builder would
 * never produce. Each case is a fresh contract whose first epoch is `msg`.
 */
function verifyCases() {
  const base = { genesis: GENESIS, epoch: 1n, fromBlock: 5_000n, toBlock: 5_999n, toBlockHash: label("block/5999") };
  const sib = (n: number) => Array.from({ length: n }, (_, i) => label(`sibling/${i}`));
  const at = (block: bigint, o: Partial<Settlement> = {}) => ({ ...settle({ ch: `verify-${block}`, block }), ...o });
  const one = (name: string, x: Settlement, proof: readonly Hex[], expect: boolean, o: { verifyEpoch?: bigint; count?: bigint; root?: Hex; verifyProof?: readonly Hex[] } = {}) => {
    const msg: RootMsg = { ...base, count: o.count ?? 1n, root: o.root ?? processProof(leafOf(x), proof) };
    return { name, msg, epoch: o.verifyEpoch ?? 1n, settlement: x, proof: o.verifyProof ?? proof, expect };
  };
  const pairEdge = buildTree([leafOf(at(5_000n)), leafOf(at(5_999n))]);
  const cases = [
    one("proof of exactly MAX_PROOF siblings", at(5_100n), sib(MAX_PROOF), true),
    one("proof of MAX_PROOF + 1 siblings under a signed root", at(5_100n), sib(MAX_PROOF + 1), false),
    one("leaf of another genesis inside a signed root", at(5_100n, { genesis: label("other-genesis") }), sib(2), false),
    one("settled one block before the epoch", at(4_999n), sib(2), false),
    one("settled one block after the epoch", at(6_000n), sib(2), false),
    one("settled on the first block", at(5_000n), proofFor(pairEdge, leafOf(at(5_000n))), true, { count: 2n, root: pairEdge.root }),
    one("settled on the last block", at(5_999n), proofFor(pairEdge, leafOf(at(5_999n))), true, { count: 2n, root: pairEdge.root }),
    one("epoch that was never submitted", at(5_100n), sib(2), false, { verifyEpoch: 2n }),
    one("empty epoch", at(5_100n), [], false, { count: 0n, root: ZERO32 }),
  ];
  for (const c of cases) {
    const m = new FlopReceiptRootModel({ genesis: GENESIS, startBlock: base.fromBlock, chainId: EVM_CHAIN_ID, verifyingContract: ROOTS_ADDRESS });
    m.submit(c.msg, true);
    expectEqual(`verify case ${c.name}`, m.verify(c.epoch, c.settlement, c.proof), c.expect);
  }
  return cases.map((c) => ({ ...c, settlement: settlementToJson(c.settlement), digest: digest712(c.msg, EVM_CHAIN_ID, ROOTS_ADDRESS) }));
}

/** One (epoch, settlement, proof) has exactly one accepted hookData. */
function hookDataCases() {
  const d = { epoch: 7n, settlement: settle({ ch: "hd", block: 1_234n }), proof: [label("p/0"), label("p/1")] };
  const ok = encodeHookData(d);
  const body = ok.slice(2);
  const word = (i: number) => body.slice(64 * i, 64 * (i + 1));
  const words = Array.from({ length: body.length / 64 }, (_, i) => word(i));
  const join = (ws: string[]): Hex => `0x${ws.join("")}`;
  const shifted = [...words.slice(0, 13), (480).toString(16).padStart(64, "0"), "00".repeat(32), ...words.slice(14)];
  const dirty = (i: number) => words.map((w, j) => (j === i ? `01${w.slice(2)}` : w));
  const cases = [
    { name: "canonical", hex: ok, expect: "OK" },
    { name: "trailing zero word", hex: join([...words, "00".repeat(32)]), expect: "BadHookData" },
    { name: "proof offset 480 with a padding word", hex: join(shifted), expect: "BadHookData" },
    { name: "proof offset 480, nothing else changed", hex: join([...words.slice(0, 13), (480).toString(16).padStart(64, "0"), ...words.slice(14)]), expect: "BadHookData" },
    { name: "dirty high bits in epoch", hex: join(dirty(0)), expect: "BadHookData" },
    { name: "dirty high bits in settledBlock", hex: join(dirty(3)), expect: "BadHookData" },
    { name: "proof length larger than the data", hex: join([...words.slice(0, 14), (3).toString(16).padStart(64, "0"), ...words.slice(15)]), expect: "BadHookData" },
    { name: "cut inside the head", hex: join(words.slice(0, 10)), expect: "BadHookData" },
  ];
  for (const c of cases) expectEqual(`hookData case ${c.name}`, outcome(() => decodeHookData(c.hex)), c.expect);
  return { decoded: { ...d, settlement: settlementToJson(d.settlement) }, cases: cases.map((c) => ({ ...c, selector: selectorOf(c.expect) })) };
}

// ---------------------------------------------------------------- scenario

export class MockUnservedAttestor implements UnservedAttestor {
  readonly #facts = new Map<string, UnservedFacts>();
  set(channelId: Hex, epoch: bigint, f: UnservedFacts): void {
    this.#facts.set(`${channelId}:${epoch}`, f);
  }
  verifyUnserved(genesis: Hex, channelId: Hex, epoch: bigint): UnservedFacts {
    const f = this.#facts.get(`${channelId}:${epoch}`);
    if (genesis !== GENESIS || f === undefined) fail(ErrorCode.AttestationMismatch, "no attestation for this channel and epoch");
    return f;
  }
}

type RewardsKey = "sum" | "latest";
type MinterKey = "stub" | "attested";
/** [owed, toProvider, toLender, toPayer, overrun, lenderShortfall] */
type PayoutTuple = readonly [bigint, bigint, bigint, bigint, bigint, bigint];
const tuple = (s: Settled): PayoutTuple => [s.owed, s.toProvider, s.toLender, s.toPayer, s.overrun, s.lenderShortfall];

type Step =
  | { op: "submit"; note: string; msg: RootMsg; quorum: boolean; expect: string }
  | { op: "freeze"; note: string; msgA: RootMsg; msgB: RootMsg; expect: string }
  | { op: "tag"; note: string; chainId: bigint; caller: Hex; poolId: Hex; epoch: bigint; settlement: Settlement; proof: readonly Hex[]; expect: string; jobId?: Hex; rawHookData?: Hex }
  | { op: "claim"; note: string; chainId: bigint; consumer: RewardsKey; epoch: bigint; settlement: Settlement; proof: readonly Hex[]; expect: string; credit?: bigint | undefined; channelEpochTotal?: bigint | undefined }
  | { op: "open"; note: string; chainId: bigint; consumer: MinterKey; lock: LockInput; expect: string }
  | { op: "setUnserved"; note: string; channelId: Hex; epoch: bigint; lastFinalizedHeight: bigint; owed: bigint }
  | { op: "redeem"; note: string; chainId: bigint; caller: Hex; consumer: MinterKey; lockId: Hex; epoch: bigint; settlement: Settlement; proof: readonly Hex[]; expect: string; payouts?: PayoutTuple }
  | { op: "reclaim"; note: string; chainId: bigint; caller: Hex; consumer: MinterKey; lockId: Hex; epoch: bigint; attestation: Hex; expect: string; payouts?: PayoutTuple };

const O = (n: bigint) => n * OMER_UNIT;
const GN_PRICE = 10n ** 15n; // 0.001 OMER per G_n

function lock(name: string, ch: string, o: Partial<LockInput> = {}): LockInput {
  return {
    lockId: label(`lock/${name}`),
    channelId: label(`channel/${ch}`),
    agent: label(`agent/${ch}`),
    miner: label(`miner/${ch}`),
    modelHash: MODEL_X,
    payer: address(`payer/${ch}`),
    provider: address(`provider/${ch}`),
    lender: address(`lender/${ch}`),
    lenderPrincipal: O(3n),
    payerDeposit: O(1n),
    omerPerGnNum: GN_PRICE,
    omerPerGnDen: 1n,
    minFlopBlock: START_BLOCK,
    ...o,
  };
}

function scenario() {
  // Epoch 1: 1000..1999. Epoch 2: 2000..2999. Epoch 3: 3000..3099, empty. Epoch 4: 3100..4999.
  const s = {
    a1: settle({ ch: "C1", block: 1_100n, idx: 0n, paid: 100n }),
    a2: settle({ ch: "C1", block: 1_500n, idx: 2n, paid: 160n }),
    b1: settle({ ch: "C2", block: 1_200n, idx: 1n, paid: 50n }),
    poolB: settle({ ch: "C3", block: 1_300n, model: MODEL_Y, paid: 70n }),
    unpooled: settle({ ch: "C4", block: 1_400n, model: MODEL_Z }),
    served: settle({ ch: "K1", block: 1_700n, gn: 2_000n }),
    early: settle({ ch: "K5", block: 1_250n }),
    zeroGn: settle({ ch: "K6", block: 1_260n, gn: 0n }),
    overrun: settle({ ch: "K7", block: 1_800n, gn: 9_000n }),
    c1e2: settle({ ch: "C1", block: 2_100n, paid: 200n }),
    top1: settle({ ch: "C6", block: 2_500n, idx: 3n, paid: 300n }),
    top2: settle({ ch: "C6", block: 2_500n, idx: 7n, paid: 450n }),
    dec1: settle({ ch: "C7", block: 2_600n, paid: 500n }),
    dec2: settle({ ch: "C7", block: 2_700n, paid: 400n }),
    ag1: settle({ ch: "C8", block: 2_800n, paid: 10n }),
    ag2: settle({ ch: "C8", block: 2_900n, agent: "C8-other", paid: 20n }),
    late: settle({ ch: "K3", block: 3_200n, gn: 500n }),
    refunded: settle({ ch: "K4", block: 3_300n, gn: 500n }),
    k9: settle({ ch: "K9", block: 3_400n, gn: 500n }),
    k10: settle({ ch: "K10", block: 3_500n, gn: 1_000n }),
  };
  const e1 = buildEpoch({ genesis: GENESIS, epoch: 1n, fromBlock: 1_000n, toBlock: 1_999n, toBlockHash: label("block/1999"), settlements: [s.a1, s.a2, s.b1, s.poolB, s.unpooled, s.served, s.early, s.zeroGn, s.overrun] });
  const e2 = buildEpoch({ genesis: GENESIS, epoch: 2n, fromBlock: 2_000n, toBlock: 2_999n, toBlockHash: label("block/2999"), settlements: [s.c1e2, s.top1, s.top2, s.dec1, s.dec2, s.ag1, s.ag2] });
  const e3 = buildEpoch({ genesis: GENESIS, epoch: 3n, fromBlock: 3_000n, toBlock: 3_099n, toBlockHash: label("block/3099"), settlements: [] });
  const e4 = buildEpoch({ genesis: GENESIS, epoch: 4n, fromBlock: 3_100n, toBlock: 4_999n, toBlockHash: label("block/4999"), settlements: [s.late, s.refunded, s.k9, s.k10] });
  const pf = (e: BuiltEpoch, x: Settlement): readonly Hex[] => e.items.find((i) => i.leaf === leafOf(x))!.proof;
  const forged = (e: BuiltEpoch, x: Settlement): Hex[] => [flip(pf(e, x)[0]!), ...pf(e, x).slice(1)];

  const MGR = POOL_MANAGER;
  type TagOpts = { epoch?: bigint; proof?: readonly Hex[]; settlement?: Settlement; caller?: Hex; chainId?: bigint; rawHookData?: Hex };
  const tag = (note: string, poolId: Hex, e: BuiltEpoch, x: Settlement, expect: string, o: TagOpts = {}): Step => ({
    op: "tag",
    note,
    chainId: o.chainId ?? EVM_CHAIN_ID,
    caller: o.caller ?? MGR,
    poolId,
    epoch: o.epoch ?? e.msg.epoch,
    settlement: o.settlement ?? x,
    proof: o.proof ?? pf(e, x),
    expect,
    ...(expect === "OK" ? { jobId: jobIdOf(o.settlement ?? x) } : {}),
    ...(o.rawHookData ? { rawHookData: o.rawHookData } : {}),
  });
  type ClaimOpts = { epoch?: bigint; chainId?: bigint };
  const claim = (note: string, consumer: RewardsKey, e: BuiltEpoch, x: Settlement, expect: string, credit?: bigint, total?: bigint, o: ClaimOpts = {}): Step => ({
    op: "claim",
    note,
    chainId: o.chainId ?? EVM_CHAIN_ID,
    consumer,
    epoch: o.epoch ?? e.msg.epoch,
    settlement: x,
    proof: pf(e, x),
    expect,
    ...(expect === "OK" ? { credit, channelEpochTotal: total } : {}),
  });
  type RedeemOpts = { caller?: Hex; proof?: readonly Hex[] };
  const redeem = (note: string, l: LockInput, e: BuiltEpoch, x: Settlement, expect: string, payouts?: PayoutTuple, o: RedeemOpts = {}): Step => ({
    op: "redeem",
    note,
    chainId: EVM_CHAIN_ID,
    caller: o.caller ?? l.provider,
    consumer: "attested",
    lockId: l.lockId,
    epoch: e.msg.epoch,
    settlement: x,
    proof: o.proof ?? pf(e, x),
    expect,
    ...(payouts ? { payouts } : {}),
  });
  const reclaim = (note: string, consumer: MinterKey, l: LockInput, epoch: bigint, expect: string, payouts?: PayoutTuple, caller: Hex = l.lender): Step => ({
    op: "reclaim",
    note,
    chainId: EVM_CHAIN_ID,
    caller,
    consumer,
    lockId: l.lockId,
    epoch,
    attestation: "0x",
    expect,
    ...(payouts ? { payouts } : {}),
  });

  const K1 = lock("K1", "K1");
  const K2 = lock("K2", "K2");
  const K2s = lock("K2-stub", "K2");
  const K3 = lock("K3", "K3");
  const K4 = lock("K4", "K4");
  const K5 = lock("K5", "K5", { minFlopBlock: 1_600n });
  const K6 = lock("K6", "K6");
  const K7 = lock("K7", "K7");
  const K8 = lock("K8", "C1", { modelHash: MODEL_Y });
  const K9 = lock("K9", "K9");
  const K10 = lock("K10", "K10", { omerPerGnNum: 1n, omerPerGnDen: 3n });

  const steps: Step[] = [
    // ---- roots (FlopReceiptRoot.submit)
    { op: "submit", note: "one signature is below the 2-of-3 threshold", msg: e1.msg, quorum: false, expect: "BelowThreshold" },
    { op: "submit", note: "root for another Flop network", msg: { ...e1.msg, genesis: label("other-genesis") }, quorum: true, expect: "WrongGenesis" },
    { op: "submit", note: "range ends before it starts", msg: { ...e1.msg, toBlock: 999n }, quorum: true, expect: "BadRange" },
    { op: "submit", note: "count 0 with a non-zero root", msg: { ...e1.msg, count: 0n }, quorum: true, expect: "EmptyRoot" },
    { op: "submit", note: "epoch 1", msg: e1.msg, quorum: true, expect: "OK" },
    { op: "submit", note: "epoch 1 replayed", msg: e1.msg, quorum: true, expect: "WrongEpoch" },
    { op: "submit", note: "non-contiguous epoch: 3 before 2", msg: { ...e3.msg, fromBlock: 2_000n }, quorum: true, expect: "WrongEpoch" },
    { op: "submit", note: "epoch 2 leaving a block gap", msg: { ...e2.msg, fromBlock: 2_001n }, quorum: true, expect: "WrongFromBlock" },

    // ---- hook
    tag("only the pool manager may tag", POOL_A, e1, s.a1, "NotPoolManager", { caller: address("stranger") }),
    tag("hook bound to chain 998, called on 999", POOL_A, e1, s.a1, "WrongChain", { chainId: 999n }),
    tag("pool the hook does not serve", label("pool/unknown"), e1, s.a1, "UnknownPool"),
    tag("model outside every pool", POOL_A, e1, s.unpooled, "ModelNotInPool"),
    tag("pool A tags C1@1100", POOL_A, e1, s.a1, "OK"),
    tag("the same job tagged again by pool A", POOL_A, e1, s.a1, "OK"),
    tag("pool B serves model X too, but the job is pool A's", POOL_B, e1, s.a1, "JobBoundElsewhere"),
    tag("pool A tags C1@1500", POOL_A, e1, s.a2, "OK"),
    tag("pool A tags C2@1200", POOL_A, e1, s.b1, "OK"),
    tag("pool B tags C3 (model Y)", POOL_B, e1, s.poolB, "OK"),
    tag("forged proof", POOL_A, e1, s.b1, "ProofRejected", { proof: forged(e1, s.b1) }),
    tag("leaf claims another genesis", POOL_A, e1, s.b1, "ProofRejected", { settlement: { ...s.b1, genesis: label("other-genesis") } }),
    tag("inflated minerPaid under the original proof", POOL_A, e1, s.b1, "ProofRejected", { settlement: { ...s.b1, minerPaid: 5_000n } }),
    tag("proof longer than MAX_PROOF", POOL_A, e1, s.b1, "ProofRejected", { proof: Array.from({ length: MAX_PROOF + 1 }, () => ZERO32) }),
    tag("epoch not accepted yet", POOL_A, e1, s.b1, "ProofRejected", { epoch: 2n }),
    tag("valid receipt in non-canonical hookData (trailing word)", POOL_A, e1, s.b1, "BadHookData", { rawHookData: `${encodeHookData({ epoch: 1n, settlement: s.b1, proof: pf(e1, s.b1) })}${"00".repeat(32)}` }),

    // ---- rewards, both dedupe modes, metric minerPaid, pool A, window 1
    claim("pool B's job in pool A's rewards", "sum", e1, s.poolB, "NotBoundToPool"),
    claim("settlement no pool has tagged", "sum", e1, s.served, "NotBoundToPool"),
    claim("sum: C1@1100", "sum", e1, s.a1, "OK", 100n, 100n),
    claim("sum: the same leaf again (double-claim)", "sum", e1, s.a1, "LeafSpent"),
    claim("sum: C1@1500 adds", "sum", e1, s.a2, "OK", 160n, 260n),
    claim("latest: C1@1500 first", "latest", e1, s.a2, "OK", 160n, 160n),
    claim("latest: the earlier C1@1100 is stale", "latest", e1, s.a1, "StaleLeaf"),
    claim("latest: the same leaf again (double-claim)", "latest", e1, s.a2, "LeafSpent"),
    claim("consumer bound to chain 998, called on 999", "sum", e1, s.b1, "WrongChain", undefined, undefined, { chainId: 999n }),
    { op: "submit", note: "epoch 2", msg: e2.msg, quorum: true, expect: "OK" },
    claim("epoch-1 leaf replayed as epoch 2", "sum", e1, s.b1, "ProofRejected", undefined, undefined, { epoch: 2n }),
    tag("epoch-1 leaf replayed into epoch 2 at the hook", POOL_A, e1, s.b1, "ProofRejected", { epoch: 2n }),
    tag("pool A tags C1@2100", POOL_A, e2, s.c1e2, "OK"),
    tag("pool A tags C6@2500#3", POOL_A, e2, s.top1, "OK"),
    tag("pool A tags C6@2500#7", POOL_A, e2, s.top2, "OK"),
    tag("pool A tags C7@2600", POOL_A, e2, s.dec1, "OK"),
    tag("pool A tags C7@2700", POOL_A, e2, s.dec2, "OK"),
    tag("pool A tags C8@2800", POOL_A, e2, s.ag1, "OK"),
    tag("pool A tags C8@2900", POOL_A, e2, s.ag2, "OK"),
    claim("sum: C1 in epoch 2 is a separate (channel, epoch)", "sum", e2, s.c1e2, "OK", 200n, 200n),
    claim("latest: C1 in epoch 2", "latest", e2, s.c1e2, "OK", 200n, 200n),
    claim("latest: C6 event 3", "latest", e2, s.top1, "OK", 300n, 300n),
    claim("latest: C6 event 7 in the same block tops up", "latest", e2, s.top2, "OK", 150n, 450n),
    claim("sum: C6 event 7", "sum", e2, s.top2, "OK", 450n, 450n),
    claim("sum: C6 event 3, claimed after event 7, still adds", "sum", e2, s.top1, "OK", 300n, 750n),
    claim("latest: C7@2600", "latest", e2, s.dec1, "OK", 500n, 500n),
    claim("latest: C7@2700 pays less than C7@2600", "latest", e2, s.dec2, "AmountDecreased"),
    claim("sum: C7@2600", "sum", e2, s.dec1, "OK", 500n, 500n),
    claim("sum: C7@2700", "sum", e2, s.dec2, "OK", 400n, 900n),
    claim("latest: C8@2800", "latest", e2, s.ag1, "OK", 10n, 10n),
    claim("latest: C8@2900 names another agent", "latest", e2, s.ag2, "AgentChanged"),
    { op: "submit", note: "epoch 3, empty", msg: e3.msg, quorum: true, expect: "OK" },
    claim("epoch 1 closed once epoch 3 is in (window 1)", "sum", e1, s.b1, "EpochExpired"),
    claim("sum: epoch 2 still open", "sum", e2, s.ag1, "OK", 10n, 10n),

    // ---- minter with the stub attestor: no unserved proof exists
    { op: "open", note: "stub minter: lock on K2", chainId: EVM_CHAIN_ID, consumer: "stub", lock: K2s, expect: "OK" },
    reclaim("stub: reclaim of unserved escrow cannot be proven", "stub", K2s, 3n, "UnservedProofUnavailable"),

    // ---- minter with a test attestor
    ...[K1, K2, K3, K4, K5, K6, K7, K8, K9, K10].map((l): Step => ({ op: "open", note: `open ${l.lockId.slice(0, 10)}`, chainId: EVM_CHAIN_ID, consumer: "attested", lock: l, expect: "OK" })),
    { op: "open", note: "a second lock on K1's channel", chainId: EVM_CHAIN_ID, consumer: "attested", lock: { ...K1, lockId: label("lock/K1-dup") }, expect: "DuplicateLock" },
    { op: "open", note: "payer equals provider", chainId: EVM_CHAIN_ID, consumer: "attested", lock: { ...lock("bad", "bad"), provider: address("payer/bad") }, expect: "BadLock" },
    redeem("lock that was never opened", lock("bad", "bad"), e1, s.served, "UnknownLock"),
    redeem("payer cannot redeem", K1, e1, s.served, "Unauthorized", undefined, { caller: K1.payer }),
    redeem("settlement of another channel", K1, e1, s.a1, "ChannelMismatch"),
    redeem("lock expects model Y", K8, e1, s.a1, "ModelMismatch"),
    redeem("settled before the lock's minFlopBlock", K5, e1, s.early, "SettlementTooOld"),
    redeem("settlement with zero compute", K6, e1, s.zeroGn, "NotServed"),
    redeem("forged proof", K1, e1, s.served, "ProofRejected", undefined, { proof: forged(e1, s.served) }),
    redeem("served: 2000 G_n = 2 OMER; provider 2, lender 2 of 3", K1, e1, s.served, "OK", [O(2n), O(2n), O(2n), 0n, 0n, O(1n)]),
    redeem("second redeem", K1, e1, s.served, "AlreadySettled"),
    redeem("overrun: 9 OMER owed against 4 escrowed", K7, e1, s.overrun, "OK", [O(9n), O(4n), 0n, 0n, O(5n), O(3n)]),
    { op: "setUnserved", note: "attest K2 unserved as of epoch 3, last state at 2990", channelId: K2.channelId, epoch: 3n, lastFinalizedHeight: 2_990n, owed: 0n },
    reclaim("3099 < 2990 + 100 + 20", "attested", K2, 3n, "TimeoutNotReached"),
    reclaim("outsider under channel-parties policy", "attested", K2, 3n, "Unauthorized", undefined, address("stranger")),
    reclaim("epoch 2 is not the latest root", "attested", K2, 2n, "StaleRoot"),
    reclaim("no attestation for K3 in epoch 3", "attested", K3, 3n, "AttestationMismatch"),
    { op: "submit", note: "epoch 4", msg: e4.msg, quorum: true, expect: "OK" },
    reclaim("epoch 3 is no longer the latest root", "attested", K2, 3n, "StaleRoot"),
    { op: "setUnserved", note: "attest K2 unserved as of epoch 4, last state at 4880", channelId: K2.channelId, epoch: 4n, lastFinalizedHeight: 4_880n, owed: 0n },
    reclaim("4999 is one block short of 4880 + 100 + 20", "attested", K2, 4n, "TimeoutNotReached"),
    { op: "setUnserved", note: "attest K2 unserved as of epoch 4, last state at 4879", channelId: K2.channelId, epoch: 4n, lastFinalizedHeight: 4_879n, owed: 0n },
    reclaim("unserved exactly at 4879 + 100 + 20 = 4999: lender 3, payer 1", "attested", K2, 4n, "OK", [0n, 0n, O(3n), O(1n), 0n, 0n]),
    redeem("K2 refund included first wins", K2, e1, s.served, "AlreadySettled"),
    { op: "setUnserved", note: "attest K3 unserved (stale view: last state at 1500)", channelId: K3.channelId, epoch: 4n, lastFinalizedHeight: 1_500n, owed: 0n },
    redeem("past the timeout a served redeem still wins until a reclaim is included", K3, e4, s.late, "OK", [O(1n) / 2n, O(1n) / 2n, O(3n), O(1n) / 2n, 0n, 0n]),
    reclaim("K3 claim included first wins", "attested", K3, 4n, "AlreadySettled"),
    { op: "setUnserved", note: "attest K4 stale with 1 OMER owed by its last state", channelId: K4.channelId, epoch: 4n, lastFinalizedHeight: 1_500n, owed: O(1n) },
    reclaim("reclaim pays the attested owed first: provider 1, lender 3", "attested", K4, 4n, "OK", [O(1n), O(1n), O(3n), 0n, 0n, 0n], K4.payer),
    redeem("K4 settled on Flop later, but the refund was included first", K4, e4, s.refunded, "AlreadySettled"),

    redeem("owed rounds down: 1000 G_n at 1/3 base unit is 333", K10, e4, s.k10, "OK", [333n, 333n, O(3n), O(1n) - 333n, 0n, 0n]),
    redeem("settlement names another miner than the lock", K9, e4, { ...s.k9, miner: label("miner/other") }, "PartyMismatch", undefined, { proof: pf(e4, s.k9) }),

    // ---- equivocation freezes the roots; nothing verifies afterwards
    { op: "freeze", note: "the same message twice is not equivocation", msgA: e4.msg, msgB: e4.msg, expect: "NotEquivocation" },
    { op: "freeze", note: "two quorum-signed roots for epoch 4", msgA: e4.msg, msgB: { ...e4.msg, root: label("rival-root") }, expect: "OK" },
    { op: "submit", note: "nothing is accepted after a freeze", msg: { ...e4.msg, epoch: 5n, fromBlock: 5_000n, toBlock: 5_999n }, quorum: true, expect: "IsFrozen" },
    tag("frozen roots verify nothing (hook)", POOL_A, e1, s.b1, "ProofRejected"),
    claim("frozen roots verify nothing (rewards), checked before the spent set", "latest", e2, s.c1e2, "ProofRejected"),
    redeem("frozen roots verify nothing (minter): K9's valid receipt", K9, e4, s.k9, "ProofRejected"),
    reclaim("reclaim stops when the roots are frozen", "attested", K6, 4n, "RootsFrozen"),
  ];

  // ---- run the models and hold them to the expectations above
  const roots = new FlopReceiptRootModel({ genesis: GENESIS, startBlock: START_BLOCK, chainId: EVM_CHAIN_ID, verifyingContract: ROOTS_ADDRESS });
  const hook = new ReceiptJobHookModel(roots, {
    evmChainId: EVM_CHAIN_ID,
    poolManager: MGR,
    pools: [
      { poolId: POOL_A, modelHashes: [MODEL_X] },
      { poolId: POOL_B, modelHashes: [MODEL_X, MODEL_Y] },
    ],
  });
  const rewardsBase = { evmChainId: EVM_CHAIN_ID, poolId: POOL_A, metric: "minerPaid" as const, claimWindowEpochs: CLAIM_WINDOW };
  const rewards = {
    sum: new AgentRewardsConsumerModel(roots, hook, { ...rewardsBase, mode: "per-leaf-sum" }),
    latest: new AgentRewardsConsumerModel(roots, hook, { ...rewardsBase, mode: "latest-per-channel" }),
  };
  const attestor = new MockUnservedAttestor();
  const minterParams = { evmChainId: EVM_CHAIN_ID, stalenessBlocks: N, challengeWindowBlocks: W, reclaimPolicy: "channel-parties" as const };
  const minters = {
    stub: new OmerMinterConsumerModel(roots, UNSERVED_ATTESTOR_STUB, minterParams),
    attested: new OmerMinterConsumerModel(roots, attestor, minterParams),
  };
  const call = (chainId: bigint, caller: Hex = MGR): CallContext => ({ chainId, caller });

  for (const [i, st] of steps.entries()) {
    const what = `scenario step ${i} (${st.note})`;
    switch (st.op) {
      case "submit":
        expectEqual(what, outcome(() => roots.submit(st.msg, st.quorum)), st.expect);
        break;
      case "freeze":
        expectEqual(what, outcome(() => roots.freeze(st.msgA, true, st.msgB, true)), st.expect);
        break;
      case "tag": {
        let job: Hex | undefined;
        expectEqual(what, outcome(() => (job = hook.tag(call(st.chainId, st.caller), st.poolId, st.rawHookData ?? encodeHookData(st)).jobId)), st.expect);
        expectEqual(`${what} jobId`, job, st.jobId);
        break;
      }
      case "claim": {
        let r: { credit: bigint; channelEpochTotal: bigint } | undefined;
        expectEqual(what, outcome(() => (r = rewards[st.consumer].claim(call(st.chainId), st.epoch, st.settlement, st.proof))), st.expect);
        expectEqual(`${what} credit`, r?.credit, st.credit);
        expectEqual(`${what} total`, r?.channelEpochTotal, st.channelEpochTotal);
        break;
      }
      case "open":
        expectEqual(what, outcome(() => minters[st.consumer].open(call(st.chainId), st.lock)), st.expect);
        break;
      case "setUnserved":
        attestor.set(st.channelId, st.epoch, { lastFinalizedHeight: st.lastFinalizedHeight, owed: st.owed });
        break;
      case "redeem": {
        let p: PayoutTuple | undefined;
        expectEqual(what, outcome(() => (p = tuple(minters[st.consumer].redeem(call(st.chainId, st.caller), st.lockId, st.epoch, st.settlement, st.proof)))), st.expect);
        expectEqual(`${what} payouts`, p, st.payouts);
        break;
      }
      case "reclaim": {
        let p: PayoutTuple | undefined;
        expectEqual(what, outcome(() => (p = tuple(minters[st.consumer].reclaim(call(st.chainId, st.caller), st.lockId, st.epoch, st.attestation)))), st.expect);
        expectEqual(`${what} payouts`, p, st.payouts);
        break;
      }
    }
  }
  const totals = { sum: rewards.sum.totalCredited(), latest: rewards.latest.totalCredited() };
  expectEqual("sum total", totals.sum, 100n + 160n + 200n + 450n + 300n + 500n + 400n + 10n);
  expectEqual("latest total", totals.latest, 160n + 200n + 300n + 150n + 500n + 10n);

  const jsonSteps = steps.map((st) => {
    const selector = "expect" in st ? selectorOf(st.expect) : undefined;
    switch (st.op) {
      case "submit":
        return { ...st, selector, digest: digest712(st.msg, EVM_CHAIN_ID, ROOTS_ADDRESS) };
      case "tag":
        return { ...st, selector, settlement: settlementToJson(st.settlement), leaf: leafOf(st.settlement), hookData: st.rawHookData ?? encodeHookData(st), rawHookData: undefined, canonical: st.rawHookData === undefined };
      case "claim":
      case "redeem":
        return { ...st, selector, settlement: settlementToJson(st.settlement), leaf: leafOf(st.settlement) };
      default:
        return { ...st, selector };
    }
  });

  return {
    params: {
      genesis: GENESIS,
      startBlock: START_BLOCK,
      evmChainId: EVM_CHAIN_ID,
      rootsAddress: ROOTS_ADDRESS,
      attesters: 3,
      threshold: 2,
      poolManager: MGR,
      pools: [
        { poolId: POOL_A, modelHashes: [MODEL_X] },
        { poolId: POOL_B, modelHashes: [MODEL_X, MODEL_Y] },
      ],
      rewards: { poolId: POOL_A, metric: "minerPaid", claimWindowEpochs: CLAIM_WINDOW, consumers: { sum: "per-leaf-sum", latest: "latest-per-channel" } },
      minter: { stalenessBlocks: N, challengeWindowBlocks: W, reclaimPolicy: "channel-parties", consumers: { stub: "UnservedAttestorStub", attested: "test-only attestor" } },
    },
    epochs: [e1, e2, e3, e4].map((e) => ({ msg: e.msg, items: e.items.map((it) => ({ settlement: settlementToJson(it.settlement), leaf: it.leaf, proof: it.proof })) })),
    steps: jsonSteps,
    totals,
  };
}


function jobIdCases() {
  const base = settle({ ch: "JK", block: 4_200n, idx: 3n, gn: 11n, paid: 7n, burned: 1n, escrow: 9_000n });
  const sameKey: Settlement = {
    ...base,
    settledBlockHash: label("jk/other-hash"),
    agent: label("jk/other-agent"),
    miner: label("jk/other-miner"),
    modelHash: label("jk/other-model"),
    aggregateGn: base.aggregateGn + 1n,
    minerPaid: base.minerPaid + 9n,
    burned: base.burned + 1n,
    escrow: base.escrow + 1n,
  };
  const otherIndex: Settlement = { ...base, eventIndex: base.eventIndex + 1n };
  const otherBlock: Settlement = { ...base, settledBlock: base.settledBlock + 1n };
  const otherChannel: Settlement = { ...base, channelId: label("jk/other-channel") };
  const otherGenesis: Settlement = { ...base, genesis: label("jk/other-genesis") };
  const cases: { name: string; a: Settlement; b: Settlement; expectEqual: boolean }[] = [
    { name: "same event key, different leaf layout", a: base, b: sameKey, expectEqual: true },
    { name: "different eventIndex", a: base, b: otherIndex, expectEqual: false },
    { name: "different settledBlock", a: base, b: otherBlock, expectEqual: false },
    { name: "different channelId", a: base, b: otherChannel, expectEqual: false },
    { name: "different genesis", a: base, b: otherGenesis, expectEqual: false },
  ];
  for (const c of cases) {
    const same = jobIdOf(c.a) === jobIdOf(c.b);
    expectEqual(`jobId case ${c.name}`, same, c.expectEqual);
    if (c.expectEqual) expectEqual(`jobId case ${c.name} leaves differ`, leafOf(c.a) === leafOf(c.b), false);
    else expectEqual(`jobId case ${c.name} leaves`, leafOf(c.a) === leafOf(c.b), false);
  }
  const id = jobIdOf(base);
  expectEqual("JOB_ID_TAG", JOB_ID_TAG, bytesToHex(keccak256(utf8(JOB_ID_TAG_STRING))));
  return {
    tag: JOB_ID_TAG,
    tagString: JOB_ID_TAG_STRING,
    encoding:
      'keccak256(abi.encode(TAG, genesis, channelId, settledBlock, eventIndex)); TAG = keccak256("InferenceFi.IF-D8.jobId.v1"); fields as flop-receipt-root v0.3.2 (bytes32, bytes32, uint64, uint32), each a 32-byte ABI word',
    base: { settlement: settlementToJson(base), jobId: id, leaf: leafOf(base) },
    cases: cases.map((c) => ({
      name: c.name,
      a: settlementToJson(c.a),
      b: settlementToJson(c.b),
      jobIdA: jobIdOf(c.a),
      jobIdB: jobIdOf(c.b),
      leafA: leafOf(c.a),
      leafB: leafOf(c.b),
      expectEqual: c.expectEqual,
    })),
  };
}

export function buildVectors() {
  return toJson({
    name: "inferencefi-receipt-root",
    version: 2,
    format: {
      adopts: "flop-receipt-root v0.3.2 (aa2fa591da38e6981a37693fb101c4f14835826d)",
      leafType: LEAF_TYPE,
      leafTypehash: LEAF_TYPEHASH,
      rootType: ROOT_TYPE,
      rootTypehash: ROOT_TYPEHASH,
      domain: { name: "FlopReceiptRoot", version: "1", chainId: EVM_CHAIN_ID, verifyingContract: ROOTS_ADDRESS, separator: domainSeparator(EVM_CHAIN_ID, ROOTS_ADDRESS) },
      leaf: "keccak256(keccak256(abi.encode(LEAF_TYPEHASH, genesis, channelId, settledBlock, settledBlockHash, eventIndex, agent, miner, modelHash, aggregateGn, minerPaid, burned, escrow)))",
      node: "keccak256(min(a, b) || max(a, b)); leaves sorted ascending; odd node promoted; duplicates refused",
      hookData: "abi.encode(uint64 epoch, Settlement s, bytes32[] proof); jobId is the event key, not in hookData",
      jobId: 'keccak256(abi.encode(TAG, genesis, channelId, settledBlock, eventIndex)); TAG = keccak256("InferenceFi.IF-D8.jobId.v1"); fields as flop-receipt-root v0.3.2 (bytes32, bytes32, uint64, uint32), each a 32-byte ABI word',
      jobIdTag: JOB_ID_TAG,
      jobIdTagString: JOB_ID_TAG_STRING,
      payoutTuple: ["owed", "toProvider", "toLender", "toPayer", "overrun", "lenderShortfall"],
      upstreamFixture: "vendor/flop-receipt-root/test/fixtures/epoch.json (cross-checked by tests/upstream.test.ts)",
    },
    leaves: leafVectors(),
    trees: treeVectors(),
    proofCases: proofCases(),
    verifyCases: verifyCases(),
    hookDataCases: hookDataCases(),
    jobIdCases: jobIdCases(),
    scenario: scenario(),
  });
}

export function serializeVectors(): string {
  return `${JSON.stringify(buildVectors(), null, 2)}\n`;
}
