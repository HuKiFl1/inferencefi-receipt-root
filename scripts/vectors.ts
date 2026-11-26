/**
 * Deterministic test vectors for the IF-D8 proposal. Scenario expectations are
 * written out by hand below; `buildVectors()` throws if the reference models
 * disagree with any of them, so the JSON is a specification, not a snapshot.
 *
 * All identifiers are synthetic labels hashed with blake2b-256 or keccak-256.
 * None is a real chain, account, key or address.
 */
import {
  AgentRewardsModel,
  BLAKE2B256,
  type Hex,
  KECCAK256,
  type LockInput,
  type MerkleProof,
  OMER_UNIT,
  OmerMinterModel,
  Prefix,
  type ReceiptClaim,
  type ReceiptDomain,
  type ReceiptLeaf,
  RootRegistry,
  type RootCommitment,
  type Snapshot,
  U64_MAX,
  U128_MAX,
  ZERO32,
  blake2b256,
  buildSnapshot,
  bytesToHex,
  checkpointOf,
  encodeLeaf,
  isReceiptRootError,
  jobIdOf,
  keccak256,
  leafHash,
  nodeHash,
  nullifierOf,
  reclaimEligible,
  utf8,
  waterfall,
  EMPTY_BLAKE_ROOT,
  EMPTY_KECCAK_ROOT,
} from "../src/index.js";

export const label = (s: string): Hex => bytesToHex(blake2b256(utf8(`inferencefi-receipt-root/test/${s}`)));
const address = (s: string): Hex => `0x${bytesToHex(keccak256(utf8(`inferencefi-receipt-root/test/${s}`))).slice(-40)}`;
const omer = (n: bigint): bigint => n * OMER_UNIT;

export const DOMAIN: ReceiptDomain = {
  flopGenesis: label("flop-genesis"),
  evmChainId: 998n,
  poolId: bytesToHex(keccak256(utf8("inferencefi-receipt-root/test/pool"))),
};
export const HOOK: Hex = address("hook");
export const EPOCH_LENGTH = 1_000n;

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

/** bigint becomes a decimal string, so uint128 values survive any JSON parser. */
function toJson(value: unknown): Json {
  if (typeof value === "bigint") return value.toString(10);
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(toJson);
  if (typeof value === "object") {
    const out: { [k: string]: Json } = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) if (v !== undefined) out[k] = toJson(v);
    return out;
  }
  throw new TypeError(`cannot serialize ${typeof value}`);
}

interface LeafSpec {
  readonly ch: string;
  readonly nonce: bigint;
  readonly owed: bigint;
  readonly escrow: bigint;
  readonly height: bigint;
  readonly provider?: string;
  readonly payer?: string;
}

function leafOf(s: LeafSpec, epoch: bigint, domain: ReceiptDomain = DOMAIN): ReceiptLeaf {
  return {
    ...domain,
    channelId: label(`channel/${s.ch}`),
    provider: label(`provider/${s.provider ?? s.ch}`),
    payer: label(`payer/${s.payer ?? s.ch}`),
    cumulativeOwed: s.owed,
    escrow: s.escrow,
    nonce: s.nonce,
    epoch,
    finalizedHeight: s.height,
    stateRoot: s.nonce === 0n ? ZERO32 : label(`state/${s.ch}/${s.nonce}/${s.owed}`),
  };
}

function snapshot(epoch: bigint, specs: readonly LeafSpec[]): Snapshot {
  return buildSnapshot({ domain: DOMAIN, hook: HOOK, epoch, epochLength: EPOCH_LENGTH }, specs.map((s) => leafOf(s, epoch)));
}

function claimFor(snap: Snapshot, ch: string): ReceiptClaim {
  const i = snap.tree.indexOf(label(`channel/${ch}`));
  if (i < 0) throw new Error(`channel ${ch} not in epoch ${snap.commitment.epoch}`);
  return { jobId: snap.jobId, leaf: snap.tree.leaves[i]!, proof: snap.tree.proof(i, KECCAK256) };
}

const proofJson = (p: MerkleProof) => ({ index: p.index, leafCount: p.leafCount, siblings: [...p.siblings] });
const leafJson = (l: ReceiptLeaf) => ({
  flopGenesis: l.flopGenesis,
  evmChainId: l.evmChainId,
  poolId: l.poolId,
  channelId: l.channelId,
  provider: l.provider,
  payer: l.payer,
  cumulativeOwed: l.cumulativeOwed,
  escrow: l.escrow,
  nonce: l.nonce,
  epoch: l.epoch,
  finalizedHeight: l.finalizedHeight,
  stateRoot: l.stateRoot,
});
const commitmentJson = (c: RootCommitment) => ({
  flopGenesis: c.flopGenesis,
  evmChainId: c.evmChainId,
  poolId: c.poolId,
  hook: c.hook,
  epoch: c.epoch,
  checkpointHeight: c.checkpointHeight,
  leafCount: c.leafCount,
  keccakRoot: c.keccakRoot,
  blakeRoot: c.blakeRoot,
});

/** Runs `fn` and returns "OK" or the typed error code. */
function outcome(fn: () => unknown): string {
  try {
    fn();
    return "OK";
  } catch (e) {
    if (isReceiptRootError(e)) return e.code;
    throw e;
  }
}

function expectEqual(what: string, actual: unknown, expected: unknown): void {
  if (JSON.stringify(toJson(actual)) !== JSON.stringify(toJson(expected))) {
    throw new Error(`vector ${what}: model gave ${JSON.stringify(toJson(actual))}, spec says ${JSON.stringify(toJson(expected))}`);
  }
}

// ---------------------------------------------------------------- primitives

function primitives() {
  const inputs: Hex[] = ["0x", bytesToHex(utf8("abc")), bytesToHex(new Uint8Array(200).map((_, i) => i & 0xff))];
  const known = {
    keccak256: {
      "0x": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
      "0x616263": "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    },
    blake2b256: {
      "0x": "0x0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
      "0x616263": "0xbddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
    },
  } as const;
  const hashes = inputs.flatMap((input) =>
    [KECCAK256, BLAKE2B256].map((h) => {
      const output = bytesToHex(h(Uint8Array.from(Buffer.from(input.slice(2), "hex"))));
      const ref = (known[h.id] as Record<string, string>)[input];
      if (ref !== undefined) expectEqual(`hash ${h.id}(${input})`, output, ref);
      return { fn: h.id, input, output };
    }),
  );
  return { hashes };
}

// ---------------------------------------------------------------- leaves

function leafEncodings() {
  const boundary: ReceiptLeaf = {
    flopGenesis: `0x${"ff".repeat(32)}`,
    evmChainId: U64_MAX,
    poolId: `0x${"ff".repeat(32)}`,
    channelId: `0x${"ff".repeat(32)}`,
    provider: `0x${"ff".repeat(31)}fe`,
    payer: `0x${"00".repeat(31)}01`,
    cumulativeOwed: U128_MAX,
    escrow: U128_MAX,
    nonce: U64_MAX,
    epoch: U64_MAX,
    finalizedHeight: U64_MAX,
    stateRoot: `0x${"ff".repeat(32)}`,
  };
  const cases: { name: string; leaf: ReceiptLeaf }[] = [
    { name: "opening-state", leaf: leafOf({ ch: "enc-0", nonce: 0n, owed: 0n, escrow: omer(100n), height: 5_000n }, 5n) },
    { name: "served", leaf: leafOf({ ch: "enc-1", nonce: 7n, owed: omer(3n) + 1n, escrow: omer(10n), height: 5_432n }, 5n) },
    { name: "overrun", leaf: leafOf({ ch: "enc-2", nonce: 2n, owed: omer(12n), escrow: omer(10n), height: 5_999n }, 5n) },
    { name: "zero-escrow", leaf: leafOf({ ch: "enc-3", nonce: 1n, owed: 1n, escrow: 0n, height: 5_001n }, 5n) },
    { name: "uint-boundaries", leaf: boundary },
  ];
  return cases.map(({ name, leaf }) => ({
    name,
    leaf: leafJson(leaf),
    encoded: bytesToHex(encodeLeaf(leaf)),
    keccakLeafHash: leafHash(leaf, KECCAK256),
    blakeLeafHash: leafHash(leaf, BLAKE2B256),
    nullifier: nullifierOf(leaf),
  }));
}

// ---------------------------------------------------------------- trees and proofs

const TREE_SIZES = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 17] as const;

function treeSnapshot(n: number): Snapshot {
  const epoch = 100n + BigInt(n);
  const cp = checkpointOf(epoch, EPOCH_LENGTH);
  const specs: LeafSpec[] = Array.from({ length: n }, (_, i) => {
    const nonce = BigInt(i % 4);
    return {
      ch: `tree-${n}-${i}`,
      provider: `p${i % 3}`,
      payer: `a${i % 5}`,
      nonce,
      owed: nonce === 0n ? 0n : omer(BigInt(i + 1)) + BigInt(n),
      escrow: omer(BigInt(10 + i)),
      height: cp - BigInt((i * 37) % 900),
    };
  });
  return snapshot(epoch, specs);
}

function trees() {
  return TREE_SIZES.map((n) => {
    const s = treeSnapshot(n);
    return {
      name: `n=${n}`,
      commitment: commitmentJson(s.commitment),
      jobId: s.jobId,
      leaves: s.tree.leaves.map(leafJson),
      keccakLeafHashes: [...s.tree.leafHashes.keccak256],
      blakeLeafHashes: [...s.tree.leafHashes.blake2b256],
      proofs: s.tree.leaves.map((_, i) => ({
        index: BigInt(i),
        leafCount: BigInt(n),
        keccakSiblings: [...s.tree.proof(i, KECCAK256).siblings],
        blakeSiblings: [...s.tree.proof(i, BLAKE2B256).siblings],
      })),
    };
  });
}

/**
 * Proofs a correct verifier must reject, all against the keccak root of the n=7
 * tree. Each uses the committed `leafCount` (7) unless the case is about the
 * count itself. A verifier that lets the caller pick `leafCount` can be fooled
 * (an internal node verifies as a leaf of a 4-leaf tree), which is why the
 * count is bound into the jobId and read from the commitment.
 */
function negativeProofs() {
  const s = treeSnapshot(7);
  const root = s.commitment.keccakRoot;
  const hashes = s.tree.leafHashes.keccak256;
  const p = (i: number) => s.tree.proof(i, KECCAK256);
  const other = treeSnapshot(5);
  const internal = nodeHash(KECCAK256, hashes[0]!, hashes[1]!);
  const cases: { name: string; leafHash: Hex; index: bigint; leafCount: bigint; siblings: readonly Hex[]; root: Hex }[] = [
    { name: "wrong-index", leafHash: hashes[2]!, index: 3n, leafCount: 7n, siblings: p(2).siblings, root },
    { name: "leaf-count-plus-one", leafHash: hashes[6]!, index: 6n, leafCount: 8n, siblings: p(6).siblings, root },
    { name: "leaf-count-minus-one", leafHash: hashes[5]!, index: 5n, leafCount: 6n, siblings: p(5).siblings, root },
    { name: "extra-sibling", leafHash: hashes[1]!, index: 1n, leafCount: 7n, siblings: [...p(1).siblings, hashes[0]!], root },
    { name: "missing-sibling", leafHash: hashes[1]!, index: 1n, leafCount: 7n, siblings: p(1).siblings.slice(0, -1), root },
    { name: "swapped-siblings", leafHash: hashes[4]!, index: 4n, leafCount: 7n, siblings: [p(4).siblings[1]!, p(4).siblings[0]!, ...p(4).siblings.slice(2)], root },
    { name: "promoted-node-given-a-sibling", leafHash: hashes[6]!, index: 6n, leafCount: 7n, siblings: [hashes[5]!, ...p(6).siblings], root },
    { name: "internal-node-as-leaf", leafHash: internal, index: 0n, leafCount: 7n, siblings: p(0).siblings.slice(1), root },
    { name: "index-equals-leaf-count", leafHash: hashes[6]!, index: 7n, leafCount: 7n, siblings: p(6).siblings, root },
    // Leaf 6 is promoted at level 0, so index 6 + 8 walks the same path. Only `index < leafCount` stops it.
    { name: "index-aliases-past-leaf-count", leafHash: hashes[6]!, index: 14n, leafCount: 7n, siblings: p(6).siblings, root },
    { name: "leaf-from-other-tree", leafHash: other.tree.leafHashes.keccak256[0]!, index: 0n, leafCount: 7n, siblings: p(0).siblings, root },
    { name: "blake-siblings-on-keccak-root", leafHash: hashes[3]!, index: 3n, leafCount: 7n, siblings: s.tree.proof(3, BLAKE2B256).siblings, root },
    { name: "blake-leaf-on-keccak-root", leafHash: s.tree.leafHashes.blake2b256[3]!, index: 3n, leafCount: 7n, siblings: p(3).siblings, root },
    { name: "empty-tree", leafHash: hashes[0]!, index: 0n, leafCount: 0n, siblings: [], root: EMPTY_KECCAK_ROOT },
  ];
  return cases.map((c) => ({ ...c, siblings: [...c.siblings] }));
}

// ---------------------------------------------------------------- jobId / nullifier domain separation

function jobIdCases() {
  const base = treeSnapshot(3).commitment;
  const flip = (h: Hex): Hex => `0x${h.slice(2, 64)}${((Number.parseInt(h.slice(64), 16) ^ 1) & 0xff).toString(16).padStart(2, "0")}`;
  const variants: { name: string; commitment: RootCommitment }[] = [
    { name: "base", commitment: base },
    { name: "other-evm-chain", commitment: { ...base, evmChainId: 999n } },
    { name: "other-flop-network", commitment: { ...base, flopGenesis: label("other-flop-genesis") } },
    { name: "other-hook", commitment: { ...base, hook: address("other-hook") } },
    { name: "other-pool", commitment: { ...base, poolId: flip(base.poolId) } },
    { name: "next-epoch", commitment: { ...base, epoch: base.epoch + 1n, checkpointHeight: base.checkpointHeight + EPOCH_LENGTH } },
    { name: "other-leaf-count", commitment: { ...base, leafCount: base.leafCount + 1n } },
    { name: "other-blake-root", commitment: { ...base, blakeRoot: flip(base.blakeRoot) } },
    { name: "other-keccak-root", commitment: { ...base, keccakRoot: flip(base.keccakRoot) } },
  ];
  const out = variants.map((v) => ({ name: v.name, commitment: commitmentJson(v.commitment), jobId: jobIdOf(v.commitment) }));
  if (new Set(out.map((o) => o.jobId)).size !== out.length) throw new Error("jobId variants collide");
  const leaf = treeSnapshot(3).tree.leaves[0]!;
  const nullifiers = [
    { name: "base", leaf },
    { name: "other-epoch", leaf: { ...leaf, epoch: leaf.epoch + 1n } },
    { name: "other-evm-chain", leaf: { ...leaf, evmChainId: 999n } },
    { name: "other-pool", leaf: { ...leaf, poolId: flip(leaf.poolId) } },
    { name: "other-channel", leaf: { ...leaf, channelId: label("channel/other") } },
    { name: "same-receipt-newer-nonce", leaf: { ...leaf, nonce: leaf.nonce + 1n, cumulativeOwed: leaf.cumulativeOwed + 1n, stateRoot: label("x") } },
  ].map((n) => ({
    name: n.name,
    flopGenesis: n.leaf.flopGenesis,
    evmChainId: n.leaf.evmChainId,
    poolId: n.leaf.poolId,
    channelId: n.leaf.channelId,
    epoch: n.leaf.epoch,
    nullifier: nullifierOf(n.leaf),
  }));
  // A newer state of the same channel in the same epoch must hit the same nullifier.
  expectEqual("nullifier ignores nonce", nullifiers[5]!.nullifier, nullifiers[0]!.nullifier);
  return { jobIds: out, nullifiers };
}

// ---------------------------------------------------------------- settlement

function payoutCases() {
  const cases: { escrow: bigint; lenderPrincipal: bigint; owed: bigint; expect: [bigint, bigint, bigint, bigint, bigint] }[] = [
    { escrow: 1000n, lenderPrincipal: 800n, owed: 0n, expect: [0n, 800n, 200n, 0n, 0n] },
    { escrow: 1000n, lenderPrincipal: 800n, owed: 150n, expect: [150n, 800n, 50n, 0n, 0n] },
    { escrow: 1000n, lenderPrincipal: 800n, owed: 200n, expect: [200n, 800n, 0n, 0n, 0n] },
    { escrow: 1000n, lenderPrincipal: 800n, owed: 600n, expect: [600n, 400n, 0n, 0n, 400n] },
    { escrow: 1000n, lenderPrincipal: 800n, owed: 1000n, expect: [1000n, 0n, 0n, 0n, 800n] },
    { escrow: 1000n, lenderPrincipal: 800n, owed: 1500n, expect: [1000n, 0n, 0n, 500n, 800n] },
    { escrow: 0n, lenderPrincipal: 0n, owed: 7n, expect: [0n, 0n, 0n, 7n, 0n] },
    { escrow: 400n, lenderPrincipal: 0n, owed: 0n, expect: [0n, 0n, 400n, 0n, 0n] },
    { escrow: U128_MAX, lenderPrincipal: U128_MAX, owed: U128_MAX, expect: [U128_MAX, 0n, 0n, 0n, U128_MAX] },
  ];
  return cases.map((c) => {
    const p = waterfall(c.escrow, c.lenderPrincipal, c.owed);
    const [toProvider, toLender, toPayer, overrun, lenderShortfall] = c.expect;
    expectEqual(`waterfall(${c.escrow},${c.lenderPrincipal},${c.owed})`, p, { toProvider, toLender, toPayer, overrun, lenderShortfall });
    return { escrow: c.escrow, lenderPrincipal: c.lenderPrincipal, owed: c.owed, toProvider, toLender, toPayer, overrun, lenderShortfall };
  });
}

function reclaimEligibilityCases() {
  const N = 100n;
  const W = 20n;
  const cases: [bigint, bigint, boolean][] = [
    [20_950n, 20_999n, false],
    [20_950n, 21_069n, false],
    [20_950n, 21_070n, true],
    [20_950n, 21_999n, true],
    [0n, 119n, false],
    [0n, 120n, true],
  ];
  return cases.map(([finalizedHeight, checkpointHeight, eligible]) => {
    expectEqual(`reclaimEligible(${checkpointHeight},${finalizedHeight})`, reclaimEligible(checkpointHeight, finalizedHeight, N, W), eligible);
    return { finalizedHeight, checkpointHeight, stalenessBlocks: N, challengeWindowBlocks: W, eligible };
  });
}

// ---------------------------------------------------------------- AgentRewards scenario (IF-F11)

function rewardsScenario() {
  const E = omer;
  const e10 = snapshot(10n, [
    { ch: "A", nonce: 3n, owed: E(300n), escrow: E(1000n), height: 10_500n },
    { ch: "B", nonce: 1n, owed: E(50n), escrow: E(500n), height: 10_200n },
    { ch: "C", nonce: 2n, owed: E(900n), escrow: E(600n), height: 10_900n },
    { ch: "D", nonce: 0n, owed: 0n, escrow: E(100n), height: 10_100n },
  ]);
  const e10Rival = snapshot(10n, [{ ch: "A", nonce: 9n, owed: E(999n), escrow: E(1000n), height: 10_600n }]);
  const e11 = snapshot(11n, [
    { ch: "A", nonce: 5n, owed: E(700n), escrow: E(1000n), height: 11_500n },
    { ch: "B", nonce: 1n, owed: E(50n), escrow: E(500n), height: 10_200n },
    { ch: "C", nonce: 4n, owed: E(1200n), escrow: E(600n), height: 11_800n },
    { ch: "D", nonce: 0n, owed: 0n, escrow: E(100n), height: 10_100n },
  ]);
  const e9 = snapshot(9n, [{ ch: "B", nonce: 1n, owed: E(50n), escrow: E(500n), height: 9_200n }]);
  // A faulty attester rolls channel A back to an older state in epoch 12.
  const e12 = snapshot(12n, [
    { ch: "A", nonce: 4n, owed: E(650n), escrow: E(1000n), height: 11_400n },
    { ch: "B", nonce: 2n, owed: E(80n), escrow: E(500n), height: 12_100n },
    { ch: "C", nonce: 4n, owed: E(1200n), escrow: E(600n), height: 11_800n },
    { ch: "D", nonce: 0n, owed: 0n, escrow: E(100n), height: 10_100n },
  ]);
  const a10 = claimFor(e10, "A");
  const otherChain = snapshotForDomain({ ...DOMAIN, evmChainId: 999n }, 10n, { ch: "A", nonce: 3n, owed: E(300n), escrow: E(1000n), height: 10_500n });
  const otherPool = snapshotForDomain({ ...DOMAIN, poolId: label("other-pool") }, 10n, { ch: "A", nonce: 3n, owed: E(300n), escrow: E(1000n), height: 10_500n });

  type Step =
    | { op: "acceptRoot"; note: string; commitment: RootCommitment; attested: boolean; expect: string }
    | { op: "claim"; note: string; claim: ReceiptClaim; expect: string; credit: bigint };
  const accept = (note: string, snap: Snapshot | RootCommitment, expect = "OK", attested = true): Step => ({
    op: "acceptRoot",
    note,
    commitment: "commitment" in snap ? snap.commitment : snap,
    attested,
    expect,
  });
  const e13 = { ...e12.commitment, epoch: 13n, checkpointHeight: checkpointOf(13n, EPOCH_LENGTH) };
  const claim = (note: string, c: ReceiptClaim, expect: string, credit = 0n): Step => ({ op: "claim", note, claim: c, expect, credit });

  const steps: Step[] = [
    accept("root without attester threshold is rejected", e10, "UNAUTHORIZED_ATTESTER", false),
    accept("epoch 10 root", e10),
    accept("a second root for epoch 10 is rejected", e10Rival, "ROOT_EXISTS"),
    claim("A epoch 10: first claim credits 300", a10, "OK", E(300n)),
    claim("A epoch 10 again: double-claim", a10, "NULLIFIER_SPENT"),
    claim("B epoch 10", claimFor(e10, "B"), "OK", E(50n)),
    claim("C epoch 10: owed 900 > escrow 600, credit capped at escrow", claimFor(e10, "C"), "OK", E(600n)),
    claim("D epoch 10: opening state carries no spend", claimFor(e10, "D"), "STATE_REPLAYED"),
    claim("inflated cumulative owed with the original proof", { ...claimFor(e10, "B"), leaf: { ...claimFor(e10, "B").leaf, cumulativeOwed: E(499n) } }, "INVALID_PROOF"),
    claim("receipt minted for chain 999, replayed on 998", { ...otherChain, jobId: e10.jobId }, "DOMAIN_MISMATCH"),
    claim("receipt for another pool", { ...otherPool, jobId: e10.jobId }, "DOMAIN_MISMATCH"),
    accept("epoch 11 root", e11),
    claim("epoch-10 leaf replayed against the epoch-11 root", { ...a10, jobId: e11.jobId }, "EPOCH_MISMATCH"),
    claim("A epoch 11: delta 700 - 300", claimFor(e11, "A"), "OK", E(400n)),
    claim("B epoch 11: no progress since epoch 10", claimFor(e11, "B"), "STATE_REPLAYED"),
    claim("C epoch 11: progress, but escrow-backed spend already credited", claimFor(e11, "C"), "OK", 0n),
    accept("root for an older epoch is rejected", e9, "EPOCH_REGRESSION"),
    accept("epoch 12 root from a faulty attester", e12),
    claim("A epoch 12: nonce rolled back from 5 to 4", claimFor(e12, "A"), "STALE_NONCE"),
    claim("B epoch 12: delta 80 - 50", claimFor(e12, "B"), "OK", E(30n)),
    claim("D epoch 10 after epoch 12: outside the 1-epoch claim window", claimFor(e10, "D"), "EPOCH_EXPIRED"),
    claim("D epoch 11 after epoch 12: still inside the window, reaches the state check", claimFor(e11, "D"), "STATE_REPLAYED"),
    claim("unknown jobId", { ...claimFor(e12, "C"), jobId: label("not-a-root") }, "UNKNOWN_ROOT"),
    accept("checkpoint one block before the end of epoch 13", { ...e13, checkpointHeight: e13.checkpointHeight - 1n }, "CHECKPOINT_MISMATCH"),
    accept("leafCount 0 with non-empty roots", { ...e13, leafCount: 0n }, "EMPTY_ROOT_MISMATCH"),
    accept("empty epoch 13 root", { ...e13, leafCount: 0n, keccakRoot: EMPTY_KECCAK_ROOT, blakeRoot: EMPTY_BLAKE_ROOT }),
  ];

  const params = { claimWindowEpochs: 1n };
  const registry = new RootRegistry({ domain: DOMAIN, hook: HOOK, epochLength: EPOCH_LENGTH });
  const model = new AgentRewardsModel(registry, params);
  for (const [i, s] of steps.entries()) {
    if (s.op === "acceptRoot") {
      expectEqual(`rewards step ${i} (${s.note})`, outcome(() => registry.accept(s.commitment, s.attested)), s.expect);
    } else {
      let credit = 0n;
      expectEqual(`rewards step ${i} (${s.note})`, outcome(() => (credit = model.claim(s.claim).credit)), s.expect);
      expectEqual(`rewards step ${i} credit`, credit, s.credit);
    }
  }
  expectEqual("rewards total", model.totalCredited(), E(700n) + E(80n) + E(600n));

  return {
    params: { ...DOMAIN, hook: HOOK, epochLength: EPOCH_LENGTH, claimWindowEpochs: params.claimWindowEpochs },
    totalCredited: model.totalCredited(),
    steps: steps.map((s) =>
      s.op === "acceptRoot"
        ? { op: s.op, note: s.note, expect: s.expect, attested: s.attested, commitment: commitmentJson(s.commitment), jobId: jobIdOf(s.commitment) }
        : { op: s.op, note: s.note, expect: s.expect, credit: s.credit, jobId: s.claim.jobId, leaf: leafJson(s.claim.leaf), proof: proofJson(s.claim.proof) },
    ),
  };
}

function snapshotForDomain(domain: ReceiptDomain, epoch: bigint, spec: LeafSpec): ReceiptClaim {
  const s = buildSnapshot({ domain, hook: HOOK, epoch, epochLength: EPOCH_LENGTH }, [leafOf(spec, epoch, domain)]);
  return { jobId: s.jobId, leaf: s.tree.leaves[0]!, proof: s.tree.proof(0, KECCAK256) };
}

// ---------------------------------------------------------------- OmerMinter scenario (IF-F12)

function minterScenario() {
  const E = omer;
  const params = { stalenessBlocks: 100n, challengeWindowBlocks: 20n, reclaimPolicy: "channel-parties" as const };
  const lock = (n: string, L: bigint, D: bigint): LockInput => ({
    lockId: label(`lock/${n}`),
    channelId: label(`channel/${n}`),
    provider: label(`provider/${n}`),
    payer: label(`payer/${n}`),
    lender: label(`lender/${n}`),
    lenderPrincipal: L,
    payerDeposit: D,
  });
  const locks = [
    lock("M1", E(800n), E(200n)),
    lock("M2", E(500n), E(500n)),
    lock("M3", 0n, E(400n)),
    lock("M4", E(300n), 0n),
    lock("M5", E(600n), E(400n)),
    lock("M6", E(500n), E(500n)),
    { ...lock("M7", E(100n), E(100n)), provider: label("provider/someone-else") },
  ];
  const [M1, M2, M3, M4, M5, M6, M7] = locks as [LockInput, LockInput, LockInput, LockInput, LockInput, LockInput, LockInput];
  const e20 = snapshot(20n, [
    { ch: "M1", nonce: 4n, owed: E(600n), escrow: E(1000n), height: 20_950n },
    { ch: "M2", nonce: 2n, owed: E(300n), escrow: E(1000n), height: 20_950n },
    { ch: "M3", nonce: 0n, owed: 0n, escrow: E(400n), height: 20_000n },
    { ch: "M4", nonce: 3n, owed: E(450n), escrow: E(300n), height: 20_500n },
    { ch: "M5", nonce: 1n, owed: E(250n), escrow: E(1000n), height: 20_800n },
  ]);
  const e21 = snapshot(21n, [
    { ch: "M2", nonce: 2n, owed: E(300n), escrow: E(1000n), height: 20_950n },
    { ch: "M3", nonce: 0n, owed: 0n, escrow: E(400n), height: 20_000n },
    { ch: "M4", nonce: 3n, owed: E(450n), escrow: E(300n), height: 20_500n },
    { ch: "M5", nonce: 2n, owed: E(400n), escrow: E(1000n), height: 21_950n },
    { ch: "M6", nonce: 1n, owed: E(100n), escrow: E(5000n), height: 21_100n },
    { ch: "M7", nonce: 1n, owed: E(100n), escrow: E(200n), height: 21_100n },
  ]);
  type P = [bigint, bigint, bigint, bigint, bigint];
  type Step =
    | { op: "acceptRoot"; note: string; snap: Snapshot; expect: string }
    | { op: "open"; note: string; lock: LockInput; expect: string }
    | { op: "redeem" | "reclaim"; note: string; lockId: Hex; claim: ReceiptClaim; by: Hex; expect: string; payouts: P };
  const Z: P = [0n, 0n, 0n, 0n, 0n];
  const act = (op: "redeem" | "reclaim", note: string, l: LockInput, c: ReceiptClaim, by: Hex, expect: string, payouts: P = Z): Step => ({
    op,
    note,
    lockId: l.lockId,
    claim: c,
    by,
    expect,
    payouts,
  });
  const steps: Step[] = [
    { op: "acceptRoot", note: "epoch 20 root", snap: e20, expect: "OK" },
    ...locks.map((l): Step => ({ op: "open", note: `open ${l.lockId.slice(0, 10)}`, lock: l, expect: "OK" })),
    { op: "open", note: "a second lock on M1's channel", lock: { ...lock("M1", 1n, 1n), lockId: label("lock/M1-dup") }, expect: "DUPLICATE_LOCK" },
    act("redeem", "payer cannot redeem", M1, claimFor(e20, "M1"), M1.payer, "UNAUTHORIZED"),
    act("redeem", "served: provider 600 first, lender 400 of 800, payer 0", M1, claimFor(e20, "M1"), M1.provider, "OK", [E(600n), E(400n), 0n, 0n, E(400n)]),
    act("redeem", "second redeem", M1, claimFor(e20, "M1"), M1.provider, "ALREADY_SETTLED"),
    act("reclaim", "M2 at epoch 20: 20999 < 20950 + 100 + 20", M2, claimFor(e20, "M2"), M2.payer, "TIMEOUT_NOT_REACHED"),
    act("redeem", "opening state is not a spend receipt", M3, claimFor(e20, "M3"), M3.provider, "NOT_SERVED"),
    act("redeem", "receipt for another channel", M2, { ...claimFor(e20, "M1") }, M2.provider, "CHANNEL_MISMATCH"),
    { op: "acceptRoot", note: "epoch 21 root", snap: e21, expect: "OK" },
    act("reclaim", "reclaim must use the latest root", M2, claimFor(e20, "M2"), M2.payer, "STALE_ROOT"),
    act("reclaim", "outsider under channel-parties policy", M2, claimFor(e21, "M2"), label("outsider"), "UNAUTHORIZED"),
    act("reclaim", "unserved after timeout: provider 300, lender 500, payer 200", M2, claimFor(e21, "M2"), M2.lender, "OK", [E(300n), E(500n), E(200n), 0n, 0n]),
    act("redeem", "refund included first wins", M2, claimFor(e21, "M2"), M2.provider, "ALREADY_SETTLED"),
    act("redeem", "past the timeout a claim still wins until a refund is included; overrun capped", M4, claimFor(e20, "M4"), M4.provider, "OK", [E(300n), 0n, 0n, E(150n), E(300n)]),
    act("reclaim", "claim included first wins", M4, claimFor(e21, "M4"), M4.payer, "ALREADY_SETTLED"),
    act("reclaim", "M5 progressed at 21950: not stale yet", M5, claimFor(e21, "M5"), M5.payer, "TIMEOUT_NOT_REACHED"),
    act("reclaim", "never served: everything back to the payer", M3, claimFor(e21, "M3"), M3.payer, "OK", [0n, 0n, E(400n), 0n, 0n]),
    act("redeem", "served M5: provider 400, lender 600", M5, claimFor(e21, "M5"), M5.provider, "OK", [E(400n), E(600n), 0n, 0n, 0n]),
    act("redeem", "receipt escrow 5000 does not match the 1000 locked", M6, claimFor(e21, "M6"), M6.provider, "ESCROW_MISMATCH"),
    act("redeem", "receipt provider is not the lock's provider", M7, claimFor(e21, "M7"), M7.provider, "PARTY_MISMATCH"),
  ];

  const registry = new RootRegistry({ domain: DOMAIN, hook: HOOK, epochLength: EPOCH_LENGTH });
  const minter = new OmerMinterModel(registry, params);
  for (const [i, s] of steps.entries()) {
    const what = `minter step ${i} (${s.note})`;
    if (s.op === "acceptRoot") expectEqual(what, outcome(() => registry.accept(s.snap.commitment, true)), s.expect);
    else if (s.op === "open") expectEqual(what, outcome(() => minter.open(s.lock)), s.expect);
    else {
      let got: P = Z;
      expectEqual(
        what,
        outcome(() => {
          const r = s.op === "redeem" ? minter.redeem(s.lockId, s.claim, s.by) : minter.reclaim(s.lockId, s.claim, s.by);
          got = [r.toProvider, r.toLender, r.toPayer, r.overrun, r.lenderShortfall];
        }),
        s.expect,
      );
      expectEqual(`${what} payouts`, got, s.payouts);
    }
  }

  const payoutJson = (p: P) => ({ toProvider: p[0], toLender: p[1], toPayer: p[2], overrun: p[3], lenderShortfall: p[4] });
  return {
    params: { ...DOMAIN, hook: HOOK, epochLength: EPOCH_LENGTH, ...params },
    steps: steps.map((s) => {
      if (s.op === "acceptRoot") return { op: s.op, note: s.note, expect: s.expect, commitment: commitmentJson(s.snap.commitment), jobId: s.snap.jobId };
      if (s.op === "open") return { op: s.op, note: s.note, expect: s.expect, lock: { ...s.lock } };
      return {
        op: s.op,
        note: s.note,
        expect: s.expect,
        lockId: s.lockId,
        by: s.by,
        jobId: s.claim.jobId,
        leaf: leafJson(s.claim.leaf),
        proof: proofJson(s.claim.proof),
        payouts: payoutJson(s.payouts),
      };
    }),
  };
}

// ---------------------------------------------------------------- assemble

export function buildVectors(): Json {
  return toJson({
    name: "inferencefi-receipt-root",
    version: 1,
    status: "Proposal for Inference Finance IF-D8. Not adopted. Synthetic identifiers only.",
    encoding: {
      prefixes: { leaf: Prefix.LEAF, node: Prefix.NODE, jobId: Prefix.JOB_ID, nullifier: Prefix.NULLIFIER },
      leafVersion: 1,
      leafBytes: 257,
      emptyRoots: { keccak256: EMPTY_KECCAK_ROOT, blake2b256: EMPTY_BLAKE_ROOT },
      epochLength: EPOCH_LENGTH,
    },
    domain: { ...DOMAIN, hook: HOOK },
    ...primitives(),
    leafEncodings: leafEncodings(),
    trees: trees(),
    negativeProofs: negativeProofs(),
    ...jobIdCases(),
    payouts: payoutCases(),
    reclaimEligibility: reclaimEligibilityCases(),
    rewardsScenario: rewardsScenario(),
    minterScenario: minterScenario(),
  });
}

export function serializeVectors(): string {
  return `${JSON.stringify(buildVectors(), null, 2)}\n`;
}
