import { keccak_256 as nobleKeccak } from "@noble/hashes/sha3.js";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  EMPTY_ROOT,
  type Hex,
  MAX_PROOF,
  SETTLEMENT_ENCODING_BYTES,
  U64_MAX,
  U128_MAX,
  buildEpoch,
  buildTree,
  bytesToHex,
  decodeHookData,
  digest712,
  encodeHookData,
  encodeSettlement,
  hexToBytes,
  isReceiptRootError,
  JOB_ID_TAG,
  JOB_ID_TAG_STRING,
  jobIdOf,
  keccak256,
  leafOf,
  utf8,
  pairHash,
  processProof,
  proofFor,
  rootOf,
  verifyRawProof,
} from "../src/index.js";
import { CHAIN, GENESIS, ROOTS, RUNS, arbHex32, arbLeaves, label, newRoots, settlement } from "./helpers.js";

const code = (fn: () => unknown): string => {
  try {
    fn();
    return "OK";
  } catch (e) {
    if (isReceiptRootError(e)) return e.code;
    throw e;
  }
};

describe("settlement leaf", () => {
  it("is abi.encode of 13 words, double keccak", () => {
    const s = settlement(1, 5n);
    const enc = encodeSettlement(s);
    expect(enc.length).toBe(SETTLEMENT_ENCODING_BYTES);
    expect(leafOf(s)).toBe(bytesToHex(nobleKeccak(nobleKeccak(enc))));
  });

  it("refuses values that do not fit their Solidity width, and non-lowercase hex", () => {
    const s = settlement(1, 5n);
    expect(code(() => encodeSettlement({ ...s, settledBlock: U64_MAX + 1n }))).toBe("INVALID_INPUT");
    expect(code(() => encodeSettlement({ ...s, eventIndex: 1n << 32n }))).toBe("INVALID_INPUT");
    expect(code(() => encodeSettlement({ ...s, minerPaid: U128_MAX + 1n }))).toBe("INVALID_INPUT");
    expect(code(() => encodeSettlement({ ...s, escrow: -1n }))).toBe("INVALID_INPUT");
    expect(code(() => encodeSettlement({ ...s, agent: s.agent.toUpperCase().replace("0X", "0x") as Hex }))).toBe("INVALID_INPUT");
  });

  it("every field changes the leaf", () => {
    const s = settlement(1, 5n);
    const base = leafOf(s);
    const edits = [
      { genesis: label("g2") },
      { channelId: label("c2") },
      { settledBlock: 6n },
      { settledBlockHash: label("bh2") },
      { eventIndex: 1n },
      { agent: label("a2") },
      { miner: label("m2") },
      { modelHash: label("mh2") },
      { aggregateGn: 1_001n },
      { minerPaid: 101n },
      { burned: 1n },
      { escrow: 10_001n },
    ];
    expect(new Set(edits.map((e) => leafOf({ ...s, ...e }))).size).toBe(12);
    for (const e of edits) expect(leafOf({ ...s, ...e })).not.toBe(base);
  });
});

describe("sorted-pair tree", () => {
  it("pair hashing is keccak(min ‖ max), the OpenZeppelin rule", () => {
    fc.assert(
      fc.property(arbHex32, arbHex32, (a, b) => {
        const [lo, hi] = a <= b ? [a, b] : [b, a];
        const want = bytesToHex(nobleKeccak(new Uint8Array([...hexToBytes(lo), ...hexToBytes(hi)])));
        return pairHash(a, b) === want && pairHash(b, a) === want;
      }),
      { numRuns: RUNS },
    );
  });

  it("root ignores input order, every proof verifies and is at most ceil(log2 n) long", () => {
    fc.assert(
      fc.property(arbLeaves(1, 40), fc.integer(), (leaves, seed) => {
        const tree = buildTree(leaves);
        const shuffled = [...leaves].sort((a, b) => (Number.parseInt(a.slice(-4), 16) ^ seed) - (Number.parseInt(b.slice(-4), 16) ^ seed));
        if (buildTree(shuffled).root !== tree.root) return false;
        const depth = Math.ceil(Math.log2(leaves.length));
        return leaves.every((l) => {
          const p = proofFor(tree, l);
          return p.length <= depth && verifyRawProof(tree.root, l, p);
        });
      }),
      { numRuns: RUNS },
    );
  });

  it("a flipped sibling, a dropped sibling or a foreign leaf never verifies", () => {
    fc.assert(
      fc.property(arbLeaves(2, 30), fc.nat(), arbHex32, (leaves, k, foreign) => {
        const tree = buildTree(leaves);
        const l = leaves[k % leaves.length]!;
        const p = proofFor(tree, l);
        const flipped = p.map((x, i) => (i === k % p.length ? (`${x.slice(0, -1)}${x.endsWith("0") ? "1" : "0"}` as Hex) : x));
        return (
          !verifyRawProof(tree.root, l, flipped) &&
          !verifyRawProof(tree.root, l, p.slice(1)) &&
          (leaves.includes(foreign) || !verifyRawProof(tree.root, foreign, p))
        );
      }),
      { numRuns: RUNS },
    );
  });

  it("an inner node passes the raw check one level up, which is why consumers hash settlements themselves", () => {
    fc.assert(
      fc.property(arbLeaves(4, 30), (leaves) => {
        const tree = buildTree(leaves);
        const [a, b] = tree.layers[0]!;
        const node = pairHash(a!, b!);
        return verifyRawProof(tree.root, node, proofFor(tree, a!).slice(1));
      }),
      { numRuns: RUNS },
    );
  });

  it("refuses an empty or duplicated leaf set; an empty epoch uses the zero root", () => {
    expect(code(() => buildTree([]))).toBe("INVALID_INPUT");
    expect(code(() => buildTree([label("x"), label("x")]))).toBe("INVALID_INPUT");
    expect(rootOf([])).toBe(EMPTY_ROOT);
    expect(processProof(label("x"), [])).toBe(label("x"));
  });
});

describe("hookData", () => {
  it("round-trips abi.encode(uint64, Settlement, bytes32[])", () => {
    fc.assert(
      fc.property(fc.bigInt({ min: 0n, max: U64_MAX }), fc.array(arbHex32, { maxLength: MAX_PROOF + 2 }), fc.nat(), (epoch, proof, ch) => {
        const d = { epoch, settlement: settlement(ch, BigInt(ch)), proof };
        const hex = encodeHookData(d);
        return hexToBytes(hex).length === 32 * (15 + proof.length) && JSON.stringify(decodeHookData(hex), (_, v) => (typeof v === "bigint" ? v.toString() : v)) === JSON.stringify(d, (_, v) => (typeof v === "bigint" ? v.toString() : v));
      }),
      { numRuns: RUNS },
    );
  });

  it("refuses trailing bytes, a non-canonical offset and dirty high bits", () => {
    const hex = encodeHookData({ epoch: 3n, settlement: settlement(1, 5n), proof: [label("p")] });
    expect(code(() => decodeHookData(`${hex}00` as Hex))).toBe("BadHookData");
    const offset = 2 + 2 * 32 * 13;
    expect(code(() => decodeHookData(`${hex.slice(0, offset + 62)}e0${hex.slice(offset + 64)}` as Hex))).toBe("BadHookData");
    expect(code(() => decodeHookData(`0x01${hex.slice(4)}` as Hex))).toBe("BadHookData");
    expect(code(() => decodeHookData(hex.slice(0, 66) as Hex))).toBe("BadHookData");
  });
});

describe("root message and contract model", () => {
  const msg = { genesis: GENESIS, epoch: 1n, fromBlock: 1n, toBlock: 10n, toBlockHash: label("h"), count: 1n, root: label("r") };

  it("every field, the chain id and the contract change the digest", () => {
    const base = digest712(msg, CHAIN, ROOTS);
    const variants = [
      digest712({ ...msg, genesis: label("g") }, CHAIN, ROOTS),
      digest712({ ...msg, epoch: 2n }, CHAIN, ROOTS),
      digest712({ ...msg, fromBlock: 2n }, CHAIN, ROOTS),
      digest712({ ...msg, toBlock: 11n }, CHAIN, ROOTS),
      digest712({ ...msg, toBlockHash: label("h2") }, CHAIN, ROOTS),
      digest712({ ...msg, count: 2n }, CHAIN, ROOTS),
      digest712({ ...msg, root: label("r2") }, CHAIN, ROOTS),
      digest712(msg, 999n, ROOTS),
      digest712(msg, CHAIN, `0x${"11".repeat(20)}`),
    ];
    expect(new Set([base, ...variants]).size).toBe(10);
  });

  it("accepts only contiguous epochs and block ranges", () => {
    fc.assert(
      fc.property(fc.array(fc.record({ len: fc.bigInt({ min: 1n, max: 50n }), skipEpoch: fc.boolean(), gap: fc.bigInt({ min: -2n, max: 2n }) }), { minLength: 1, maxLength: 12 }), (plan) => {
        const roots = newRoots(1n);
        for (const st of plan) {
          const epoch = roots.lastEpoch + (st.skipEpoch ? 2n : 1n);
          const fromBlock = roots.nextFromBlock + st.gap;
          const m = { ...msg, epoch, fromBlock, toBlock: fromBlock + st.len - 1n };
          const want = st.skipEpoch ? "WrongEpoch" : st.gap !== 0n ? "WrongFromBlock" : "OK";
          if (fromBlock < 0n) continue;
          if (code(() => roots.submit(m, true)) !== want) return false;
        }
        return true;
      }),
      { numRuns: RUNS },
    );
  });

  it("buildEpoch dedupes an exact repeat, refuses a conflicting repeat and out-of-range rows", () => {
    const s = settlement(1, 5n);
    const base = { genesis: GENESIS, epoch: 1n, fromBlock: 1n, toBlock: 10n, toBlockHash: label("h") };
    expect(buildEpoch({ ...base, settlements: [s, { ...s }] }).msg.count).toBe(1n);
    expect(code(() => buildEpoch({ ...base, settlements: [s, { ...s, minerPaid: 1n }] }))).toBe("INVALID_INPUT");
    expect(code(() => buildEpoch({ ...base, settlements: [settlement(2, 11n)] }))).toBe("INVALID_INPUT");
    expect(code(() => buildEpoch({ ...base, settlements: [{ ...s, genesis: label("g") }] }))).toBe("INVALID_INPUT");
    expect(buildEpoch({ ...base, settlements: [] }).msg).toMatchObject({ count: 0n, root: EMPTY_ROOT });
  });

  it("an accepted empty epoch verifies nothing, and a frozen contract verifies nothing", () => {
    const roots = newRoots(1n);
    roots.submit({ ...msg, count: 0n, root: EMPTY_ROOT }, true);
    expect(roots.verify(1n, settlement(1, 5n), [])).toBe(false);
    const roots2 = newRoots(1n);
    const s = settlement(1, 5n);
    const e = buildEpoch({ genesis: GENESIS, epoch: 1n, fromBlock: 1n, toBlock: 10n, toBlockHash: label("h"), settlements: [s] });
    roots2.submit(e.msg, true);
    expect(roots2.verify(1n, s, [])).toBe(true);
    roots2.freeze(e.msg, true, { ...e.msg, root: label("rival") }, true);
    expect(roots2.verify(1n, s, [])).toBe(false);
  });
});

describe("jobId is the event key", () => {
  it("is keccak256(abi.encode(TAG, genesis, channelId, settledBlock, eventIndex)) with v0.3.2 widths", () => {
    expect(JOB_ID_TAG_STRING).toBe("FlopReceiptRoot.jobId.v1");
    expect(JOB_ID_TAG).toBe(bytesToHex(keccak256(utf8(JOB_ID_TAG_STRING))));
    expect(JOB_ID_TAG).toBe("0x748fa4722b652359047a16941d7e978a83dcfab3a169bea48a5a663e7d31bd14");
    const s = settlement(1, 5n);
    const sameKey = { ...s, minerPaid: s.minerPaid + 1n, aggregateGn: s.aggregateGn + 2n, settledBlockHash: label("layout") };
    const otherIndex = { ...s, eventIndex: s.eventIndex + 1n };
    expect(jobIdOf(s)).not.toBe(leafOf(s));
    expect(jobIdOf(sameKey)).toBe(jobIdOf(s));
    expect(leafOf(sameKey)).not.toBe(leafOf(s));
    expect(jobIdOf(otherIndex)).not.toBe(jobIdOf(s));
  });
});

