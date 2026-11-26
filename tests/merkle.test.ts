import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  BLAKE2B256,
  type HashFn,
  type Hex,
  KECCAK256,
  buildReceiptTree,
  bytesToHex,
  concatBytes,
  emptyRoot,
  hexToBytes,
  merkleProof,
  merkleRoot,
  nodeHash,
  verifyProof,
} from "../src/index.js";
import { RUNS, arbHex32, arbLeafSet, codeOf, label, leafOf } from "./helpers.js";

/** RFC 6962 §2.1 MTH, written recursively from the RFC text, over leaf hashes. */
function rfc6962Root(h: HashFn, d: readonly Hex[]): Hex {
  if (d.length === 0) return bytesToHex(h(new Uint8Array()));
  if (d.length === 1) return d[0]!;
  let k = 1;
  while (k * 2 < d.length) k *= 2;
  return bytesToHex(h(concatBytes(Uint8Array.of(1), hexToBytes(rfc6962Root(h, d.slice(0, k))), hexToBytes(rfc6962Root(h, d.slice(k))))));
}

/** RFC 6962 §2.1.1 PATH(m, D[n]), leaf-to-root order. */
function rfc6962Path(h: HashFn, m: number, d: readonly Hex[]): Hex[] {
  if (d.length <= 1) return [];
  let k = 1;
  while (k * 2 < d.length) k *= 2;
  return m < k ? [...rfc6962Path(h, m, d.slice(0, k)), rfc6962Root(h, d.slice(k))] : [...rfc6962Path(h, m - k, d.slice(k)), rfc6962Root(h, d.slice(0, k))];
}

const arbHashes = fc.array(arbHex32, { maxLength: 70 });

describe("tree shape", () => {
  it("empty root is H() for both hashes", () => {
    expect(emptyRoot(KECCAK256)).toBe("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    expect(emptyRoot(BLAKE2B256)).toBe("0x0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
    expect(merkleRoot(KECCAK256, [])).toBe(emptyRoot(KECCAK256));
  });

  it("one leaf: the root is the leaf hash and the proof is empty", () => {
    const h = label("only");
    expect(merkleRoot(KECCAK256, [h])).toBe(h);
    expect(merkleProof(KECCAK256, [h], 0).siblings).toEqual([]);
    expect(verifyProof(KECCAK256, h, h, { index: 0n, leafCount: 1n, siblings: [] })).toBe(true);
  });

  it("an odd last node is promoted, never paired with itself", () => {
    const [a, b, c] = [label("a"), label("b"), label("c")];
    expect(merkleRoot(KECCAK256, [a, b, c])).toBe(nodeHash(KECCAK256, nodeHash(KECCAK256, a, b), c));
    expect(merkleRoot(KECCAK256, [a, b, c])).not.toBe(merkleRoot(KECCAK256, [a, b, c, c]));
  });

  it("equals the RFC 6962 root and audit path for every size and index", () => {
    fc.assert(
      fc.property(arbHashes, fc.constantFrom(KECCAK256, BLAKE2B256), (d, h) => {
        expect(merkleRoot(h, d)).toBe(rfc6962Root(h, d));
        for (let i = 0; i < d.length; i++) expect([...merkleProof(h, d, i).siblings]).toEqual(rfc6962Path(h, i, d));
      }),
      { numRuns: RUNS },
    );
  });

  it("every proof verifies and no other position does", () => {
    fc.assert(
      fc.property(arbHashes.filter((d) => d.length > 0 && new Set(d).size === d.length), (d) => {
        const root = merkleRoot(KECCAK256, d);
        for (let i = 0; i < d.length; i++) {
          const p = merkleProof(KECCAK256, d, i);
          expect(verifyProof(KECCAK256, root, d[i]!, p)).toBe(true);
          if (d.length > 1) expect(verifyProof(KECCAK256, root, d[i]!, { ...p, index: BigInt((i + 1) % d.length) })).toBe(false);
        }
      }),
      { numRuns: RUNS },
    );
  });

  it("proof index out of range throws in the prover and is rejected by the verifier", () => {
    expect(codeOf(() => merkleProof(KECCAK256, [label("a")], 1))).toBe("INDEX_OUT_OF_RANGE");
    expect(verifyProof(KECCAK256, label("a"), label("a"), { index: -1n, leafCount: 1n, siblings: [] })).toBe(false);
    expect(verifyProof(KECCAK256, label("a"), label("a"), { index: 0n, leafCount: 0n, siblings: [] })).toBe(false);
    expect(verifyProof(KECCAK256, label("a"), label("a"), { index: 0n, leafCount: 1n, siblings: ["0x12" as Hex] })).toBe(false);
  });
});

describe("receipt tree", () => {
  it("sorts by channel id, so input order does not change the roots", () => {
    fc.assert(
      fc.property(arbLeafSet(3n, 16), fc.integer(), (leaves, seed) => {
        const shuffled = [...leaves].sort((a, b) => ((a.nonce ^ BigInt(seed)) < (b.nonce ^ BigInt(seed)) ? -1 : 1));
        const t1 = buildReceiptTree(leaves);
        const t2 = buildReceiptTree(shuffled);
        expect(t2.roots).toEqual(t1.roots);
        for (let i = 1; i < t1.leaves.length; i++) expect(t1.leaves[i - 1]!.channelId < t1.leaves[i]!.channelId).toBe(true);
      }),
      { numRuns: RUNS },
    );
  });

  it("rejects a channel listed twice", () => {
    const a = leafOf({ ch: "a", nonce: 1n, owed: 1n, escrow: 1n, height: 1n }, 0n);
    expect(codeOf(() => buildReceiptTree([a, { ...a, nonce: 2n, cumulativeOwed: 2n }]))).toBe("DUPLICATE_CHANNEL");
  });

  it("keccak and blake trees share order and proof shape", () => {
    fc.assert(
      fc.property(arbLeafSet(9n, 20), (leaves) => {
        const t = buildReceiptTree(leaves);
        for (let i = 0; i < t.leaves.length; i++) {
          const k = t.proof(i, KECCAK256);
          const b = t.proof(i, BLAKE2B256);
          expect(k.siblings.length).toBe(b.siblings.length);
          expect(verifyProof(KECCAK256, t.roots.keccak256, t.leafHashes.keccak256[i]!, k)).toBe(true);
          expect(verifyProof(BLAKE2B256, t.roots.blake2b256, t.leafHashes.blake2b256[i]!, b)).toBe(true);
          expect(verifyProof(KECCAK256, t.roots.keccak256, t.leafHashes.keccak256[i]!, b)).toBe(t.leaves.length === 1);
        }
      }),
      { numRuns: RUNS },
    );
  });
});
