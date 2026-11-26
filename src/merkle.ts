import { type Hex, U64_MAX, bytesToHex, compareHex, concatBytes, hexToBytes, isHex } from "./bytes.js";
import { ErrorCode, fail } from "./errors.js";
import type { HashFn, HashId } from "./hash/index.js";
import { HASHES } from "./hash/index.js";
import { Prefix, type ReceiptLeaf, leafHashBytes, validateLeaf } from "./leaf.js";

/**
 * Merkle tree in the shape of RFC 6962 §2.1 (Certificate Transparency):
 *
 *   MTH({})       = H()                       empty root: hash of the empty string
 *   MTH({d0})     = H(0x00 ‖ d0)              leaf
 *   MTH(D[0..n])  = H(0x01 ‖ MTH(D[0..k]) ‖ MTH(D[k..n]))   k = largest power of 2 < n
 *
 * Built level by level: nodes are paired left to right and an odd last node is
 * promoted to the next level unchanged. It is never paired with itself, which
 * avoids the duplicate-last-node ambiguity of Bitcoin's tree (CVE-2012-2459).
 * Both constructions give the same root; `tests/merkle.test.ts` checks this.
 */

export interface MerkleProof {
  /** Position of the leaf in the sorted leaf list. */
  readonly index: bigint;
  /** Number of leaves in the tree. Bound into the jobId, so it cannot be chosen by the prover. */
  readonly leafCount: bigint;
  /** Sibling hashes from the leaf level upward. A promoted level contributes none. */
  readonly siblings: readonly Hex[];
}

export function emptyRoot(hash: HashFn): Hex {
  return bytesToHex(hash(new Uint8Array(0)));
}

export function nodeHashBytes(hash: HashFn, left: Uint8Array, right: Uint8Array): Uint8Array {
  return hash(concatBytes(Uint8Array.of(Prefix.NODE), left, right));
}

export function nodeHash(hash: HashFn, left: Hex, right: Hex): Hex {
  return bytesToHex(nodeHashBytes(hash, hexToBytes(left), hexToBytes(right)));
}

/** All levels, leaves first, root last. Empty input gives no levels. */
function levels(hash: HashFn, leafHashes: readonly Uint8Array[]): Uint8Array[][] {
  if (leafHashes.length === 0) return [];
  const out: Uint8Array[][] = [[...leafHashes]];
  let level = out[0]!;
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? nodeHashBytes(hash, level[i]!, level[i + 1]!) : level[i]!);
    }
    out.push(next);
    level = next;
  }
  return out;
}

export function merkleRoot(hash: HashFn, leafHashes: readonly Hex[]): Hex {
  if (leafHashes.length === 0) return emptyRoot(hash);
  const lv = levels(hash, leafHashes.map(hexToBytes));
  return bytesToHex(lv[lv.length - 1]![0]!);
}

export function merkleProof(hash: HashFn, leafHashes: readonly Hex[], index: number): MerkleProof {
  if (!Number.isSafeInteger(index) || index < 0 || index >= leafHashes.length) {
    fail(ErrorCode.INDEX_OUT_OF_RANGE, `index ${index} not in [0, ${leafHashes.length})`);
  }
  const lv = levels(hash, leafHashes.map(hexToBytes));
  const siblings: Hex[] = [];
  let i = index;
  for (let l = 0; l < lv.length - 1; l++) {
    const level = lv[l]!;
    if (i % 2 === 1) siblings.push(bytesToHex(level[i - 1]!));
    else if (i + 1 < level.length) siblings.push(bytesToHex(level[i + 1]!));
    i = Math.floor(i / 2);
  }
  return { index: BigInt(index), leafCount: BigInt(leafHashes.length), siblings };
}

/**
 * Recomputes the root from a leaf hash and a position-checked proof. Returns
 * false, never throws, on any malformed input. Every sibling must be consumed.
 */
export function verifyProof(hash: HashFn, root: Hex, leafHash: Hex, proof: MerkleProof): boolean {
  const { index, leafCount, siblings } = proof;
  if (typeof index !== "bigint" || typeof leafCount !== "bigint") return false;
  if (leafCount < 1n || leafCount > U64_MAX || index < 0n || index >= leafCount) return false;
  if (!isHex(root, 32) || !isHex(leafHash, 32) || !siblings.every((s) => isHex(s, 32))) return false;
  let h = hexToBytes(leafHash);
  let i = index;
  let n = leafCount;
  let k = 0;
  while (n > 1n) {
    if (i % 2n === 1n) {
      const s = siblings[k++];
      if (s === undefined) return false;
      h = nodeHashBytes(hash, hexToBytes(s), h);
    } else if (i + 1n < n) {
      const s = siblings[k++];
      if (s === undefined) return false;
      h = nodeHashBytes(hash, h, hexToBytes(s));
    }
    i /= 2n;
    n = (n + 1n) / 2n;
  }
  return k === siblings.length && bytesToHex(h) === root;
}

/** Sorted, duplicate-free leaves with both commitments over the same order. */
export interface ReceiptTree {
  readonly leaves: readonly ReceiptLeaf[];
  readonly leafHashes: Readonly<Record<HashId, readonly Hex[]>>;
  readonly roots: Readonly<Record<HashId, Hex>>;
  indexOf(channelId: Hex): number;
  proof(index: number, hash: HashFn): MerkleProof;
}

/**
 * Sorts leaves by `channelId` (unsigned, ascending) and rejects duplicates, so
 * a channel appears at most once per root and both trees share one order.
 */
export function buildReceiptTree(input: readonly ReceiptLeaf[]): ReceiptTree {
  for (const leaf of input) validateLeaf(leaf);
  const leaves = [...input].sort((a, b) => compareHex(a.channelId, b.channelId));
  for (let i = 1; i < leaves.length; i++) {
    if (leaves[i]!.channelId === leaves[i - 1]!.channelId) {
      fail(ErrorCode.DUPLICATE_CHANNEL, `channel ${leaves[i]!.channelId} appears twice`);
    }
  }
  const leafHashes = {} as Record<HashId, Hex[]>;
  const roots = {} as Record<HashId, Hex>;
  for (const h of HASHES) {
    leafHashes[h.id] = leaves.map((l) => bytesToHex(leafHashBytes(l, h)));
    roots[h.id] = merkleRoot(h, leafHashes[h.id]);
  }
  const position = new Map(leaves.map((l, i) => [l.channelId, i] as const));
  return {
    leaves,
    leafHashes,
    roots,
    indexOf: (channelId) => position.get(channelId) ?? -1,
    proof: (index, hash) => merkleProof(hash, leafHashes[hash.id], index),
  };
}
