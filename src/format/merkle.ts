import { type Hex, ZERO32, bytesToHex, compareHex, concatBytes, hexToBytes, isHex } from "../bytes.js";
import { ErrorCode, fail } from "../errors.js";
import { keccak256 } from "../hash/index.js";

/**
 * The flop-receipt-root v0.3.2 tree: OpenZeppelin's sorted-pair rule,
 * `parent = keccak256(min(a, b) ‖ max(a, b))`, over leaves sorted ascending.
 * An odd last node is promoted unchanged. Duplicate leaves are refused.
 * A proof is only the sibling list; it carries no index.
 */

/** FlopReceiptRoot.verify refuses longer proofs. */
export const MAX_PROOF = 64;

/** The contract's convention for an epoch with no settlements: `count = 0` and `root = 0`. */
export const EMPTY_ROOT: Hex = ZERO32;

export function pairHash(a: Hex, b: Hex): Hex {
  const [lo, hi] = compareHex(a, b) <= 0 ? [a, b] : [b, a];
  return bytesToHex(keccak256(concatBytes(hexToBytes(lo), hexToBytes(hi))));
}

export interface SortedPairTree {
  /** `layers[0]` is the sorted leaf list; the last layer holds the root alone. */
  readonly layers: readonly (readonly Hex[])[];
  readonly root: Hex;
  readonly count: number;
}

function check32(h: Hex, what: string): void {
  if (!isHex(h, 32)) fail(ErrorCode.INVALID_INPUT, `${what} must be 32 bytes of lowercase 0x-hex`);
}

export function buildTree(leaves: readonly Hex[]): SortedPairTree {
  if (leaves.length === 0) fail(ErrorCode.INVALID_INPUT, "merkle: no leaves (an empty epoch uses EMPTY_ROOT with count 0)");
  for (const l of leaves) check32(l, "leaf");
  const sorted = [...leaves].sort(compareHex);
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i] === sorted[i - 1]) fail(ErrorCode.INVALID_INPUT, `merkle: duplicate leaf ${sorted[i]}`);
  }
  const layers: Hex[][] = [sorted];
  for (let level = sorted; level.length > 1; ) {
    const next: Hex[] = [];
    for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? pairHash(level[i]!, level[i + 1]!) : level[i]!);
    layers.push(next);
    level = next;
  }
  return { layers, root: layers.at(-1)![0]!, count: sorted.length };
}

/** Root of a leaf set, or EMPTY_ROOT for none. */
export function rootOf(leaves: readonly Hex[]): Hex {
  return leaves.length === 0 ? EMPTY_ROOT : buildTree(leaves).root;
}

export function proofFor(tree: SortedPairTree, leaf: Hex): Hex[] {
  let idx = tree.layers[0]!.indexOf(leaf);
  if (idx < 0) fail(ErrorCode.INVALID_INPUT, `merkle: leaf ${leaf} not in tree`);
  const proof: Hex[] = [];
  for (const layer of tree.layers.slice(0, -1)) {
    const sib = idx ^ 1;
    if (sib < layer.length) proof.push(layer[sib]!);
    idx >>= 1;
  }
  return proof;
}

export function processProof(leaf: Hex, proof: readonly Hex[]): Hex {
  check32(leaf, "leaf");
  let h = leaf;
  for (const p of proof) {
    check32(p, "proof element");
    h = pairHash(h, p);
  }
  return h;
}

/**
 * Raw check of a leaf HASH against a root. Consumers must not expose this to
 * callers: a 64-byte inner node passes it with a shortened proof. They take
 * a Settlement and hash it themselves (see FlopReceiptRootModel.verify).
 */
export function verifyRawProof(root: Hex, leaf: Hex, proof: readonly Hex[]): boolean {
  return processProof(leaf, proof) === root;
}
