import type { Hex } from "./bytes.js";
import type { RootCommitment } from "./commitment.js";
import { checkpointOf } from "./commitment.js";
import { isReceiptRootError } from "./errors.js";
import { type ReceiptLeaf, sameDomain } from "./leaf.js";
import { buildReceiptTree } from "./merkle.js";

export type FindingCode =
  | "INVALID_LEAF_SET"
  | "DOMAIN_MISMATCH"
  | "EPOCH_MISMATCH"
  | "HEIGHT_BEYOND_CHECKPOINT"
  | "CHECKPOINT_MISMATCH"
  | "LEAF_COUNT_MISMATCH"
  | "KECCAK_ROOT_MISMATCH"
  | "BLAKE_ROOT_MISMATCH"
  | "STALE_NONCE"
  | "OWED_DECREASED"
  | "CONFLICTING_STATE"
  | "HEIGHT_REGRESSION"
  | "FIELD_CHANGED"
  | "CHANNEL_DROPPED";

export interface Finding {
  readonly code: FindingCode;
  readonly channelId?: Hex;
  readonly detail: string;
}

/**
 * Watcher check on a published snapshot: rebuild both trees from the published
 * leaf set and compare with the commitment. A KECCAK/BLAKE mismatch is the
 * evidence that the dual commitment was not built over the same leaves.
 */
export function auditSnapshot(c: RootCommitment, leaves: readonly ReceiptLeaf[], epochLength: bigint): Finding[] {
  const out: Finding[] = [];
  if (c.checkpointHeight !== checkpointOf(c.epoch, epochLength)) {
    out.push({ code: "CHECKPOINT_MISMATCH", detail: `checkpoint ${c.checkpointHeight} is not the end of epoch ${c.epoch}` });
  }
  for (const l of leaves) {
    if (!sameDomain(l, c)) out.push({ code: "DOMAIN_MISMATCH", channelId: l.channelId, detail: "leaf domain differs" });
    if (l.epoch !== c.epoch) out.push({ code: "EPOCH_MISMATCH", channelId: l.channelId, detail: `leaf epoch ${l.epoch}` });
    if (l.finalizedHeight > c.checkpointHeight) {
      out.push({ code: "HEIGHT_BEYOND_CHECKPOINT", channelId: l.channelId, detail: `finalized at ${l.finalizedHeight}` });
    }
  }
  let tree;
  try {
    tree = buildReceiptTree(leaves);
  } catch (e) {
    if (!isReceiptRootError(e)) throw e;
    out.push({ code: "INVALID_LEAF_SET", detail: e.message });
    return out;
  }
  if (BigInt(tree.leaves.length) !== c.leafCount) out.push({ code: "LEAF_COUNT_MISMATCH", detail: `${tree.leaves.length} != ${c.leafCount}` });
  if (tree.roots.keccak256 !== c.keccakRoot) out.push({ code: "KECCAK_ROOT_MISMATCH", detail: tree.roots.keccak256 });
  if (tree.roots.blake2b256 !== c.blakeRoot) out.push({ code: "BLAKE_ROOT_MISMATCH", detail: tree.roots.blake2b256 });
  return out;
}

/**
 * Watcher check across consecutive snapshots of one domain. Per channel, the
 * Flop monotonicity invariant (I4) must hold: nonce and owed never decrease,
 * one nonce has one content, identity fields never change. A dropped channel
 * is reported so the watcher can match it to a settlement.
 */
export function auditTransition(prev: readonly ReceiptLeaf[], next: readonly ReceiptLeaf[]): Finding[] {
  const out: Finding[] = [];
  const after = new Map(next.map((l) => [l.channelId, l] as const));
  for (const a of prev) {
    const b = after.get(a.channelId);
    const id = a.channelId;
    if (b === undefined) {
      out.push({ code: "CHANNEL_DROPPED", channelId: id, detail: "absent from the newer snapshot" });
      continue;
    }
    if (a.provider !== b.provider || a.payer !== b.payer || a.escrow !== b.escrow || !sameDomain(a, b)) {
      out.push({ code: "FIELD_CHANGED", channelId: id, detail: "parties, escrow or domain changed" });
    }
    if (b.nonce < a.nonce) out.push({ code: "STALE_NONCE", channelId: id, detail: `${b.nonce} < ${a.nonce}` });
    if (b.cumulativeOwed < a.cumulativeOwed) out.push({ code: "OWED_DECREASED", channelId: id, detail: `${b.cumulativeOwed} < ${a.cumulativeOwed}` });
    if (b.nonce === a.nonce && (b.cumulativeOwed !== a.cumulativeOwed || b.stateRoot !== a.stateRoot || b.finalizedHeight !== a.finalizedHeight)) {
      out.push({ code: "CONFLICTING_STATE", channelId: id, detail: `nonce ${a.nonce} has two contents` });
    }
    if (b.finalizedHeight < a.finalizedHeight) out.push({ code: "HEIGHT_REGRESSION", channelId: id, detail: `${b.finalizedHeight} < ${a.finalizedHeight}` });
  }
  return out;
}
