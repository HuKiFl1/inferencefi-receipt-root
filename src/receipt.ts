import type { Hex } from "./bytes.js";
import type { RootCommitment } from "./commitment.js";
import { ErrorCode, fail, isReceiptRootError } from "./errors.js";
import { BLAKE2B256, type HashFn, KECCAK256 } from "./hash/index.js";
import { type ReceiptLeaf, leafHash, sameDomain, validateLeaf } from "./leaf.js";
import { type MerkleProof, verifyProof } from "./merkle.js";
import type { RootRegistry } from "./registry.js";

/** What a claimant submits: the jobId of an accepted root, the leaf fields, and a keccak proof. */
export interface ReceiptClaim {
  readonly jobId: Hex;
  readonly leaf: ReceiptLeaf;
  readonly proof: MerkleProof;
}

/**
 * Checks shared by every consumer. The verifier hashes the leaf fields itself
 * and never accepts a caller-supplied leaf hash.
 */
export function verifyAgainstCommitment(c: RootCommitment, leaf: ReceiptLeaf, proof: MerkleProof, hash: HashFn): void {
  try {
    validateLeaf(leaf);
  } catch (e) {
    if (isReceiptRootError(e)) fail(ErrorCode.INVALID_LEAF, e.message);
    throw e;
  }
  if (!sameDomain(leaf, c)) fail(ErrorCode.DOMAIN_MISMATCH, "leaf is for another chain, pool or FLOP network");
  if (leaf.epoch !== c.epoch) fail(ErrorCode.EPOCH_MISMATCH, `leaf epoch ${leaf.epoch} != root epoch ${c.epoch}`);
  if (leaf.finalizedHeight > c.checkpointHeight) {
    fail(ErrorCode.HEIGHT_BEYOND_CHECKPOINT, `leaf finalized at ${leaf.finalizedHeight} > checkpoint ${c.checkpointHeight}`);
  }
  const root = hash.id === "keccak256" ? c.keccakRoot : c.blakeRoot;
  if (proof.leafCount !== c.leafCount || !verifyProof(hash, root, leafHash(leaf, hash), proof)) {
    fail(ErrorCode.INVALID_PROOF, "Merkle proof does not verify against the committed root");
  }
}

/** EVM-side check (keccak). Returns the commitment the receipt was proven against. */
export function verifyReceipt(registry: RootRegistry, claim: ReceiptClaim): RootCommitment {
  const c = registry.byJobId(claim.jobId);
  if (c === undefined) fail(ErrorCode.UNKNOWN_ROOT, `jobId ${claim.jobId} is not an accepted root`);
  verifyAgainstCommitment(c, claim.leaf, claim.proof, KECCAK256);
  return c;
}

/** FLOP-side check (blake2b-256) against the same commitment. */
export function verifyReceiptFlop(c: RootCommitment, leaf: ReceiptLeaf, proof: MerkleProof): void {
  verifyAgainstCommitment(c, leaf, proof, BLAKE2B256);
}
