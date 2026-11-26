import { type Hex, U64_MAX, bytesToHex, concatBytes, fixedBytes, isHex, uintBE } from "./bytes.js";
import { ErrorCode, fail } from "./errors.js";
import { BLAKE2B256, KECCAK256 } from "./hash/index.js";
import { LEAF_VERSION, Prefix, type ReceiptDomain, type ReceiptLeaf, sameDomain, validateDomain } from "./leaf.js";
import { type ReceiptTree, buildReceiptTree, emptyRoot } from "./merkle.js";

/**
 * Epochs are measured in FLOP finalized heights, anchored at height 0:
 * epoch `e` covers `[e·len, (e+1)·len − 1]` and its checkpoint is the last height.
 */
export function epochOf(height: bigint, epochLength: bigint): bigint {
  if (epochLength < 1n || height < 0n) fail(ErrorCode.INVALID_INPUT, "epochOf: need epochLength >= 1 and height >= 0");
  return height / epochLength;
}

export function checkpointOf(epoch: bigint, epochLength: bigint): bigint {
  if (epochLength < 1n || epoch < 0n) fail(ErrorCode.INVALID_INPUT, "checkpointOf: need epochLength >= 1 and epoch >= 0");
  return (epoch + 1n) * epochLength - 1n;
}

/**
 * What the attesters sign and the EVM registry stores. Both roots cover the
 * same leaf bytes in the same order. Only `keccakRoot` is checked on the EVM.
 * `blakeRoot` is bound here so the FLOP-side commitment cannot be swapped later.
 */
export interface RootCommitment extends ReceiptDomain {
  /** Uniswap-v4 hook contract that tags swaps with this jobId. 20 bytes. */
  readonly hook: Hex;
  readonly epoch: bigint;
  /** FLOP finalized height the snapshot was taken at: `checkpointOf(epoch)`. */
  readonly checkpointHeight: bigint;
  readonly leafCount: bigint;
  readonly keccakRoot: Hex;
  readonly blakeRoot: Hex;
}

export function validateCommitment(c: RootCommitment): void {
  validateDomain(c);
  if (!isHex(c.hook, 20)) fail(ErrorCode.INVALID_INPUT, "hook must be a 20-byte address in lowercase 0x-hex");
  for (const [k, v] of [["epoch", c.epoch], ["checkpointHeight", c.checkpointHeight], ["leafCount", c.leafCount]] as const) {
    if (typeof v !== "bigint" || v < 0n || v > U64_MAX) fail(ErrorCode.INVALID_INPUT, `${k} must be a uint64 bigint`);
  }
  if (!isHex(c.keccakRoot, 32) || !isHex(c.blakeRoot, 32)) fail(ErrorCode.INVALID_INPUT, "roots must be 32 bytes");
}

/**
 * IF-D8 proposal: the hook's jobId is a domain-separated commitment to the
 * receipt roots, not the raw root.
 *
 *   jobId = keccak256(0x02 ‖ uint8 version ‖ flopGenesis ‖ uint64 evmChainId ‖ address hook ‖ poolId
 *                     ‖ uint64 epoch ‖ uint64 checkpointHeight ‖ uint64 leafCount ‖ keccakRoot ‖ blakeRoot)
 */
export function jobIdOf(c: RootCommitment): Hex {
  validateCommitment(c);
  return bytesToHex(
    KECCAK256(
      concatBytes(
        Uint8Array.of(Prefix.JOB_ID, LEAF_VERSION),
        fixedBytes(c.flopGenesis, 32, "flopGenesis"),
        uintBE(c.evmChainId, 8),
        fixedBytes(c.hook, 20, "hook"),
        fixedBytes(c.poolId, 32, "poolId"),
        uintBE(c.epoch, 8),
        uintBE(c.checkpointHeight, 8),
        uintBE(c.leafCount, 8),
        fixedBytes(c.keccakRoot, 32, "keccakRoot"),
        fixedBytes(c.blakeRoot, 32, "blakeRoot"),
      ),
    ),
  );
}

/**
 * Once-per-epoch key for AgentRewards (IF-F11). It is keyed by the receipt's
 * identity (domain, channel, epoch), not by the root or the leaf index, so a
 * channel listed twice, or in two roots, still nullifies once.
 *
 *   nullifier = keccak256(0x03 ‖ uint8 version ‖ flopGenesis ‖ uint64 evmChainId ‖ poolId ‖ channelId ‖ uint64 epoch)
 */
export function nullifierOf(leaf: Pick<ReceiptLeaf, "flopGenesis" | "evmChainId" | "poolId" | "channelId" | "epoch">): Hex {
  return bytesToHex(
    KECCAK256(
      concatBytes(
        Uint8Array.of(Prefix.NULLIFIER, LEAF_VERSION),
        fixedBytes(leaf.flopGenesis, 32, "flopGenesis"),
        uintBE(leaf.evmChainId, 8),
        fixedBytes(leaf.poolId, 32, "poolId"),
        fixedBytes(leaf.channelId, 32, "channelId"),
        uintBE(leaf.epoch, 8),
      ),
    ),
  );
}

export interface SnapshotMeta {
  readonly domain: ReceiptDomain;
  readonly hook: Hex;
  readonly epoch: bigint;
  readonly epochLength: bigint;
}

export interface Snapshot {
  readonly commitment: RootCommitment;
  readonly jobId: Hex;
  readonly tree: ReceiptTree;
}

/**
 * What an honest attester builds at an epoch checkpoint: the latest finalized
 * state of every unsettled channel in the domain, one leaf per channel.
 */
export function buildSnapshot(meta: SnapshotMeta, leaves: readonly ReceiptLeaf[]): Snapshot {
  validateDomain(meta.domain);
  const checkpointHeight = checkpointOf(meta.epoch, meta.epochLength);
  for (const leaf of leaves) {
    if (!sameDomain(leaf, meta.domain)) fail(ErrorCode.DOMAIN_MISMATCH, `leaf ${leaf.channelId} is for another domain`);
    if (leaf.epoch !== meta.epoch) fail(ErrorCode.EPOCH_MISMATCH, `leaf ${leaf.channelId} has epoch ${leaf.epoch}, snapshot is ${meta.epoch}`);
    if (leaf.finalizedHeight > checkpointHeight) {
      fail(ErrorCode.HEIGHT_BEYOND_CHECKPOINT, `leaf ${leaf.channelId} finalized at ${leaf.finalizedHeight} > checkpoint ${checkpointHeight}`);
    }
  }
  const tree = buildReceiptTree(leaves);
  const commitment: RootCommitment = {
    flopGenesis: meta.domain.flopGenesis,
    evmChainId: meta.domain.evmChainId,
    poolId: meta.domain.poolId,
    hook: meta.hook,
    epoch: meta.epoch,
    checkpointHeight,
    leafCount: BigInt(tree.leaves.length),
    keccakRoot: tree.roots.keccak256,
    blakeRoot: tree.roots.blake2b256,
  };
  return { commitment, jobId: jobIdOf(commitment), tree };
}

export const EMPTY_KECCAK_ROOT: Hex = emptyRoot(KECCAK256);
export const EMPTY_BLAKE_ROOT: Hex = emptyRoot(BLAKE2B256);
