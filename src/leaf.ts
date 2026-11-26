import { type Hex, U64_MAX, U128_MAX, ZERO32, bytesToHex, concatBytes, fixedBytes, isHex, uintBE } from "./bytes.js";
import { ErrorCode, fail } from "./errors.js";
import type { HashFn } from "./hash/index.js";

/** One-byte type prefixes. Every hashed preimage in this package starts with exactly one. */
export const Prefix = {
  LEAF: 0x00,
  NODE: 0x01,
  JOB_ID: 0x02,
  NULLIFIER: 0x03,
} as const;

export const LEAF_VERSION = 1;
/** Encoded leaf body length in bytes, without the 0x00 prefix. */
export const LEAF_BYTES = 257;

/**
 * Where a receipt may be consumed. A receipt for one domain never verifies in
 * another: every field is inside the leaf preimage.
 */
export interface ReceiptDomain {
  /** FLOP network identity (genesis block hash). 32 bytes. */
  readonly flopGenesis: Hex;
  /** EVM chain the receipt is consumed on, e.g. 998 for HyperEVM testnet. */
  readonly evmChainId: bigint;
  /** Uniswap-v4 PoolId, which already commits to the hook address via PoolKey. 32 bytes. */
  readonly poolId: Hex;
}

/**
 * A finalized FLOP channel state, in the sense of the Flop reclaim spec
 * (§4.2: `σ = (nonce, owed, root, h)`), plus the channel's fixed identity.
 * The implicit opening state `σ₀` is a leaf with `nonce = 0`, `cumulativeOwed = 0`,
 * `stateRoot = 0x00…00` and `finalizedHeight = h_open`.
 */
export interface ReceiptLeaf extends ReceiptDomain {
  readonly channelId: Hex;
  /** FLOP account of the provider (miner). 32 bytes. */
  readonly provider: Hex;
  /** FLOP account of the payer (agent). 32 bytes. */
  readonly payer: Hex;
  /** Cumulative amount owed to the provider, in OMER base units (uint128). */
  readonly cumulativeOwed: bigint;
  /** Channel escrow `E = L + D`, fixed at open (uint128). */
  readonly escrow: bigint;
  /** Strictly increasing per channel. 0 only for `σ₀`. */
  readonly nonce: bigint;
  /** Epoch of the snapshot root that contains this leaf. */
  readonly epoch: bigint;
  /** FLOP finalized height at which this state was recorded (`σ.h`). */
  readonly finalizedHeight: bigint;
  /** The co-signed channel state root (`σ.root`). Zero only for `σ₀`. */
  readonly stateRoot: Hex;
}

function u64(value: unknown, field: string): void {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX) fail(ErrorCode.INVALID_LEAF, `${field} must be a uint64 bigint`);
}

function u128(value: unknown, field: string): void {
  if (typeof value !== "bigint" || value < 0n || value > U128_MAX) fail(ErrorCode.INVALID_LEAF, `${field} must be a uint128 bigint`);
}

function b32(value: unknown, field: string, nonZero: boolean): void {
  if (!isHex(value, 32)) fail(ErrorCode.INVALID_LEAF, `${field} must be 32 bytes of lowercase 0x-hex`);
  if (nonZero && value === ZERO32) fail(ErrorCode.INVALID_LEAF, `${field} must be non-zero`);
}

export function validateDomain(d: ReceiptDomain): void {
  b32(d.flopGenesis, "flopGenesis", true);
  u64(d.evmChainId, "evmChainId");
  if (d.evmChainId === 0n) fail(ErrorCode.INVALID_LEAF, "evmChainId must be >= 1");
  b32(d.poolId, "poolId", true);
}

export function validateLeaf(leaf: ReceiptLeaf): void {
  validateDomain(leaf);
  b32(leaf.channelId, "channelId", true);
  b32(leaf.provider, "provider", true);
  b32(leaf.payer, "payer", true);
  if (leaf.provider === leaf.payer) fail(ErrorCode.INVALID_LEAF, "payer and provider must differ");
  u128(leaf.cumulativeOwed, "cumulativeOwed");
  u128(leaf.escrow, "escrow");
  u64(leaf.nonce, "nonce");
  u64(leaf.epoch, "epoch");
  u64(leaf.finalizedHeight, "finalizedHeight");
  b32(leaf.stateRoot, "stateRoot", false);
  if (leaf.nonce === 0n) {
    if (leaf.cumulativeOwed !== 0n || leaf.stateRoot !== ZERO32) {
      fail(ErrorCode.INVALID_LEAF, "nonce 0 is the opening state: cumulativeOwed must be 0 and stateRoot zero");
    }
  } else if (leaf.stateRoot === ZERO32) {
    fail(ErrorCode.INVALID_LEAF, "a finalized state (nonce >= 1) must carry a non-zero stateRoot");
  }
}

/**
 * Fixed-width big-endian body, 257 bytes. Byte-identical to Solidity
 * `abi.encodePacked(uint8 version, bytes32, uint64, bytes32, bytes32, bytes32,
 * bytes32, uint128, uint128, uint64, uint64, uint64, bytes32)`.
 */
export function encodeLeaf(leaf: ReceiptLeaf): Uint8Array {
  validateLeaf(leaf);
  const out = concatBytes(
    uintBE(BigInt(LEAF_VERSION), 1),
    fixedBytes(leaf.flopGenesis, 32, "flopGenesis"),
    uintBE(leaf.evmChainId, 8),
    fixedBytes(leaf.poolId, 32, "poolId"),
    fixedBytes(leaf.channelId, 32, "channelId"),
    fixedBytes(leaf.provider, 32, "provider"),
    fixedBytes(leaf.payer, 32, "payer"),
    uintBE(leaf.cumulativeOwed, 16),
    uintBE(leaf.escrow, 16),
    uintBE(leaf.nonce, 8),
    uintBE(leaf.epoch, 8),
    uintBE(leaf.finalizedHeight, 8),
    fixedBytes(leaf.stateRoot, 32, "stateRoot"),
  );
  if (out.length !== LEAF_BYTES) fail(ErrorCode.INVALID_LEAF, `encoded leaf has ${out.length} bytes`);
  return out;
}

/** `H(0x00 ‖ encodeLeaf(leaf))`. */
export function leafHashBytes(leaf: ReceiptLeaf, hash: HashFn): Uint8Array {
  return hash(concatBytes(Uint8Array.of(Prefix.LEAF), encodeLeaf(leaf)));
}

export function leafHash(leaf: ReceiptLeaf, hash: HashFn): Hex {
  return bytesToHex(leafHashBytes(leaf, hash));
}

export function sameDomain(a: ReceiptDomain, b: ReceiptDomain): boolean {
  return a.flopGenesis === b.flopGenesis && a.evmChainId === b.evmChainId && a.poolId === b.poolId;
}
