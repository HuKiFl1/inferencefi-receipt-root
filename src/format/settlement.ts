import { type Hex, U64_MAX, U128_MAX, bytesToHex, concatBytes, isHex, utf8 } from "../bytes.js";
import { ErrorCode, fail } from "../errors.js";
import { keccak256 } from "../hash/index.js";
import { bytes32Word, uintWord } from "./abi.js";

/**
 * One finalized `computeChannel.Settled` (or force-settled) event, exactly as
 * FlopReceiptRoot v0.3.2 `Settlement` declares it. Accounts are 32-byte
 * public keys; amounts are whatever the Flop event carries (per-event vs
 * cumulative is open: flop-receipt-root issue #4, question 2).
 */
export interface Settlement {
  readonly genesis: Hex;
  readonly channelId: Hex;
  readonly settledBlock: bigint;
  readonly settledBlockHash: Hex;
  readonly eventIndex: bigint;
  readonly agent: Hex;
  readonly miner: Hex;
  readonly modelHash: Hex;
  readonly aggregateGn: bigint;
  readonly minerPaid: bigint;
  readonly burned: bigint;
  readonly escrow: bigint;
}

export const LEAF_TYPE =
  "FlopSettlementLeaf(bytes32 genesis,bytes32 channelId,uint64 settledBlock,bytes32 settledBlockHash,uint32 eventIndex,bytes32 agent,bytes32 miner,bytes32 modelHash,uint128 aggregateGn,uint128 minerPaid,uint128 burned,uint128 escrow)";
export const LEAF_TYPEHASH: Hex = bytesToHex(keccak256(utf8(LEAF_TYPE)));

/** `abi.encode(LEAF_TYPEHASH, ...fields)`: 13 words, 416 bytes. */
export const SETTLEMENT_ENCODING_BYTES = 416;

const U32_MAX = (1n << 32n) - 1n;

export function validateSettlement(s: Settlement): void {
  for (const k of ["genesis", "channelId", "settledBlockHash", "agent", "miner", "modelHash"] as const) {
    if (!isHex(s[k], 32)) fail(ErrorCode.INVALID_INPUT, `${k} must be 32 bytes of lowercase 0x-hex`);
  }
  const widths = [
    ["settledBlock", U64_MAX],
    ["eventIndex", U32_MAX],
    ["aggregateGn", U128_MAX],
    ["minerPaid", U128_MAX],
    ["burned", U128_MAX],
    ["escrow", U128_MAX],
  ] as const;
  for (const [k, max] of widths) {
    const v = s[k];
    if (typeof v !== "bigint" || v < 0n || v > max) fail(ErrorCode.INVALID_INPUT, `${k} = ${String(v)} is out of range`);
  }
}

export function encodeSettlement(s: Settlement): Uint8Array {
  validateSettlement(s);
  return concatBytes(
    bytes32Word(LEAF_TYPEHASH),
    bytes32Word(s.genesis, "genesis"),
    bytes32Word(s.channelId, "channelId"),
    uintWord(s.settledBlock, 64, "settledBlock"),
    bytes32Word(s.settledBlockHash, "settledBlockHash"),
    uintWord(s.eventIndex, 32, "eventIndex"),
    bytes32Word(s.agent, "agent"),
    bytes32Word(s.miner, "miner"),
    bytes32Word(s.modelHash, "modelHash"),
    uintWord(s.aggregateGn, 128, "aggregateGn"),
    uintWord(s.minerPaid, 128, "minerPaid"),
    uintWord(s.burned, 128, "burned"),
    uintWord(s.escrow, 128, "escrow"),
  );
}

/** `keccak256(keccak256(abi.encode(LEAF_TYPEHASH, ...)))`, as `FlopReceiptRoot.leafOf`. */
export function leafOf(s: Settlement): Hex {
  return bytesToHex(keccak256(keccak256(encodeSettlement(s))));
}

/** The settlement tuple in the shape upstream epoch files use (integers as decimal strings). */
export interface SettlementJson {
  readonly genesis: string;
  readonly channelId: string;
  readonly settledBlock: string;
  readonly settledBlockHash: string;
  readonly eventIndex: string;
  readonly agent: string;
  readonly miner: string;
  readonly modelHash: string;
  readonly aggregateGn: string;
  readonly minerPaid: string;
  readonly burned: string;
  readonly escrow: string;
}

const uint = (v: unknown, field: string): bigint => {
  const s = String(v);
  if (!/^\d+$/.test(s)) fail(ErrorCode.INVALID_INPUT, `${field} is not a decimal integer`);
  return BigInt(s);
};
const b32 = (v: unknown, field: string): Hex => {
  const s = String(v).toLowerCase();
  if (!isHex(s, 32)) fail(ErrorCode.INVALID_INPUT, `${field} is not 32-byte hex`);
  return s;
};

export function settlementFromJson(j: SettlementJson): Settlement {
  const s: Settlement = {
    genesis: b32(j.genesis, "genesis"),
    channelId: b32(j.channelId, "channelId"),
    settledBlock: uint(j.settledBlock, "settledBlock"),
    settledBlockHash: b32(j.settledBlockHash, "settledBlockHash"),
    eventIndex: uint(j.eventIndex, "eventIndex"),
    agent: b32(j.agent, "agent"),
    miner: b32(j.miner, "miner"),
    modelHash: b32(j.modelHash, "modelHash"),
    aggregateGn: uint(j.aggregateGn, "aggregateGn"),
    minerPaid: uint(j.minerPaid, "minerPaid"),
    burned: uint(j.burned, "burned"),
    escrow: uint(j.escrow, "escrow"),
  };
  validateSettlement(s);
  return s;
}

export function settlementToJson(s: Settlement): SettlementJson {
  return {
    genesis: s.genesis,
    channelId: s.channelId,
    settledBlock: s.settledBlock.toString(),
    settledBlockHash: s.settledBlockHash,
    eventIndex: s.eventIndex.toString(),
    agent: s.agent,
    miner: s.miner,
    modelHash: s.modelHash,
    aggregateGn: s.aggregateGn.toString(),
    minerPaid: s.minerPaid.toString(),
    burned: s.burned.toString(),
    escrow: s.escrow.toString(),
  };
}
