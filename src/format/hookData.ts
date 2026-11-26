import { type Hex, bytesToHex, concatBytes, hexToBytes, isHex } from "../bytes.js";
import { ErrorCode, fail, isReceiptRootError } from "../errors.js";
import { bytes32Word, readWord, uintWord, wordToUint } from "./abi.js";
import { type Settlement, validateSettlement } from "./settlement.js";

/** What a swap carries for IF-D8: `abi.encode(uint64 epoch, Settlement s, bytes32[] proof)`. The jobId is not in hookData; it is the event key `jobIdOf(s)`. */
export interface HookData {
  readonly epoch: bigint;
  readonly settlement: Settlement;
  readonly proof: readonly Hex[];
}

const SETTLEMENT_WORDS = 12;
const HEAD_WORDS = 1 + SETTLEMENT_WORDS + 1;

function settlementWords(s: Settlement): Uint8Array[] {
  return [
    bytes32Word(s.genesis),
    bytes32Word(s.channelId),
    uintWord(s.settledBlock, 64),
    bytes32Word(s.settledBlockHash),
    uintWord(s.eventIndex, 32),
    bytes32Word(s.agent),
    bytes32Word(s.miner),
    bytes32Word(s.modelHash),
    uintWord(s.aggregateGn, 128),
    uintWord(s.minerPaid, 128),
    uintWord(s.burned, 128),
    uintWord(s.escrow, 128),
  ];
}

export function encodeHookData(d: HookData): Hex {
  validateSettlement(d.settlement);
  return bytesToHex(
    concatBytes(
      uintWord(d.epoch, 64, "epoch"),
      ...settlementWords(d.settlement),
      uintWord(BigInt(32 * HEAD_WORDS), 256),
      uintWord(BigInt(d.proof.length), 256),
      ...d.proof.map((p) => bytes32Word(p, "proof element")),
    ),
  );
}

/**
 * Strict decoder: canonical offset, no trailing bytes, no dirty high bits, so
 * one (epoch, settlement, proof) has exactly one hookData. Solidity's
 * `abi.decode` alone accepts trailing bytes and other offsets; the reference
 * hook re-encodes and compares. The proof length cap is left to `verify`.
 */
export function decodeHookData(hex: Hex): HookData {
  try {
    return decodeStrict(hexToBytes(hex));
  } catch (e) {
    if (isReceiptRootError(e, ErrorCode.INVALID_INPUT)) fail(ErrorCode.BadHookData, e.message);
    throw e;
  }
}

function decodeStrict(data: Uint8Array): HookData {
  const w = (i: number) => readWord(data, i);
  const b32 = (i: number): Hex => bytesToHex(w(i));
  if (wordToUint(w(HEAD_WORDS - 1), 256) !== BigInt(32 * HEAD_WORDS)) fail(ErrorCode.INVALID_INPUT, "non-canonical proof offset");
  const n = wordToUint(w(HEAD_WORDS), 256);
  if (BigInt(data.length) !== 32n * (BigInt(HEAD_WORDS) + 1n + n)) fail(ErrorCode.INVALID_INPUT, "hookData length does not match the proof length");
  const settlement: Settlement = {
    genesis: b32(1),
    channelId: b32(2),
    settledBlock: wordToUint(w(3), 64),
    settledBlockHash: b32(4),
    eventIndex: wordToUint(w(5), 32),
    agent: b32(6),
    miner: b32(7),
    modelHash: b32(8),
    aggregateGn: wordToUint(w(9), 128),
    minerPaid: wordToUint(w(10), 128),
    burned: wordToUint(w(11), 128),
    escrow: wordToUint(w(12), 128),
  };
  const proof: Hex[] = [];
  for (let i = 0; i < Number(n); i++) proof.push(b32(HEAD_WORDS + 1 + i));
  if (!proof.every((p) => isHex(p, 32))) fail(ErrorCode.INVALID_INPUT, "bad proof element");
  return { epoch: wordToUint(w(0), 64), settlement, proof };
}
