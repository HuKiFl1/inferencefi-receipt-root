import { type Hex, concatBytes, fixedBytes, uintBE } from "../bytes.js";
import { ErrorCode, fail } from "../errors.js";

/** One 32-byte ABI word for a `uint<bits>`. Throws instead of truncating. */
export function uintWord(value: bigint, bits: number, field = "value"): Uint8Array {
  if (typeof value !== "bigint" || value < 0n || value >= 1n << BigInt(bits)) {
    fail(ErrorCode.INVALID_INPUT, `${field} = ${String(value)} does not fit uint${bits}`);
  }
  return uintBE(value, 32);
}

export function bytes32Word(value: Hex, field = "value"): Uint8Array {
  return fixedBytes(value, 32, field);
}

/** An `address` as an ABI word: 12 zero bytes, then the 20 address bytes. */
export function addressWord(value: Hex, field = "address"): Uint8Array {
  return concatBytes(new Uint8Array(12), fixedBytes(value, 20, field));
}

export function readWord(data: Uint8Array, index: number): Uint8Array {
  const start = 32 * index;
  if (start + 32 > data.length) fail(ErrorCode.INVALID_INPUT, `ABI data ends before word ${index}`);
  return data.subarray(start, start + 32);
}

export function wordToUint(word: Uint8Array, bits: number, field = "value"): bigint {
  let v = 0n;
  for (const b of word) v = (v << 8n) | BigInt(b);
  if (v >= 1n << BigInt(bits)) fail(ErrorCode.INVALID_INPUT, `${field} has dirty high bits for uint${bits}`);
  return v;
}
