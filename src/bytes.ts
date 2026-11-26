import { ErrorCode, fail } from "./errors.js";

/** Lowercase `0x`-prefixed hex string. */
export type Hex = `0x${string}`;

export const U64_MAX = (1n << 64n) - 1n;
export const U128_MAX = (1n << 128n) - 1n;
export const ZERO32: Hex = `0x${"00".repeat(32)}`;

const HEX_RE = /^0x(?:[0-9a-f]{2})*$/;

export function isHex(value: unknown, byteLength?: number): value is Hex {
  if (typeof value !== "string" || !HEX_RE.test(value)) return false;
  return byteLength === undefined || value.length === 2 + 2 * byteLength;
}

export function hexToBytes(hex: string): Uint8Array {
  if (!isHex(hex)) fail(ErrorCode.INVALID_INPUT, `not lowercase 0x-hex with whole bytes: ${String(hex).slice(0, 80)}`);
  const out = new Uint8Array((hex.length - 2) / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(2 + 2 * i, 4 + 2 * i), 16);
  return out;
}

export function bytesToHex(bytes: Uint8Array): Hex {
  let s = "0x";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s as Hex;
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const p of parts) length += p.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Big-endian, fixed width. Throws unless 0 <= value < 2^(8*width). */
export function uintBE(value: bigint, width: number): Uint8Array {
  if (typeof value !== "bigint" || value < 0n || value >= 1n << BigInt(8 * width)) {
    fail(ErrorCode.INVALID_INPUT, `value out of range for uint${8 * width}: ${String(value)}`);
  }
  const out = new Uint8Array(width);
  let v = value;
  for (let i = width - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function fixedBytes(hex: Hex, width: number, field: string): Uint8Array {
  if (!isHex(hex, width)) fail(ErrorCode.INVALID_INPUT, `${field} must be ${width} bytes of lowercase 0x-hex`);
  return hexToBytes(hex);
}

/** Unsigned lexicographic comparison of equal-length hex strings (lowercase). */
export function compareHex(a: Hex, b: Hex): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** UTF-8 encoding, written out so the library needs no platform globals. Lone surrogates become U+FFFD, as with TextEncoder. */
export function utf8(text: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < text.length; i++) {
    let cp = text.charCodeAt(i);
    if (cp >= 0xd800 && cp <= 0xdbff) {
      const next = i + 1 < text.length ? text.charCodeAt(i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        cp = 0x10000 + ((cp - 0xd800) << 10) + (next - 0xdc00);
        i++;
      } else {
        cp = 0xfffd;
      }
    } else if (cp >= 0xdc00 && cp <= 0xdfff) {
      cp = 0xfffd;
    }
    if (cp < 0x80) out.push(cp);
    else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
  }
  return Uint8Array.from(out);
}
