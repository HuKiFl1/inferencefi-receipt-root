/**
 * Unkeyed BLAKE2b with a configurable digest length, written from RFC 7693
 * §2–§3. BLAKE2b-256 (`outLen = 32`) is the hash Substrate exposes as
 * `blake2_256`. Words are 64-bit little-endian, held as two 32-bit halves.
 */

const BLOCK_BYTES = 128;
const ROUNDS = 12;

/** RFC 7693 §2.6: the SHA-512 initial values, as [lo, hi] halves. */
const IV: readonly number[] = [
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
  0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
];

/** RFC 7693 §2.7 message schedule. Rounds 10 and 11 reuse rows 0 and 1. */
const SIGMA: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/** v[i] += v[j] + (x | y halves), in place on word indices. */
function add3(v: Uint32Array, i: number, j: number, xlo: number, xhi: number): void {
  const lo = v[2 * i]! + v[2 * j]! + xlo;
  const carry = Math.floor(lo / 0x100000000);
  v[2 * i] = lo >>> 0;
  v[2 * i + 1] = (v[2 * i + 1]! + v[2 * j + 1]! + xhi + carry) >>> 0;
}

/** v[d] = rotr64(v[d] ^ v[a], n) for n in {16, 24, 32, 63}. */
function xorRotr(v: Uint32Array, d: number, a: number, n: number): void {
  const lo = (v[2 * d]! ^ v[2 * a]!) >>> 0;
  const hi = (v[2 * d + 1]! ^ v[2 * a + 1]!) >>> 0;
  if (n === 32) {
    v[2 * d] = hi;
    v[2 * d + 1] = lo;
  } else if (n < 32) {
    v[2 * d] = ((lo >>> n) | (hi << (32 - n))) >>> 0;
    v[2 * d + 1] = ((hi >>> n) | (lo << (32 - n))) >>> 0;
  } else {
    const m = n - 32;
    v[2 * d] = ((hi >>> m) | (lo << (32 - m))) >>> 0;
    v[2 * d + 1] = ((lo >>> m) | (hi << (32 - m))) >>> 0;
  }
}

function g(v: Uint32Array, m: Uint32Array, a: number, b: number, c: number, d: number, x: number, y: number): void {
  add3(v, a, b, m[2 * x]!, m[2 * x + 1]!);
  xorRotr(v, d, a, 32);
  add3(v, c, d, 0, 0);
  xorRotr(v, b, c, 24);
  add3(v, a, b, m[2 * y]!, m[2 * y + 1]!);
  xorRotr(v, d, a, 16);
  add3(v, c, d, 0, 0);
  xorRotr(v, b, c, 63);
}

/** RFC 7693 §3.2 compression F. `t` is the byte counter (< 2^53 here). */
function compress(h: Uint32Array, block: Uint8Array, t: number, last: boolean): void {
  const m = new Uint32Array(32);
  for (let i = 0; i < 32; i++) {
    const o = 4 * i;
    m[i] = (block[o]! | (block[o + 1]! << 8) | (block[o + 2]! << 16) | (block[o + 3]! << 24)) >>> 0;
  }
  const v = new Uint32Array(32);
  v.set(h, 0);
  v.set(IV, 16);
  v[24] = (v[24]! ^ (t >>> 0)) >>> 0;
  v[25] = (v[25]! ^ Math.floor(t / 0x100000000)) >>> 0;
  if (last) {
    v[28] = ~v[28]! >>> 0;
    v[29] = ~v[29]! >>> 0;
  }
  for (let r = 0; r < ROUNDS; r++) {
    const s = SIGMA[r % 10]!;
    g(v, m, 0, 4, 8, 12, s[0]!, s[1]!);
    g(v, m, 1, 5, 9, 13, s[2]!, s[3]!);
    g(v, m, 2, 6, 10, 14, s[4]!, s[5]!);
    g(v, m, 3, 7, 11, 15, s[6]!, s[7]!);
    g(v, m, 0, 5, 10, 15, s[8]!, s[9]!);
    g(v, m, 1, 6, 11, 12, s[10]!, s[11]!);
    g(v, m, 2, 7, 8, 13, s[12]!, s[13]!);
    g(v, m, 3, 4, 9, 14, s[14]!, s[15]!);
  }
  for (let i = 0; i < 16; i++) h[i] = (h[i]! ^ v[i]! ^ v[i + 16]!) >>> 0;
}

export function blake2b(message: Uint8Array, outLen = 64): Uint8Array {
  if (!Number.isInteger(outLen) || outLen < 1 || outLen > 64) throw new RangeError("blake2b: outLen must be 1..64");
  const h = new Uint32Array(IV);
  h[0] = (h[0]! ^ 0x01010000 ^ outLen) >>> 0;
  let offset = 0;
  while (message.length - offset > BLOCK_BYTES) {
    compress(h, message.subarray(offset, offset + BLOCK_BYTES), offset + BLOCK_BYTES, false);
    offset += BLOCK_BYTES;
  }
  const last = new Uint8Array(BLOCK_BYTES);
  last.set(message.subarray(offset));
  compress(h, last, message.length, true);
  const out = new Uint8Array(outLen);
  for (let i = 0; i < outLen; i++) out[i] = (h[i >>> 2]! >>> (8 * (i & 3))) & 0xff;
  return out;
}

export function blake2b256(message: Uint8Array): Uint8Array {
  return blake2b(message, 32);
}
