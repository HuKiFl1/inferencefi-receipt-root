/**
 * Keccak-256 as used by the EVM `KECCAK256` opcode: Keccak[c = 512] with the
 * original multi-rate padding `pad10*1` and domain byte 0x01 (not the SHA3-256
 * byte 0x06). Written from NIST FIPS 202 §3 (step mappings), §5.1 (pad10*1)
 * and Algorithm 5 (round constants). 64-bit lanes are held as two 32-bit
 * halves so no BigInt arithmetic runs in the permutation.
 */

const ROUNDS = 24;
const RATE_BYTES = 136;

/** FIPS 202 Algorithm 5: rc(t), one bit of the round-constant LFSR. */
function rcBit(t: number): number {
  if (t % 255 === 0) return 1;
  // R[0..7] as an array of bits, R = 10000000.
  let r = [1, 0, 0, 0, 0, 0, 0, 0];
  for (let i = 1; i <= t % 255; i++) {
    const next = [0, ...r];
    next[0] = next[0]! ^ next[8]!;
    next[4] = next[4]! ^ next[8]!;
    next[5] = next[5]! ^ next[8]!;
    next[6] = next[6]! ^ next[8]!;
    r = next.slice(0, 8);
  }
  return r[0]!;
}

/** Round constants split into [lo, hi] 32-bit halves. */
const RC: readonly (readonly [number, number])[] = Array.from({ length: ROUNDS }, (_, ir) => {
  let lo = 0;
  let hi = 0;
  for (let j = 0; j <= 6; j++) {
    if (rcBit(j + 7 * ir) === 1) {
      const bit = (1 << j) - 1;
      if (bit < 32) lo |= 1 << bit;
      else hi |= 1 << (bit - 32);
    }
  }
  return [lo >>> 0, hi >>> 0] as const;
});

/** FIPS 202 §3.2.2 rho offsets, indexed by lane x + 5y. */
const RHO: readonly number[] = (() => {
  const out = new Array<number>(25).fill(0);
  let x = 1;
  let y = 0;
  for (let t = 0; t < 24; t++) {
    out[x + 5 * y] = (((t + 1) * (t + 2)) / 2) % 64;
    [x, y] = [y, (2 * x + 3 * y) % 5];
  }
  return out;
})();

function rotl(lo: number, hi: number, n: number): [number, number] {
  if (n === 0) return [lo, hi];
  if (n === 32) return [hi, lo];
  if (n < 32) return [((lo << n) | (hi >>> (32 - n))) >>> 0, ((hi << n) | (lo >>> (32 - n))) >>> 0];
  const m = n - 32;
  return [((hi << m) | (lo >>> (32 - m))) >>> 0, ((lo << m) | (hi >>> (32 - m))) >>> 0];
}

/** Keccak-f[1600] on 25 lanes; lane i is (s[2i] = low half, s[2i+1] = high half). */
function keccakF1600(s: Uint32Array): void {
  const c = new Uint32Array(10);
  const b = new Uint32Array(50);
  for (let round = 0; round < ROUNDS; round++) {
    // theta
    for (let x = 0; x < 5; x++) {
      let lo = 0;
      let hi = 0;
      for (let y = 0; y < 5; y++) {
        lo ^= s[2 * (x + 5 * y)]!;
        hi ^= s[2 * (x + 5 * y) + 1]!;
      }
      c[2 * x] = lo;
      c[2 * x + 1] = hi;
    }
    for (let x = 0; x < 5; x++) {
      const xm = (x + 4) % 5;
      const xp = (x + 1) % 5;
      const [rlo, rhi] = rotl(c[2 * xp]!, c[2 * xp + 1]!, 1);
      const dlo = c[2 * xm]! ^ rlo;
      const dhi = c[2 * xm + 1]! ^ rhi;
      for (let y = 0; y < 5; y++) {
        s[2 * (x + 5 * y)] = s[2 * (x + 5 * y)]! ^ dlo;
        s[2 * (x + 5 * y) + 1] = s[2 * (x + 5 * y) + 1]! ^ dhi;
      }
    }
    // rho and pi: B[y, 2x + 3y] = rot(A[x, y], r[x, y])
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const i = x + 5 * y;
        const [lo, hi] = rotl(s[2 * i]!, s[2 * i + 1]!, RHO[i]!);
        const j = y + 5 * ((2 * x + 3 * y) % 5);
        b[2 * j] = lo;
        b[2 * j + 1] = hi;
      }
    }
    // chi
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        const i = x + 5 * y;
        const i1 = ((x + 1) % 5) + 5 * y;
        const i2 = ((x + 2) % 5) + 5 * y;
        s[2 * i] = (b[2 * i]! ^ (~b[2 * i1]! & b[2 * i2]!)) >>> 0;
        s[2 * i + 1] = (b[2 * i + 1]! ^ (~b[2 * i1 + 1]! & b[2 * i2 + 1]!)) >>> 0;
      }
    }
    // iota
    const [rlo, rhi] = RC[round]!;
    s[0] = (s[0]! ^ rlo) >>> 0;
    s[1] = (s[1]! ^ rhi) >>> 0;
  }
}

function absorbBlock(s: Uint32Array, block: Uint8Array): void {
  for (let i = 0; i < RATE_BYTES / 8; i++) {
    const o = 8 * i;
    const lo = block[o]! | (block[o + 1]! << 8) | (block[o + 2]! << 16) | (block[o + 3]! << 24);
    const hi = block[o + 4]! | (block[o + 5]! << 8) | (block[o + 6]! << 16) | (block[o + 7]! << 24);
    s[2 * i] = (s[2 * i]! ^ lo) >>> 0;
    s[2 * i + 1] = (s[2 * i + 1]! ^ hi) >>> 0;
  }
  keccakF1600(s);
}

export function keccak256(message: Uint8Array): Uint8Array {
  const s = new Uint32Array(50);
  let offset = 0;
  while (message.length - offset >= RATE_BYTES) {
    absorbBlock(s, message.subarray(offset, offset + RATE_BYTES));
    offset += RATE_BYTES;
  }
  const last = new Uint8Array(RATE_BYTES);
  last.set(message.subarray(offset));
  last[message.length - offset] = last[message.length - offset]! ^ 0x01;
  last[RATE_BYTES - 1] = last[RATE_BYTES - 1]! ^ 0x80;
  absorbBlock(s, last);
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    const lo = s[2 * i]!;
    const hi = s[2 * i + 1]!;
    for (let k = 0; k < 4; k++) {
      out[8 * i + k] = (lo >>> (8 * k)) & 0xff;
      out[8 * i + 4 + k] = (hi >>> (8 * k)) & 0xff;
    }
  }
  return out;
}
