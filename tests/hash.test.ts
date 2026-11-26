import { keccak_256 as nobleKeccak } from "@noble/hashes/sha3.js";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { bytesToHex, keccak256, utf8 } from "../src/index.js";
const RUNS = Number(process.env.PROPERTY_RUNS ?? 100);

describe("keccak-256 (FIPS 202 permutation, Keccak padding)", () => {
  it("matches published digests", () => {
    expect(bytesToHex(keccak256(new Uint8Array()))).toBe("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    expect(bytesToHex(keccak256(utf8("abc")))).toBe("0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
  });

  it("handles every length around the 136-byte rate boundary", () => {
    for (let n = 0; n <= 3 * 136 + 1; n++) {
      const m = new Uint8Array(n).map((_, i) => (i * 7 + n) & 0xff);
      expect(bytesToHex(keccak256(m))).toBe(bytesToHex(nobleKeccak(m)));
    }
  });

  it("agrees with an independent implementation on random input", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 1200 }), (m) => bytesToHex(keccak256(m)) === bytesToHex(nobleKeccak(m))),
      { numRuns: RUNS * 3 },
    );
  });
});

describe("utf8", () => {
  it("matches TextEncoder, including astral characters and lone surrogates", () => {
    const units = fc.array(fc.oneof(fc.integer({ min: 0, max: 0x7f }), fc.integer({ min: 0, max: 0xffff }), fc.integer({ min: 0xd800, max: 0xdfff })), { maxLength: 64 });
    fc.assert(
      fc.property(units, (u) => {
        const s = String.fromCharCode(...u);
        return bytesToHex(utf8(s)) === bytesToHex(new TextEncoder().encode(s));
      }),
      { numRuns: RUNS * 3 },
    );
    expect(bytesToHex(utf8("é€😀"))).toBe("0xc3a9e282acf09f9880");
  });
});
