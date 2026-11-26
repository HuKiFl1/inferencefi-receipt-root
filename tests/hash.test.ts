import { blake2b as nobleBlake2b } from "@noble/hashes/blake2.js";
import { keccak_256 as nobleKeccak } from "@noble/hashes/sha3.js";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { blake2b, blake2b256, bytesToHex, keccak256, utf8 } from "../src/index.js";
import { RUNS } from "./helpers.js";

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

describe("BLAKE2b (RFC 7693)", () => {
  it("matches RFC 7693 Appendix A (BLAKE2b-512 of 'abc')", () => {
    expect(bytesToHex(blake2b(utf8("abc"), 64))).toBe(
      "0xba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    );
  });

  it("matches published BLAKE2b-256 digests", () => {
    expect(bytesToHex(blake2b256(new Uint8Array()))).toBe("0x0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
    expect(bytesToHex(blake2b256(utf8("abc")))).toBe("0xbddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
  });

  it("handles every length around the 128-byte block boundary", () => {
    for (let n = 0; n <= 3 * 128 + 1; n++) {
      const m = new Uint8Array(n).map((_, i) => (i * 13 + n) & 0xff);
      expect(bytesToHex(blake2b256(m))).toBe(bytesToHex(nobleBlake2b(m, { dkLen: 32 })));
    }
  });

  it("agrees with an independent implementation for every digest length", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 700 }), fc.integer({ min: 1, max: 64 }), (m, outLen) => {
        return bytesToHex(blake2b(m, outLen)) === bytesToHex(nobleBlake2b(m, { dkLen: outLen }));
      }),
      { numRuns: RUNS * 3 },
    );
  });

  it("rejects digest lengths outside 1..64", () => {
    expect(() => blake2b(new Uint8Array(), 0)).toThrow(RangeError);
    expect(() => blake2b(new Uint8Array(), 65)).toThrow(RangeError);
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
