import { describe, expect, it } from "vitest";
import {
  BLAKE2B256,
  KECCAK256,
  LEAF_BYTES,
  type ReceiptLeaf,
  U64_MAX,
  U128_MAX,
  ZERO32,
  bytesToHex,
  concatBytes,
  encodeLeaf,
  hexToBytes,
  leafHash,
  omerFromUsage,
  OMER_UNIT,
} from "../src/index.js";
import { DOMAIN, codeOf, label, leafOf } from "./helpers.js";

const base: ReceiptLeaf = leafOf({ ch: "x", nonce: 3n, owed: 42n, escrow: 100n, height: 7n }, 0n);

describe("leaf encoding", () => {
  it("is 257 bytes with the documented field offsets", () => {
    const b = encodeLeaf(base);
    expect(b.length).toBe(LEAF_BYTES);
    const hex = (from: number, to: number) => bytesToHex(b.subarray(from, to));
    expect(b[0]).toBe(1);
    expect(hex(1, 33)).toBe(DOMAIN.flopGenesis);
    expect(BigInt(hex(33, 41))).toBe(998n);
    expect(hex(41, 73)).toBe(DOMAIN.poolId);
    expect(hex(73, 105)).toBe(base.channelId);
    expect(hex(105, 137)).toBe(base.provider);
    expect(hex(137, 169)).toBe(base.payer);
    expect(BigInt(hex(169, 185))).toBe(42n);
    expect(BigInt(hex(185, 201))).toBe(100n);
    expect(BigInt(hex(201, 209))).toBe(3n);
    expect(BigInt(hex(209, 217))).toBe(0n);
    expect(BigInt(hex(217, 225))).toBe(7n);
    expect(hex(225, 257)).toBe(base.stateRoot);
  });

  it("hashes as H(0x00 ‖ body) under both hash functions", () => {
    for (const h of [KECCAK256, BLAKE2B256]) {
      expect(leafHash(base, h)).toBe(bytesToHex(h(concatBytes(Uint8Array.of(0), encodeLeaf(base)))));
    }
    expect(leafHash(base, KECCAK256)).not.toBe(leafHash(base, BLAKE2B256));
  });

  it("accepts the uint64 / uint128 boundaries", () => {
    const max = { ...base, evmChainId: U64_MAX, cumulativeOwed: U128_MAX, escrow: U128_MAX, nonce: U64_MAX, epoch: U64_MAX, finalizedHeight: U64_MAX };
    expect(encodeLeaf(max).length).toBe(LEAF_BYTES);
  });

  it.each([
    ["owed above uint128", { cumulativeOwed: U128_MAX + 1n }],
    ["negative escrow", { escrow: -1n }],
    ["nonce above uint64", { nonce: U64_MAX + 1n }],
    ["number instead of bigint", { epoch: 1 as unknown as bigint }],
    ["chain id 0", { evmChainId: 0n }],
    ["zero channel id", { channelId: ZERO32 }],
    ["uppercase hex", { provider: base.provider.toUpperCase().replace("0X", "0x") as `0x${string}` }],
    ["short hex", { payer: "0x1234" as `0x${string}` }],
    ["payer equals provider", { payer: base.provider }],
    ["opening state with owed", { nonce: 0n, stateRoot: ZERO32 }],
    ["opening state with a state root", { nonce: 0n, cumulativeOwed: 0n }],
    ["finalized state without a state root", { stateRoot: ZERO32 }],
  ])("rejects %s", (_name, patch) => {
    expect(codeOf(() => encodeLeaf({ ...base, ...patch } as ReceiptLeaf))).toBe("INVALID_LEAF");
  });

  it("accepts the implicit opening state σ₀", () => {
    expect(codeOf(() => encodeLeaf({ ...base, nonce: 0n, cumulativeOwed: 0n, stateRoot: ZERO32 }))).toBe("OK");
  });

  it("hex helpers round-trip and reject malformed input", () => {
    const h = label("round-trip");
    expect(bytesToHex(hexToBytes(h))).toBe(h);
    expect(codeOf(() => hexToBytes("0xabc"))).toBe("INVALID_INPUT");
    expect(codeOf(() => hexToBytes("abcd"))).toBe("INVALID_INPUT");
  });
});

describe("OMER units", () => {
  it("750k input + 250k output tokens at reference prices is exactly 1 OMER", () => {
    expect(omerFromUsage({ inputTokens: 750_000n, outputTokens: 250_000n, inputPrice: 3n, outputPrice: 15n })).toBe(OMER_UNIT);
    expect(omerFromUsage({ inputTokens: 1_500_000n, outputTokens: 500_000n, inputPrice: 1n, outputPrice: 4n })).toBe(2n * OMER_UNIT);
  });

  it("rounds down, and cumulative conversion never loses more than one base unit", () => {
    const p = { inputPrice: 3n, outputPrice: 15n };
    const perCall = [1n, 2n, 3n].map((k) => omerFromUsage({ inputTokens: k, outputTokens: k, ...p }));
    const cumulative = omerFromUsage({ inputTokens: 6n, outputTokens: 6n, ...p });
    const exactNumerator = OMER_UNIT * (6n * 3n + 6n * 15n);
    const denominator = 750_000n * 3n + 250_000n * 15n;
    expect(cumulative * denominator <= exactNumerator && exactNumerator < (cumulative + 1n) * denominator).toBe(true);
    expect(perCall.reduce((a, b) => a + b, 0n) <= cumulative).toBe(true);
  });

  it("rejects zero prices and negative counts", () => {
    expect(codeOf(() => omerFromUsage({ inputTokens: 1n, outputTokens: 1n, inputPrice: 0n, outputPrice: 0n }))).toBe("INVALID_INPUT");
    expect(codeOf(() => omerFromUsage({ inputTokens: -1n, outputTokens: 1n, inputPrice: 1n, outputPrice: 1n }))).toBe("INVALID_INPUT");
  });
});
