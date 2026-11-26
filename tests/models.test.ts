import { describe, expect, it } from "vitest";
import {
  AgentRewardsModel,
  OmerMinterModel,
  RootRegistry,
  checkpointOf,
  earliestReclaimHeight,
  epochOf,
  isReceiptRootError,
} from "../src/index.js";
import { DOMAIN, EPOCH_LENGTH, HOOK, claimOf, codeOf, label, leafOf, registry, snap } from "./helpers.js";

const lock = {
  lockId: label("lock"),
  channelId: label("ch/u"),
  provider: label("provider/u"),
  payer: label("payer/u"),
  lender: label("lender/u"),
  lenderPrincipal: 70n,
  payerDeposit: 30n,
};

describe("epochs", () => {
  it("epoch e covers [e·len, (e+1)·len − 1] and its checkpoint is the last height", () => {
    expect(epochOf(0n, 1_000n)).toBe(0n);
    expect(epochOf(999n, 1_000n)).toBe(0n);
    expect(epochOf(1_000n, 1_000n)).toBe(1n);
    expect(checkpointOf(0n, 1_000n)).toBe(999n);
    expect(checkpointOf(21n, 1_000n)).toBe(21_999n);
    expect(epochOf(checkpointOf(7n, 13n), 13n)).toBe(7n);
    expect(codeOf(() => epochOf(1n, 0n))).toBe("INVALID_INPUT");
    expect(earliestReclaimHeight(20_950n, 100n, 20n)).toBe(21_070n);
  });
});

describe("parameter validation", () => {
  it("registry", () => {
    expect(codeOf(() => new RootRegistry({ domain: DOMAIN, hook: HOOK, epochLength: 0n }))).toBe("INVALID_PARAMS");
    expect(codeOf(() => new RootRegistry({ domain: DOMAIN, hook: label("32-bytes-is-not-an-address"), epochLength: 1n }))).toBe("INVALID_PARAMS");
  });

  it("minter", () => {
    const reg = registry();
    expect(codeOf(() => new OmerMinterModel(reg, { stalenessBlocks: 0n, challengeWindowBlocks: 1n, reclaimPolicy: "anyone" }))).toBe("INVALID_PARAMS");
    expect(codeOf(() => new OmerMinterModel(reg, { stalenessBlocks: 1n, challengeWindowBlocks: 0n, reclaimPolicy: "anyone" }))).toBe("INVALID_PARAMS");
    expect(codeOf(() => new OmerMinterModel(reg, { stalenessBlocks: 1n, challengeWindowBlocks: 1n, reclaimPolicy: "keeper" as never }))).toBe("INVALID_PARAMS");
  });

  it("rewards", () => {
    expect(codeOf(() => new AgentRewardsModel(registry(), { claimWindowEpochs: -1n }))).toBe("INVALID_PARAMS");
  });
});

describe("OmerMinter inputs", () => {
  const minter = () => new OmerMinterModel(registry(), { stalenessBlocks: 10n, challengeWindowBlocks: 5n, reclaimPolicy: "channel-parties" });

  it.each([
    ["zero lock id", { lockId: `0x${"00".repeat(32)}` }],
    ["payer equals provider", { payer: lock.provider }],
    ["negative principal", { lenderPrincipal: -1n }],
    ["escrow above uint128", { lenderPrincipal: 1n << 128n }],
  ])("rejects %s", (_n, patch) => {
    expect(codeOf(() => minter().open({ ...lock, ...patch } as typeof lock))).toBe("INVALID_INPUT");
  });

  it("unknown lock, duplicate lock id", () => {
    const m = minter();
    m.open(lock);
    expect(codeOf(() => m.open({ ...lock, channelId: label("ch/other") }))).toBe("DUPLICATE_LOCK");
    const s = snap(0n, [leafOf({ ch: "u", nonce: 1n, owed: 1n, escrow: 100n, height: 0n }, 0n)]);
    expect(codeOf(() => m.redeem(label("nope"), claimOf(s, lock.channelId), lock.provider))).toBe("UNKNOWN_LOCK");
  });

  it("binds the receipt to the lock's parties and escrow", () => {
    const reg = registry();
    const m = new OmerMinterModel(reg, { stalenessBlocks: 10n, challengeWindowBlocks: 5n, reclaimPolicy: "channel-parties" });
    m.open(lock);
    const wrongEscrow = snap(0n, [leafOf({ ch: "u", nonce: 1n, owed: 1n, escrow: 99n, height: 0n }, 0n)]);
    reg.accept(wrongEscrow.commitment, true);
    expect(codeOf(() => m.redeem(lock.lockId, claimOf(wrongEscrow, lock.channelId), lock.provider))).toBe("ESCROW_MISMATCH");
    const otherPayer = { ...lock, lockId: label("lock2"), channelId: label("ch/u2"), payer: label("payer/nobody") };
    m.open(otherPayer);
    const s1 = snap(1n, [leafOf({ ch: "u2", nonce: 1n, owed: 1n, escrow: 100n, height: 1_000n }, 1n)]);
    reg.accept(s1.commitment, true);
    expect(codeOf(() => m.redeem(otherPayer.lockId, claimOf(s1, otherPayer.channelId), otherPayer.provider))).toBe("PARTY_MISMATCH");
  });

  it("a rejected call leaves the lock untouched", () => {
    const reg = registry();
    const m = new OmerMinterModel(reg, { stalenessBlocks: 10n, challengeWindowBlocks: 5n, reclaimPolicy: "channel-parties" });
    const before = m.open(lock);
    const s = snap(0n, [leafOf({ ch: "u", nonce: 1n, owed: 1n, escrow: 100n, height: 990n }, 0n)]);
    reg.accept(s.commitment, true);
    expect(codeOf(() => m.reclaim(lock.lockId, claimOf(s, lock.channelId), lock.payer))).toBe("TIMEOUT_NOT_REACHED");
    expect(m.lock(lock.lockId)).toEqual(before);
  });
});

describe("AgentRewards bookkeeping", () => {
  it("records the credited state and rejects a later identity change", () => {
    const reg = registry();
    const r = new AgentRewardsModel(reg, { claimWindowEpochs: 0n });
    const l0 = leafOf({ ch: "k", nonce: 1n, owed: 5n, escrow: 9n, height: 0n }, 0n);
    const s0 = snap(0n, [l0]);
    reg.accept(s0.commitment, true);
    expect(r.claim(claimOf(s0, l0.channelId)).credit).toBe(5n);
    expect(r.credited(l0.channelId)?.nonce).toBe(1n);
    const s1 = snap(1n, [{ ...l0, epoch: 1n, nonce: 2n, cumulativeOwed: 6n, escrow: 10n, stateRoot: label("s"), finalizedHeight: EPOCH_LENGTH }]);
    reg.accept(s1.commitment, true);
    expect(codeOf(() => r.claim(claimOf(s1, l0.channelId)))).toBe("ESCROW_MISMATCH");
    expect(r.isSpent(claimOf(s1, l0.channelId).jobId)).toBe(false);
  });

  it("claim window 0: only the latest epoch is claimable", () => {
    const reg = registry();
    const r = new AgentRewardsModel(reg, { claimWindowEpochs: 0n });
    const l = leafOf({ ch: "w", nonce: 1n, owed: 5n, escrow: 9n, height: 0n }, 0n);
    const s0 = snap(0n, [l]);
    reg.accept(s0.commitment, true);
    reg.accept(snap(1n, []).commitment, true);
    expect(codeOf(() => r.claim(claimOf(s0, l.channelId)))).toBe("EPOCH_EXPIRED");
  });

  it("errors are typed", () => {
    try {
      new AgentRewardsModel(registry(), { claimWindowEpochs: -1n });
    } catch (e) {
      expect(isReceiptRootError(e, "INVALID_PARAMS")).toBe(true);
      expect(isReceiptRootError(e, "UNKNOWN_ROOT")).toBe(false);
    }
  });
});
