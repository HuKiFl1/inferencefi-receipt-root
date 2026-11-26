import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  AgentRewardsConsumerModel,
  type DedupeMode,
  type FlopReceiptRootModel,
  type Hex,
  type LockInput,
  OmerMinterConsumerModel,
  ReceiptJobHookModel,
  type Settlement,
  UNSERVED_ATTESTOR_STUB,
  type UnservedAttestor,
  encodeHookData,
  isReceiptRootError,
  jobIdOf,
  leafOf,
  waterfall,
} from "../src/index.js";
import { CHAIN, MANAGER, MODEL, POOL, POOL_2, RUNS, addr, label, newRoots, proofOf, settlement, submitEpoch } from "./helpers.js";

const code = (fn: () => unknown): string => {
  try {
    fn();
    return "OK";
  } catch (e) {
    if (isReceiptRootError(e)) return e.code;
    throw e;
  }
};

const ctx = (caller: Hex = MANAGER, chainId = CHAIN) => ({ chainId, caller });
const hookFor = (roots: FlopReceiptRootModel) =>
  new ReceiptJobHookModel(roots, { evmChainId: CHAIN, poolManager: MANAGER, pools: [{ poolId: POOL, modelHashes: [MODEL] }, { poolId: POOL_2, modelHashes: [MODEL] }] });
const rewardsFor = (roots: FlopReceiptRootModel, hook: ReceiptJobHookModel, mode: DedupeMode, claimWindowEpochs = 100n) =>
  new AgentRewardsConsumerModel(roots, hook, { evmChainId: CHAIN, poolId: POOL, mode, metric: "minerPaid", claimWindowEpochs });

describe("hook: jobId is the event key, bound to one pool per chain", () => {
  it("binding: a job tagged in one pool cannot be tagged in another, nor claimed by the other pool's rewards", () => {
    const roots = newRoots();
    const s = settlement(1, 5n);
    const e = submitEpoch(roots, 10n, [s]);
    const hook = hookFor(roots);
    const hd = encodeHookData({ epoch: 1n, settlement: s, proof: proofOf(e, s) });
    expect(hook.tag(ctx(), POOL_2, hd).jobId).toBe(jobIdOf(s));
    expect(code(() => hook.tag(ctx(), POOL, hd))).toBe("JobBoundElsewhere");
    expect(code(() => rewardsFor(roots, hook, "per-leaf-sum").claim(ctx(), 1n, s, proofOf(e, s)))).toBe("NotBoundToPool");
    expect(code(() => hook.tag(ctx(MANAGER, CHAIN + 1n), POOL, hd))).toBe("WrongChain");
    expect(code(() => hook.tag(ctx(addr("someone")), POOL, hd))).toBe("NotPoolManager");
  });

  it("same event key and a different leaf layout share a jobId; a different eventIndex does not", () => {
    const roots = newRoots();
    const s = settlement(1, 5n);
    const sameKey = { ...s, minerPaid: s.minerPaid + 9n, settledBlockHash: label("other-hash"), agent: label("other-agent") };
    const otherIndex = { ...s, eventIndex: s.eventIndex + 1n };
    expect(jobIdOf(sameKey)).toBe(jobIdOf(s));
    expect(leafOf(sameKey)).not.toBe(leafOf(s));
    expect(jobIdOf(otherIndex)).not.toBe(jobIdOf(s));
    const e = submitEpoch(roots, 10n, [s]);
    const hook = hookFor(roots);
    const hd = encodeHookData({ epoch: 1n, settlement: s, proof: proofOf(e, s) });
    expect(hook.tag(ctx(), POOL, hd).jobId).toBe(jobIdOf(s));
    expect(hook.poolOf(jobIdOf(sameKey))).toBe(POOL);
  });

  it("a settlement only verifies in the epoch that rooted it, for the genesis it names", () => {
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 12 }), fc.integer({ min: 1, max: 12 }), (n1, n2) => {
        const roots = newRoots();
        const a = Array.from({ length: n1 }, (_, i) => settlement(i, BigInt(1 + i)));
        const b = Array.from({ length: n2 }, (_, i) => settlement(100 + i, BigInt(100 + i)));
        const e1 = submitEpoch(roots, 99n, a);
        const e2 = submitEpoch(roots, 100n, b);
        return (
          a.every((s) => roots.verify(1n, s, proofOf(e1, s)) && !roots.verify(2n, s, proofOf(e1, s)) && !roots.verify(1n, { ...s, genesis: label("other") }, proofOf(e1, s))) &&
          b.every((s) => roots.verify(2n, s, proofOf(e2, s)) && !roots.verify(1n, s, proofOf(e2, s)))
        );
      }),
      { numRuns: RUNS },
    );
  });
});

describe("AgentRewards: one credit per leaf; dedupe unit is a switch", () => {
  const arbPlan = fc.array(
    fc.record({ ch: fc.integer({ min: 0, max: 3 }), amount: fc.bigInt({ min: 0n, max: 1_000n }) }),
    { minLength: 1, maxLength: 16 },
  );

  for (const mode of ["per-leaf-sum", "latest-per-channel"] as const) {
    it(`${mode}: claiming every leaf in any order, with repeats, credits each leaf at most once`, () => {
      fc.assert(
        fc.property(arbPlan, fc.array(fc.nat(), { minLength: 1, maxLength: 40 }), (plan, order) => {
          const roots = newRoots();
          // Amounts are cumulative per channel in block order, so both modes have a well-defined answer.
          const run = new Map<number, bigint>();
          const ss: Settlement[] = plan.map((p, i) => {
            const cum = (run.get(p.ch) ?? 0n) + p.amount;
            run.set(p.ch, cum);
            return settlement(p.ch, BigInt(1 + i), { minerPaid: mode === "per-leaf-sum" ? p.amount : cum });
          });
          const e = submitEpoch(roots, 100n, ss);
          const hook = hookFor(roots);
          const r = rewardsFor(roots, hook, mode);
          for (const s of ss) hook.tag(ctx(), POOL, { epoch: 1n, settlement: s, proof: proofOf(e, s) });
          const seen = new Set<Hex>();
          for (const k of [...order.map((o) => o % ss.length), ...ss.keys()]) {
            const s = ss[k]!;
            const out = code(() => r.claim(ctx(), 1n, s, proofOf(e, s)));
            if (seen.has(leafOf(s))) {
              if (out !== "LeafSpent") return false;
            } else if (out === "OK") seen.add(leafOf(s));
            else if (mode === "per-leaf-sum" || out !== "StaleLeaf") return false;
          }
          const want = [...run.values()].reduce((x, y) => x + y, 0n);
          // latest mode can only reach the full total if the last leaf per channel got in.
          return mode === "per-leaf-sum" ? r.totalCredited() === want : r.totalCredited() <= want;
        }),
        { numRuns: RUNS },
      );
    });
  }

  it("latest-per-channel: claiming in block order credits exactly the latest cumulative amount per channel", () => {
    fc.assert(
      fc.property(arbPlan, (plan) => {
        const roots = newRoots();
        const run = new Map<number, bigint>();
        const ss = plan.map((p, i) => {
          const cum = (run.get(p.ch) ?? 0n) + p.amount;
          run.set(p.ch, cum);
          return settlement(p.ch, BigInt(1 + i), { minerPaid: cum });
        });
        const e = submitEpoch(roots, 100n, ss);
        const hook = hookFor(roots);
        const r = rewardsFor(roots, hook, "latest-per-channel");
        for (const s of ss) {
          hook.tag(ctx(), POOL, { epoch: 1n, settlement: s, proof: proofOf(e, s) });
          r.claim(ctx(), 1n, s, proofOf(e, s));
        }
        return [...run.entries()].every(([ch, cum]) => r.channelEpochTotal(label(`ch/${ch}`), 1n) === cum);
      }),
      { numRuns: RUNS },
    );
  });

  it("an epoch closes after the claim window; a forged proof never pays", () => {
    const roots = newRoots();
    const s = settlement(1, 5n);
    const t = settlement(2, 6n);
    const e = submitEpoch(roots, 10n, [s, t]);
    const hook = hookFor(roots);
    const r = rewardsFor(roots, hook, "per-leaf-sum", 1n);
    hook.tag(ctx(), POOL, { epoch: 1n, settlement: s, proof: proofOf(e, s) });
    expect(code(() => r.claim(ctx(), 1n, s, proofOf(e, t)))).toBe("ProofRejected");
    expect(code(() => r.claim(ctx(), 1n, { ...s, minerPaid: s.minerPaid + 1n }, proofOf(e, s)))).toBe("ProofRejected");
    submitEpoch(roots, 10n, []);
    submitEpoch(roots, 10n, []);
    expect(code(() => r.claim(ctx(), 1n, s, proofOf(e, s)))).toBe("EpochExpired");
  });
});

describe("OmerMinter: redeem by Settled leaf, reclaim only by attestation, TCLK", () => {
  const N = 100n;
  const W = 20n;
  const lock = (o: Partial<LockInput> = {}): LockInput => ({
    lockId: label("lock"),
    channelId: label("ch/1"),
    agent: label("agent/1"),
    miner: label("miner/1"),
    modelHash: MODEL,
    payer: addr("payer"),
    provider: addr("provider"),
    lender: addr("lender"),
    lenderPrincipal: 600n,
    payerDeposit: 400n,
    omerPerGnNum: 1n,
    omerPerGnDen: 2n,
    minFlopBlock: 1n,
    ...o,
  });
  const minter = (roots: FlopReceiptRootModel, attestor: UnservedAttestor) =>
    new OmerMinterConsumerModel(roots, attestor, { evmChainId: CHAIN, stalenessBlocks: N, challengeWindowBlocks: W, reclaimPolicy: "channel-parties" });

  it("the stub attestor fails every reclaim closed, whatever the timing", () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt({ min: 1n, max: 400n }), { minLength: 1, maxLength: 6 }), (lens) => {
        const roots = newRoots();
        for (const len of lens) submitEpoch(roots, len, []);
        const m = minter(roots, UNSERVED_ATTESTOR_STUB);
        m.open(ctx(addr("payer")), lock());
        return code(() => m.reclaim(ctx(addr("payer")), lock().lockId, roots.lastEpoch, "0x")) === "UnservedProofUnavailable" && m.status(lock().lockId) === "Locked";
      }),
      { numRuns: RUNS },
    );
  });

  it("TCLK: exactly one terminal call lands; reclaim needs the latest root at or past h + N + W; redeem wins until then and after", () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 1n, max: 300n }),
        fc.array(fc.record({ len: fc.bigInt({ min: 1n, max: 80n }), op: fc.constantFrom("redeem", "reclaim-latest", "reclaim-stale", "none") }), { minLength: 1, maxLength: 10 }),
        (h, plan) => {
          const roots = newRoots();
          const s = settlement(1, 1n);
          const e1 = submitEpoch(roots, 1n, [s]);
          const attestor: UnservedAttestor = { verifyUnserved: () => ({ lastFinalizedHeight: h, owed: 0n }) };
          const m = minter(roots, attestor);
          m.open(ctx(addr("payer")), lock());
          let landed = 0;
          for (const st of plan) {
            submitEpoch(roots, st.len, []);
            const latest = roots.lastEpoch;
            const to = roots.epochs(latest)!.toBlock;
            let out = "none";
            if (st.op === "redeem") out = code(() => m.redeem(ctx(addr("provider")), lock().lockId, 1n, s, proofOf(e1, s)));
            if (st.op === "reclaim-latest") out = code(() => m.reclaim(ctx(addr("lender")), lock().lockId, latest, "0x"));
            if (st.op === "reclaim-stale") out = code(() => m.reclaim(ctx(addr("lender")), lock().lockId, latest - 1n, "0x"));
            if (out === "OK") landed++;
            if (landed > 0 && out !== "none" && out !== "OK" && out !== "AlreadySettled") return false;
            if (landed === 0 || out === "OK") {
              if (st.op === "redeem" && out !== "OK") return false;
              if (st.op === "reclaim-stale" && out !== "StaleRoot") return false;
              if (st.op === "reclaim-latest" && out !== (to >= h + N + W ? "OK" : "TimeoutNotReached")) return false;
            }
          }
          return landed <= 1;
        },
      ),
      { numRuns: RUNS },
    );
  });

  it("redeem binds the lock's channel, parties, model and freshness, and pays by the waterfall", () => {
    const roots = newRoots();
    const good = settlement(1, 5n, { aggregateGn: 3_000n });
    const e = submitEpoch(roots, 10n, [good]);
    const m = minter(roots, UNSERVED_ATTESTOR_STUB);
    m.open(ctx(addr("payer")), lock());
    const p = ctx(addr("provider"));
    const id = lock().lockId;
    expect(code(() => m.redeem(ctx(addr("payer")), id, 1n, good, proofOf(e, good)))).toBe("Unauthorized");
    expect(code(() => m.redeem(p, id, 1n, { ...good, channelId: label("ch/2") }, proofOf(e, good)))).toBe("ChannelMismatch");
    expect(code(() => m.redeem(p, id, 1n, { ...good, miner: label("x") }, proofOf(e, good)))).toBe("PartyMismatch");
    expect(code(() => m.redeem(p, id, 1n, { ...good, modelHash: label("x") }, proofOf(e, good)))).toBe("ModelMismatch");
    expect(code(() => m.redeem(p, id, 1n, { ...good, aggregateGn: 0n }, proofOf(e, good)))).toBe("NotServed");
    const r = m.redeem(p, id, 1n, good, proofOf(e, good));
    expect(r).toMatchObject({ owed: 1_500n, ...waterfall(1_000n, 600n, 1_500n) });
    expect(code(() => m.redeem(p, id, 1n, good, proofOf(e, good)))).toBe("AlreadySettled");
  });

  it("a frozen root contract blocks both paths", () => {
    const roots = newRoots();
    const s = settlement(1, 5n);
    const e = submitEpoch(roots, 10n, [s]);
    const m = minter(roots, { verifyUnserved: () => ({ lastFinalizedHeight: 0n, owed: 0n }) });
    m.open(ctx(addr("payer")), lock());
    roots.freeze(e.msg, true, { ...e.msg, root: label("rival") }, true);
    expect(code(() => m.reclaim(ctx(addr("payer")), lock().lockId, 1n, "0x"))).toBe("RootsFrozen");
    expect(code(() => m.redeem(ctx(addr("provider")), lock().lockId, 1n, s, proofOf(e, s)))).toBe("ProofRejected");
  });

  it("waterfall conserves escrow", () => {
    fc.assert(
      fc.property(fc.bigInt({ min: 0n, max: 10n ** 30n }), fc.bigInt({ min: 0n, max: 10n ** 30n }), fc.bigInt({ min: 0n, max: 10n ** 31n }), (a, b, owed) => {
        const [L, E] = a <= b ? [a, b] : [b, a];
        const w = waterfall(E, L, owed);
        return w.toProvider + w.toLender + w.toPayer === E && w.toProvider + w.overrun === owed && w.toLender + w.lenderShortfall === L;
      }),
      { numRuns: RUNS },
    );
  });
});
