/**
 * One block per threat in DESIGN.md §9. Each property runs against random leaf
 * sets and random attacker choices; RUNS scales them (PROPERTY_RUNS=5000).
 */
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  AgentRewardsModel,
  EpochClaimBitmap,
  KECCAK256,
  OmerMinterModel,
  type ReceiptClaim,
  type ReceiptLeaf,
  U128_MAX,
  ZERO32,
  auditSnapshot,
  auditTransition,
  buildSnapshot,
  checkpointOf,
  jobIdOf,
  leafHash,
  merkleProof,
  merkleRoot,
  nodeHash,
  nullifierOf,
  reclaimEligible,
  verifyProof,
  verifyReceipt,
  waterfall,
} from "../src/index.js";
import { DOMAIN, EPOCH_LENGTH, HOOK, RUNS, addr, arbHex32, arbLeaf, arbLeafSet, claimOf, codeOf, label, leafOf, registry, snap } from "./helpers.js";

const nonEmpty = (epoch: bigint, max = 16) => arbLeafSet(epoch, max).filter((l) => l.length > 0);

describe("T1 replay across epochs", () => {
  it("a leaf proven in epoch e never verifies against another epoch's root", () => {
    fc.assert(
      fc.property(nonEmpty(5n), fc.nat(), (leaves, pick) => {
        const reg = registry();
        const s5 = snap(5n, leaves);
        const s6 = snap(6n, leaves.map((l) => ({ ...l, epoch: 6n })));
        reg.accept(s5.commitment, true);
        reg.accept(s6.commitment, true);
        const c = claimOf(s5, s5.tree.leaves[pick % leaves.length]!.channelId);
        expect(codeOf(() => verifyReceipt(reg, c))).toBe("OK");
        expect(codeOf(() => verifyReceipt(reg, { ...c, jobId: s6.jobId }))).toBe("EPOCH_MISMATCH");
        expect(s5.commitment.keccakRoot).not.toBe(s6.commitment.keccakRoot);
        expect(nullifierOf(c.leaf)).not.toBe(nullifierOf({ ...c.leaf, epoch: 6n }));
      }),
      { numRuns: RUNS },
    );
  });
});

describe("T2/T3 replay across chains, FLOP networks, pools and hooks", () => {
  const variants = [
    { name: "EVM chain", domain: { ...DOMAIN, evmChainId: 999n } },
    { name: "FLOP network", domain: { ...DOMAIN, flopGenesis: label("other-genesis") } },
    { name: "pool", domain: { ...DOMAIN, poolId: label("other-pool") } },
  ];
  it.each(variants)("a receipt for another $name never verifies here", ({ domain }) => {
    fc.assert(
      fc.property(arbLeaf(4n, domain), (leaf) => {
        const theirs = snap(4n, [leaf], domain);
        const reg = registry();
        const ours = snap(4n, [{ ...leaf, ...DOMAIN }]);
        reg.accept(ours.commitment, true);
        const claim = claimOf(theirs, leaf.channelId);
        expect(codeOf(() => verifyReceipt(reg, { ...claim, jobId: ours.jobId }))).toBe("DOMAIN_MISMATCH");
        expect(codeOf(() => reg.accept(theirs.commitment, true))).toBe("DOMAIN_MISMATCH");
        expect(leafHash(leaf, KECCAK256)).not.toBe(leafHash({ ...leaf, ...DOMAIN }, KECCAK256));
      }),
      { numRuns: Math.ceil(RUNS / 2) },
    );
  });

  it("the same tree under another hook or chain has a different jobId and is refused by this registry", () => {
    const s = snap(1n, [leafOf({ ch: "h", nonce: 1n, owed: 1n, escrow: 1n, height: 1_500n }, 1n)]);
    const otherHook = { ...s.commitment, hook: addr("other-hook") };
    expect(jobIdOf(otherHook)).not.toBe(s.jobId);
    expect(codeOf(() => registry().accept(otherHook, true))).toBe("DOMAIN_MISMATCH");
  });
});

describe("T4 double-claim", () => {
  it("each (channel, epoch) is credited at most once, whatever the claim order", () => {
    fc.assert(
      fc.property(nonEmpty(7n, 8), fc.array(fc.nat(), { minLength: 1, maxLength: 30 }), (leaves, order) => {
        const reg = registry();
        const s = snap(7n, leaves);
        reg.accept(s.commitment, true);
        const rewards = new AgentRewardsModel(reg, { claimWindowEpochs: 0n });
        const credited = new Map<string, bigint>();
        const touched = new Set<string>();
        for (const k of order) {
          const leaf = s.tree.leaves[k % s.tree.leaves.length]!;
          touched.add(leaf.channelId);
          const code = codeOf(() => {
            const r = rewards.claim(claimOf(s, leaf.channelId));
            credited.set(leaf.channelId, (credited.get(leaf.channelId) ?? 0n) + r.credit);
          });
          expect(["OK", "NULLIFIER_SPENT", "STATE_REPLAYED"]).toContain(code);
        }
        for (const leaf of s.tree.leaves) {
          const backed = leaf.cumulativeOwed < leaf.escrow ? leaf.cumulativeOwed : leaf.escrow;
          const expected = !touched.has(leaf.channelId) || leaf.nonce === 0n ? 0n : backed;
          expect(credited.get(leaf.channelId) ?? 0n).toBe(expected);
        }
      }),
      { numRuns: RUNS },
    );
  });

  it("a channel listed twice by a faulty attester defeats an index bitmap but not the nullifier set", () => {
    const a = leafOf({ ch: "dup", nonce: 2n, owed: 50n, escrow: 100n, height: 7_100n }, 7n);
    const hashes = [leafHash(a, KECCAK256), leafHash(a, KECCAK256)];
    const root = merkleRoot(KECCAK256, hashes);
    const bitmap = new EpochClaimBitmap();
    for (const i of [0, 1]) {
      expect(verifyProof(KECCAK256, root, hashes[i]!, merkleProof(KECCAK256, hashes, i))).toBe(true);
      expect(codeOf(() => bitmap.setClaimed(7n, BigInt(i)))).toBe("OK");
    }
    const nullifiers = new Set([0, 1].map(() => nullifierOf(a)));
    expect(nullifiers.size).toBe(1);
  });

  it("bitmap words hold 256 claims and reject a repeat", () => {
    const b = new EpochClaimBitmap();
    expect(EpochClaimBitmap.locate(255n)).toEqual({ word: 0n, mask: 1n << 255n });
    expect(EpochClaimBitmap.locate(256n)).toEqual({ word: 1n, mask: 1n });
    b.setClaimed(3n, 300n);
    expect(b.isClaimed(3n, 300n)).toBe(true);
    expect(b.isClaimed(4n, 300n)).toBe(false);
    expect(codeOf(() => b.setClaimed(3n, 300n))).toBe("NULLIFIER_SPENT");
  });
});

describe("T5 stale root", () => {
  it("one immutable root per epoch, epochs only move forward", () => {
    fc.assert(
      fc.property(fc.uniqueArray(fc.bigInt({ min: 0n, max: 50n }), { minLength: 1, maxLength: 12 }), (epochs) => {
        const reg = registry();
        let latest = -1n;
        for (const e of epochs) {
          const s = snap(e, []);
          const code = codeOf(() => reg.accept(s.commitment, true));
          expect(code).toBe(e > latest ? "OK" : "EPOCH_REGRESSION");
          if (e > latest) latest = e;
          expect(codeOf(() => reg.accept(s.commitment, true))).toBe(e === latest ? "ROOT_EXISTS" : "EPOCH_REGRESSION");
        }
        expect(reg.latest()!.epoch).toBe(latest);
      }),
      { numRuns: RUNS },
    );
  });

  it("reclaim proven against any root but the latest fails, so an older lower-owed snapshot cannot shortchange the provider", () => {
    const reg = registry();
    const minter = new OmerMinterModel(reg, { stalenessBlocks: 10n, challengeWindowBlocks: 5n, reclaimPolicy: "anyone" });
    const lock = { lockId: label("lk"), channelId: label("ch/s"), provider: label("provider/s"), payer: label("payer/s"), lender: label("lender/s"), lenderPrincipal: 60n, payerDeposit: 40n };
    minter.open(lock);
    const old = snap(3n, [leafOf({ ch: "s", nonce: 1n, owed: 10n, escrow: 100n, height: 3_000n }, 3n)]);
    const cur = snap(4n, [leafOf({ ch: "s", nonce: 2n, owed: 70n, escrow: 100n, height: 3_500n }, 4n)]);
    reg.accept(old.commitment, true);
    reg.accept(cur.commitment, true);
    expect(codeOf(() => minter.reclaim(lock.lockId, claimOf(old, lock.channelId), lock.payer))).toBe("STALE_ROOT");
    const s = minter.reclaim(lock.lockId, claimOf(cur, lock.channelId), lock.payer);
    expect(s.toProvider).toBe(70n);
  });

  it("checkpoint must be the last height of the epoch and empty roots must be the defined empty roots", () => {
    const s = snap(2n, []);
    expect(codeOf(() => registry().accept({ ...s.commitment, checkpointHeight: s.commitment.checkpointHeight - 1n }, true))).toBe("CHECKPOINT_MISMATCH");
    expect(codeOf(() => registry().accept({ ...s.commitment, keccakRoot: label("x") }, true))).toBe("EMPTY_ROOT_MISMATCH");
    const one = snap(2n, [leafOf({ ch: "e", nonce: 1n, owed: 1n, escrow: 1n, height: 2_100n }, 2n)]);
    expect(codeOf(() => registry().accept({ ...one.commitment, leafCount: 0n }, true))).toBe("EMPTY_ROOT_MISMATCH");
  });
});

describe("T6 reorg: finalized heights only", () => {
  it("no leaf above the checkpoint can enter a snapshot or verify", () => {
    fc.assert(
      fc.property(arbLeaf(6n), fc.bigInt({ min: 1n, max: 1n << 32n }), (leaf, over) => {
        const cp = checkpointOf(6n, EPOCH_LENGTH);
        const late = { ...leaf, finalizedHeight: cp + over };
        expect(codeOf(() => snap(6n, [late]))).toBe("HEIGHT_BEYOND_CHECKPOINT");
        const reg = registry();
        const s = snap(6n, [leaf]);
        reg.accept(s.commitment, true);
        expect(codeOf(() => verifyReceipt(reg, { ...claimOf(s, leaf.channelId), leaf: late }))).toBe("HEIGHT_BEYOND_CHECKPOINT");
      }),
      { numRuns: RUNS },
    );
  });
});

describe("T7 inflated cumulative owed", () => {
  it("changing any leaf field after proving breaks the proof", () => {
    const fields = ["cumulativeOwed", "escrow", "nonce", "finalizedHeight"] as const;
    fc.assert(
      fc.property(nonEmpty(8n, 10), fc.nat(), fc.constantFrom(...fields), fc.bigInt({ min: 1n, max: 1n << 20n }), (leaves, pick, field, delta) => {
        const reg = registry();
        const s = snap(8n, leaves);
        reg.accept(s.commitment, true);
        const c = claimOf(s, s.tree.leaves[pick % leaves.length]!.channelId);
        const bumped = { ...c.leaf, [field]: c.leaf[field] + delta } as ReceiptLeaf;
        if (bumped.cumulativeOwed > U128_MAX || bumped.escrow > U128_MAX) return;
        const code = codeOf(() => verifyReceipt(reg, { ...c, leaf: bumped }));
        expect(["INVALID_PROOF", "HEIGHT_BEYOND_CHECKPOINT", "INVALID_LEAF"]).toContain(code);
      }),
      { numRuns: RUNS },
    );
  });

  it("rewards never exceed escrow-backed spend, and payouts never exceed escrow", () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 0n, max: U128_MAX }),
        fc.bigInt({ min: 0n, max: U128_MAX }),
        fc.bigInt({ min: 0n, max: U128_MAX }),
        (escrow, l, owed) => {
          const lender = l % (escrow + 1n);
          const p = waterfall(escrow, lender, owed);
          expect(p.toProvider + p.toLender + p.toPayer).toBe(escrow);
          expect(p.toProvider + p.overrun).toBe(owed);
          expect(p.toLender + p.lenderShortfall).toBe(lender);
          if (p.toLender > 0n) expect(p.toProvider).toBe(owed);
          if (p.toPayer > 0n) expect(p.toLender).toBe(lender);
        },
      ),
      { numRuns: RUNS * 5 },
    );
  });
});

describe("T8 nonce rollback and equivocation", () => {
  it("rewards accept a channel's states only in increasing nonce and owed order", () => {
    fc.assert(
      fc.property(
        fc.array(fc.record({ nonce: fc.bigInt({ min: 0n, max: 6n }), owed: fc.bigInt({ min: 0n, max: 6n }) }), { minLength: 1, maxLength: 8 }),
        (states) => {
          const reg = registry();
          const rewards = new AgentRewardsModel(reg, { claimWindowEpochs: 100n });
          let last = { nonce: 0n, owed: 0n };
          for (const [i, st] of states.entries()) {
            const epoch = BigInt(i);
            const owed = st.nonce === 0n ? 0n : st.owed;
            const leaf = leafOf({ ch: "r", nonce: st.nonce, owed, escrow: 4n, height: epoch * EPOCH_LENGTH }, epoch);
            const s = snap(epoch, [leaf]);
            reg.accept(s.commitment, true);
            const code = codeOf(() => rewards.claim(claimOf(s, leaf.channelId)));
            const expected =
              st.nonce < last.nonce ? "STALE_NONCE"
              : st.nonce === last.nonce ? (owed === last.owed ? "STATE_REPLAYED" : "CONFLICTING_STATE")
              : owed < last.owed ? "OWED_DECREASED"
              : "OK";
            expect(code).toBe(expected);
            if (code === "OK") last = { nonce: st.nonce, owed };
          }
          const backed = (x: bigint) => (x < 4n ? x : 4n);
          expect(rewards.totalCredited()).toBe(backed(last.owed));
        },
      ),
      { numRuns: RUNS },
    );
  });

  it("watchers flag a rollback, a decrease, an equivocation and a changed identity between snapshots", () => {
    const prev = [
      leafOf({ ch: "a", nonce: 5n, owed: 50n, escrow: 9n, height: 100n }, 1n),
      leafOf({ ch: "b", nonce: 2n, owed: 20n, escrow: 9n, height: 90n }, 1n),
      leafOf({ ch: "c", nonce: 3n, owed: 30n, escrow: 9n, height: 80n }, 1n),
      leafOf({ ch: "d", nonce: 1n, owed: 1n, escrow: 9n, height: 70n }, 1n),
      leafOf({ ch: "e", nonce: 1n, owed: 1n, escrow: 9n, height: 60n }, 1n),
    ];
    const next = [
      { ...prev[0]!, epoch: 2n, nonce: 4n },
      { ...prev[1]!, epoch: 2n, nonce: 3n, cumulativeOwed: 19n },
      { ...prev[2]!, epoch: 2n, cumulativeOwed: 31n },
      { ...prev[3]!, epoch: 2n, escrow: 10n },
    ];
    const codes = auditTransition(prev, next).map((f) => `${f.code}`);
    expect(codes).toEqual(expect.arrayContaining(["STALE_NONCE", "OWED_DECREASED", "CONFLICTING_STATE", "FIELD_CHANGED", "CHANNEL_DROPPED"]));
    const honest = prev.map((l) => ({ ...l, epoch: 2n }));
    expect(auditTransition(prev, honest)).toEqual([]);
  });
});

describe("T9 second preimage and tree malleability", () => {
  it("an internal node never verifies as a leaf at the committed leaf count", () => {
    fc.assert(
      fc.property(fc.uniqueArray(arbHex32, { minLength: 2, maxLength: 40 }), fc.nat(), (d, pick) => {
        const root = merkleRoot(KECCAK256, d);
        const i = 2 * (pick % Math.floor(d.length / 2));
        const internal = nodeHash(KECCAK256, d[i]!, d[i + 1]!);
        const upper = merkleProof(KECCAK256, d, i).siblings.slice(1);
        for (let index = 0n; index < BigInt(d.length); index++) {
          expect(verifyProof(KECCAK256, root, internal, { index, leafCount: BigInt(d.length), siblings: upper })).toBe(false);
        }
      }),
      { numRuns: RUNS },
    );
  });

  it("a caller-chosen leafCount can verify a real leaf at a wrong count, so receipts bind it to the commitment", () => {
    const leaves = Array.from({ length: 5 }, (_, i) => leafOf({ ch: `lc${i}`, nonce: 1n, owed: 1n, escrow: 1n, height: 9_000n }, 9n));
    const s = snap(9n, leaves);
    const reg = registry();
    reg.accept(s.commitment, true);
    const c = claimOf(s, s.tree.leaves[0]!.channelId);
    expect(verifyProof(KECCAK256, s.commitment.keccakRoot, leafHash(c.leaf, KECCAK256), { ...c.proof, leafCount: 6n })).toBe(true);
    expect(codeOf(() => verifyReceipt(reg, { ...c, proof: { ...c.proof, leafCount: 6n } }))).toBe("INVALID_PROOF");
  });

  it("distinct leaf sets give distinct roots, including duplicate-last-node padding", () => {
    fc.assert(
      fc.property(fc.uniqueArray(arbHex32, { minLength: 1, maxLength: 33 }), (d) => {
        const padded = [...d, d[d.length - 1]!];
        expect(merkleRoot(KECCAK256, padded)).not.toBe(merkleRoot(KECCAK256, d));
      }),
      { numRuns: RUNS },
    );
  });
});

describe("T10 redeem / reclaim race (TCLK)", () => {
  type Op = { kind: "redeem" | "reclaim"; root: number };
  const arbOps = fc.array(fc.record({ kind: fc.constantFrom<"redeem" | "reclaim">("redeem", "reclaim"), root: fc.nat({ max: 2 }) }), { minLength: 1, maxLength: 10 });

  it("exactly one terminal transition settles; reclaim only after N + W; redeem wins until a refund is included", () => {
    fc.assert(
      fc.property(
        arbOps,
        fc.bigInt({ min: 0n, max: 1_000n }),
        fc.bigInt({ min: 0n, max: 1_000n }),
        fc.array(fc.bigInt({ min: 0n, max: 600n }), { minLength: 3, maxLength: 3 }),
        (ops: Op[], lender, payer, heights) => {
          const reg = registry();
          const N = 100n;
          const W = 20n;
          const minter = new OmerMinterModel(reg, { stalenessBlocks: N, challengeWindowBlocks: W, reclaimPolicy: "anyone" });
          const escrow = lender + payer;
          const lock = { lockId: label("race"), channelId: label("ch/race"), provider: label("provider/race"), payer: label("payer/race"), lender: label("lender/race"), lenderPrincipal: lender, payerDeposit: payer };
          minter.open(lock);
          const snaps = [0, 1, 2].map((k) => {
            const epoch = BigInt(k);
            const cp = checkpointOf(epoch, EPOCH_LENGTH);
            const h = cp - heights[k]!;
            return snap(epoch, [leafOf({ ch: "race", nonce: BigInt(k + 1), owed: BigInt(100 * (k + 1)), escrow, height: h > 0n ? h : 0n }, epoch)]);
          });
          let settled = 0;
          let accepted = -1;
          for (const op of ops) {
            while (accepted < op.root) reg.accept(snaps[++accepted]!.commitment, true);
            const c = claimOf(snaps[op.root]!, lock.channelId);
            const wasSettled = settled > 0;
            const code = codeOf(() => (op.kind === "redeem" ? minter.redeem(lock.lockId, c, lock.provider) : minter.reclaim(lock.lockId, c, label("anyone"))));
            if (wasSettled) {
              expect(code).toBe("ALREADY_SETTLED");
              continue;
            }
            if (op.kind === "redeem") expect(code).toBe("OK");
            else {
              const latest = op.root === accepted;
              const eligible = reclaimEligible(snaps[op.root]!.commitment.checkpointHeight, c.leaf.finalizedHeight, N, W);
              expect(code).toBe(!latest ? "STALE_ROOT" : eligible ? "OK" : "TIMEOUT_NOT_REACHED");
            }
            if (code === "OK") {
              settled++;
              const s = minter.lock(lock.lockId)!.settlement!;
              expect(s.toProvider + s.toLender + s.toPayer).toBe(escrow);
              expect(s.toProvider).toBe(c.leaf.cumulativeOwed < escrow ? c.leaf.cumulativeOwed : escrow);
            }
          }
          expect(settled).toBeLessThanOrEqual(1);
        },
      ),
      { numRuns: RUNS },
    );
  });

  it("reclaim policy: channel-parties refuses outsiders, anyone allows them, redeem is provider-only", () => {
    for (const policy of ["channel-parties", "anyone"] as const) {
      const reg = registry();
      const minter = new OmerMinterModel(reg, { stalenessBlocks: 1n, challengeWindowBlocks: 1n, reclaimPolicy: policy });
      const lock = { lockId: label("p"), channelId: label("ch/p"), provider: label("provider/p"), payer: label("payer/p"), lender: label("lender/p"), lenderPrincipal: 5n, payerDeposit: 5n };
      minter.open(lock);
      const s = snap(0n, [leafOf({ ch: "p", nonce: 1n, owed: 3n, escrow: 10n, height: 0n }, 0n)]);
      reg.accept(s.commitment, true);
      const c = claimOf(s, lock.channelId);
      expect(codeOf(() => minter.redeem(lock.lockId, c, lock.lender))).toBe("UNAUTHORIZED");
      expect(codeOf(() => minter.reclaim(lock.lockId, c, label("outsider")))).toBe(policy === "anyone" ? "OK" : "UNAUTHORIZED");
    }
  });
});

describe("T11 dual commitment", () => {
  it("watchers detect a commitment whose blake root or keccak root is not over the published leaves", () => {
    fc.assert(
      fc.property(nonEmpty(3n, 12), arbLeaf(3n), (leaves, extra) => {
        const s = snap(3n, leaves);
        expect(auditSnapshot(s.commitment, leaves, EPOCH_LENGTH)).toEqual([]);
        if (leaves.some((l) => l.channelId === extra.channelId)) return;
        const other = snap(3n, [...leaves, extra]);
        const forgedBlake = { ...s.commitment, blakeRoot: other.commitment.blakeRoot };
        const forgedKeccak = { ...s.commitment, keccakRoot: other.commitment.keccakRoot };
        expect(auditSnapshot(forgedBlake, leaves, EPOCH_LENGTH).map((f) => f.code)).toEqual(["BLAKE_ROOT_MISMATCH"]);
        expect(auditSnapshot(forgedKeccak, leaves, EPOCH_LENGTH).map((f) => f.code)).toEqual(["KECCAK_ROOT_MISMATCH"]);
        expect(jobIdOf(forgedBlake)).not.toBe(s.jobId);
      }),
      { numRuns: RUNS },
    );
  });

  it("the FLOP-side blake proof verifies the same receipt against the same commitment", async () => {
    const { verifyReceiptFlop, BLAKE2B256 } = await import("../src/index.js");
    const leaves = [0, 1, 2].map((i) => leafOf({ ch: `f${i}`, nonce: 1n, owed: 1n, escrow: 1n, height: 0n }, 0n));
    const s = snap(0n, leaves);
    for (let i = 0; i < 3; i++) {
      expect(codeOf(() => verifyReceiptFlop(s.commitment, s.tree.leaves[i]!, s.tree.proof(i, BLAKE2B256)))).toBe("OK");
      expect(codeOf(() => verifyReceiptFlop(s.commitment, s.tree.leaves[i]!, s.tree.proof(i, KECCAK256)))).toBe("INVALID_PROOF");
    }
  });

  it("an attester without the threshold cannot publish", () => {
    const s = buildSnapshot({ domain: DOMAIN, hook: HOOK, epoch: 0n, epochLength: EPOCH_LENGTH }, []);
    expect(codeOf(() => registry().accept(s.commitment, false))).toBe("UNAUTHORIZED_ATTESTER");
  });
});

describe("snapshot builder guards", () => {
  it("rejects leaves from another domain or epoch", () => {
    const l = leafOf({ ch: "g", nonce: 1n, owed: 1n, escrow: 1n, height: 0n }, 0n);
    expect(codeOf(() => snap(0n, [{ ...l, evmChainId: 1n }]))).toBe("DOMAIN_MISMATCH");
    expect(codeOf(() => snap(1n, [l]))).toBe("EPOCH_MISMATCH");
    expect(ZERO32).toMatch(/^0x0{64}$/);
  });

  it("receipts with malformed leaves are INVALID_LEAF, not a crash", () => {
    const reg = registry();
    const s = snap(0n, [leafOf({ ch: "m", nonce: 1n, owed: 1n, escrow: 1n, height: 0n }, 0n)]);
    reg.accept(s.commitment, true);
    const c: ReceiptClaim = claimOf(s, label("ch/m"));
    expect(codeOf(() => verifyReceipt(reg, { ...c, leaf: { ...c.leaf, nonce: -1n } }))).toBe("INVALID_LEAF");
  });
});
