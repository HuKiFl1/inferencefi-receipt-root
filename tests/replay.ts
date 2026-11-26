import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

/** The module under test: the real `src/`, or a mutated copy of it. */
export type M = typeof import("../src/index.js");
type Hex = `0x${string}`;
/** Parsed vector JSON. Shapes are checked by the assertions that read it. */
type J = any;

export function loadVectors(): J {
  return JSON.parse(readFileSync(new URL("../vectors/receipt-root-v1.json", import.meta.url), "utf8"));
}

const fromHex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h.slice(2), "hex"));

export function parseLeaf(j: J) {
  return {
    flopGenesis: j.flopGenesis as Hex,
    evmChainId: BigInt(j.evmChainId),
    poolId: j.poolId as Hex,
    channelId: j.channelId as Hex,
    provider: j.provider as Hex,
    payer: j.payer as Hex,
    cumulativeOwed: BigInt(j.cumulativeOwed),
    escrow: BigInt(j.escrow),
    nonce: BigInt(j.nonce),
    epoch: BigInt(j.epoch),
    finalizedHeight: BigInt(j.finalizedHeight),
    stateRoot: j.stateRoot as Hex,
  };
}

export function parseCommitment(j: J) {
  return {
    flopGenesis: j.flopGenesis as Hex,
    evmChainId: BigInt(j.evmChainId),
    poolId: j.poolId as Hex,
    hook: j.hook as Hex,
    epoch: BigInt(j.epoch),
    checkpointHeight: BigInt(j.checkpointHeight),
    leafCount: BigInt(j.leafCount),
    keccakRoot: j.keccakRoot as Hex,
    blakeRoot: j.blakeRoot as Hex,
  };
}

const parseProof = (j: J) => ({ index: BigInt(j.index), leafCount: BigInt(j.leafCount), siblings: j.siblings as Hex[] });

function outcome(m: M, fn: () => void): string {
  try {
    fn();
    return "OK";
  } catch (e) {
    if (m.isReceiptRootError(e)) return e.code;
    throw e;
  }
}

export function replayPrimitives(m: M, v: J): void {
  for (const h of v.hashes) {
    const fn = h.fn === "keccak256" ? m.KECCAK256 : m.BLAKE2B256;
    assert.equal(m.bytesToHex(fn(fromHex(h.input))), h.output, `${h.fn}(${h.input})`);
  }
  assert.equal(m.EMPTY_KECCAK_ROOT, v.encoding.emptyRoots.keccak256);
  assert.equal(m.EMPTY_BLAKE_ROOT, v.encoding.emptyRoots.blake2b256);
  for (const c of v.leafEncodings) {
    const leaf = parseLeaf(c.leaf);
    assert.equal(m.bytesToHex(m.encodeLeaf(leaf)), c.encoded, `encode ${c.name}`);
    assert.equal(m.leafHash(leaf, m.KECCAK256), c.keccakLeafHash, `keccak leaf ${c.name}`);
    assert.equal(m.leafHash(leaf, m.BLAKE2B256), c.blakeLeafHash, `blake leaf ${c.name}`);
    assert.equal(m.nullifierOf(leaf), c.nullifier, `nullifier ${c.name}`);
  }
}

export function replayTrees(m: M, v: J): void {
  for (const t of v.trees) {
    const leaves = t.leaves.map(parseLeaf);
    const c = parseCommitment(t.commitment);
    // Reverse the input so the builder's own sort is exercised.
    const snap = m.buildSnapshot(
      { domain: c, hook: c.hook, epoch: c.epoch, epochLength: BigInt(v.encoding.epochLength) },
      [...leaves].reverse(),
    );
    assert.deepEqual(snap.commitment, c, `commitment ${t.name}`);
    assert.equal(snap.jobId, t.jobId, `jobId ${t.name}`);
    assert.deepEqual([...snap.tree.leafHashes.keccak256], t.keccakLeafHashes, `keccak leaves ${t.name}`);
    assert.deepEqual([...snap.tree.leafHashes.blake2b256], t.blakeLeafHashes, `blake leaves ${t.name}`);
    for (const p of t.proofs) {
      const i = Number(p.index);
      for (const [hash, key, root, hashes] of [
        [m.KECCAK256, "keccakSiblings", c.keccakRoot, t.keccakLeafHashes],
        [m.BLAKE2B256, "blakeSiblings", c.blakeRoot, t.blakeLeafHashes],
      ] as const) {
        const proof = snap.tree.proof(i, hash);
        assert.deepEqual([...proof.siblings], p[key], `${key} ${t.name}[${i}]`);
        const ok = m.verifyProof(hash, root, hashes[i], { index: BigInt(i), leafCount: c.leafCount, siblings: p[key] });
        assert.equal(ok, true, `verify ${key} ${t.name}[${i}]`);
      }
    }
  }
  for (const n of v.negativeProofs) {
    const ok = m.verifyProof(m.KECCAK256, n.root, n.leafHash, { index: BigInt(n.index), leafCount: BigInt(n.leafCount), siblings: n.siblings });
    assert.equal(ok, false, `negative proof ${n.name} must be rejected`);
  }
}

export function replayCommitments(m: M, v: J): void {
  for (const c of v.jobIds) assert.equal(m.jobIdOf(parseCommitment(c.commitment)), c.jobId, `jobId ${c.name}`);
  for (const n of v.nullifiers) {
    const got = m.nullifierOf({ flopGenesis: n.flopGenesis, evmChainId: BigInt(n.evmChainId), poolId: n.poolId, channelId: n.channelId, epoch: BigInt(n.epoch) });
    assert.equal(got, n.nullifier, `nullifier ${n.name}`);
  }
  for (const p of v.payouts) {
    const got = m.waterfall(BigInt(p.escrow), BigInt(p.lenderPrincipal), BigInt(p.owed));
    assert.deepEqual(
      got,
      { toProvider: BigInt(p.toProvider), toLender: BigInt(p.toLender), toPayer: BigInt(p.toPayer), overrun: BigInt(p.overrun), lenderShortfall: BigInt(p.lenderShortfall) },
      `waterfall ${p.escrow}/${p.lenderPrincipal}/${p.owed}`,
    );
  }
  for (const r of v.reclaimEligibility) {
    const got = m.reclaimEligible(BigInt(r.checkpointHeight), BigInt(r.finalizedHeight), BigInt(r.stalenessBlocks), BigInt(r.challengeWindowBlocks));
    assert.equal(got, r.eligible, `eligibility ${r.finalizedHeight}/${r.checkpointHeight}`);
  }
}

export function replayRewards(m: M, v: J): void {
  const s = v.rewardsScenario;
  const p = s.params;
  const registry = new m.RootRegistry({ domain: parseCommitment({ ...p, epoch: 0, checkpointHeight: 0, leafCount: 0 }), hook: p.hook, epochLength: BigInt(p.epochLength) });
  const rewards = new m.AgentRewardsModel(registry, { claimWindowEpochs: BigInt(p.claimWindowEpochs) });
  for (const [i, st] of s.steps.entries()) {
    if (st.op === "acceptRoot") {
      assert.equal(outcome(m, () => void registry.accept(parseCommitment(st.commitment), st.attested)), st.expect, `rewards ${i}: ${st.note}`);
      if (st.expect === "OK") assert.equal(registry.latestJobId(), st.jobId);
    } else {
      let credit = 0n;
      const code = outcome(m, () => {
        credit = rewards.claim({ jobId: st.jobId, leaf: parseLeaf(st.leaf), proof: parseProof(st.proof) }).credit;
      });
      assert.equal(code, st.expect, `rewards ${i}: ${st.note}`);
      assert.equal(credit, BigInt(st.credit), `rewards ${i} credit: ${st.note}`);
    }
  }
  assert.equal(rewards.totalCredited(), BigInt(s.totalCredited));
}

export function replayMinter(m: M, v: J): void {
  const s = v.minterScenario;
  const p = s.params;
  const registry = new m.RootRegistry({ domain: parseCommitment({ ...p, epoch: 0, checkpointHeight: 0, leafCount: 0 }), hook: p.hook, epochLength: BigInt(p.epochLength) });
  const minter = new m.OmerMinterModel(registry, {
    stalenessBlocks: BigInt(p.stalenessBlocks),
    challengeWindowBlocks: BigInt(p.challengeWindowBlocks),
    reclaimPolicy: p.reclaimPolicy,
  });
  for (const [i, st] of s.steps.entries()) {
    const what = `minter ${i}: ${st.note}`;
    if (st.op === "acceptRoot") assert.equal(outcome(m, () => void registry.accept(parseCommitment(st.commitment), true)), st.expect, what);
    else if (st.op === "open") {
      const l = st.lock;
      const lock = { ...l, lenderPrincipal: BigInt(l.lenderPrincipal), payerDeposit: BigInt(l.payerDeposit) };
      assert.equal(outcome(m, () => void minter.open(lock)), st.expect, what);
    } else {
      let got: unknown = { toProvider: 0n, toLender: 0n, toPayer: 0n, overrun: 0n, lenderShortfall: 0n };
      const claim = { jobId: st.jobId, leaf: parseLeaf(st.leaf), proof: parseProof(st.proof) };
      const code = outcome(m, () => {
        const r = st.op === "redeem" ? minter.redeem(st.lockId, claim, st.by) : minter.reclaim(st.lockId, claim, st.by);
        got = { toProvider: r.toProvider, toLender: r.toLender, toPayer: r.toPayer, overrun: r.overrun, lenderShortfall: r.lenderShortfall };
      });
      assert.equal(code, st.expect, what);
      const e = st.payouts;
      assert.deepEqual(
        got,
        { toProvider: BigInt(e.toProvider), toLender: BigInt(e.toLender), toPayer: BigInt(e.toPayer), overrun: BigInt(e.overrun), lenderShortfall: BigInt(e.lenderShortfall) },
        `${what} payouts`,
      );
    }
  }
}

export function replayAll(m: M, v: J = loadVectors()): void {
  replayPrimitives(m, v);
  replayTrees(m, v);
  replayCommitments(m, v);
  replayRewards(m, v);
  replayMinter(m, v);
}
