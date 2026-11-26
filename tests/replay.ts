import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type * as Lib from "../src/index.js";

/** Replays vectors/if-d8-v2.json against a copy of the library (the real one, or a mutant). */
export type M = typeof Lib;
type Hex = Lib.Hex;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type J = Record<string, any>;

export const VECTORS_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "vectors", "if-d8-v2.json");
export const loadVectors = (): J => JSON.parse(readFileSync(VECTORS_PATH, "utf8")) as J;

const big = (v: string | number): bigint => BigInt(v);
const msgOf = (j: J): Lib.RootMsg => ({
  genesis: j.genesis,
  epoch: big(j.epoch),
  fromBlock: big(j.fromBlock),
  toBlock: big(j.toBlock),
  toBlockHash: j.toBlockHash,
  count: big(j.count),
  root: j.root,
});
const lockOf = (j: J): Lib.LockInput => ({
  lockId: j.lockId,
  channelId: j.channelId,
  agent: j.agent,
  miner: j.miner,
  modelHash: j.modelHash,
  payer: j.payer,
  provider: j.provider,
  lender: j.lender,
  lenderPrincipal: big(j.lenderPrincipal),
  payerDeposit: big(j.payerDeposit),
  omerPerGnNum: big(j.omerPerGnNum),
  omerPerGnDen: big(j.omerPerGnDen),
  minFlopBlock: big(j.minFlopBlock),
});

function outcome(m: M, fn: () => void): string {
  try {
    fn();
    return "OK";
  } catch (e) {
    if (m.isReceiptRootError(e)) return e.code;
    throw e;
  }
}

export function replayFormat(m: M, v: J): void {
  assert.equal(m.LEAF_TYPEHASH, v.format.leafTypehash, "LEAF_TYPEHASH");
  assert.equal(m.ROOT_TYPEHASH, v.format.rootTypehash, "ROOT_TYPEHASH");
  assert.equal(m.domainSeparator(big(v.format.domain.chainId), v.format.domain.verifyingContract), v.format.domain.separator, "domain separator");
  for (const c of v.leaves) {
    const s = m.settlementFromJson(c.settlement);
    assert.equal(m.bytesToHex(m.encodeSettlement(s)), c.encoding, `encoding ${c.name}`);
    assert.equal(m.leafOf(s), c.leaf, `leaf ${c.name}`);
  }
  for (const t of v.trees) {
    const leaves: Hex[] = t.settlements.map((s: Lib.SettlementJson) => m.leafOf(m.settlementFromJson(s)));
    assert.deepEqual(leaves, t.leaves, `leaves ${t.name}`);
    const tree = m.buildTree(leaves);
    assert.deepEqual(tree.layers[0], t.sortedLeaves, `sorted ${t.name}`);
    assert.equal(tree.root, t.root, `root ${t.name}`);
    for (const [i, l] of leaves.entries()) {
      assert.deepEqual(m.proofFor(tree, l), t.proofs[i], `proof ${t.name}[${i}]`);
      assert.equal(m.verifyRawProof(t.root, l, t.proofs[i]), true, `verify ${t.name}[${i}]`);
    }
  }
  const pc = v.proofCases;
  assert.equal(m.pairHash(pc.nodeAsLeaf.left, pc.nodeAsLeaf.right), pc.nodeAsLeaf.node, "inner node");
  for (const c of pc.cases) assert.equal(m.verifyRawProof(c.root, c.leaf, c.proof), c.expect, `proof case ${c.name}`);
  const d = v.format.domain;
  for (const c of v.verifyCases) {
    const msg = msgOf(c.msg);
    const roots = new m.FlopReceiptRootModel({ genesis: msg.genesis, startBlock: msg.fromBlock, chainId: big(d.chainId), verifyingContract: d.verifyingContract });
    assert.equal(roots.digest(msg), c.digest, `verify case ${c.name} digest`);
    roots.submit(msg, true);
    assert.equal(roots.verify(big(c.epoch), m.settlementFromJson(c.settlement), c.proof), c.expect, `verify case ${c.name}`);
  }
  const hd = v.hookDataCases;
  for (const c of hd.cases) {
    assert.equal(outcome(m, () => m.decodeHookData(c.hex)), c.expect, `hookData case ${c.name}`);
    if (c.expect === "OK") {
      const want = { epoch: big(hd.decoded.epoch), settlement: m.settlementFromJson(hd.decoded.settlement), proof: hd.decoded.proof };
      assert.deepEqual(m.decodeHookData(c.hex), want, `hookData case ${c.name} decoded`);
      assert.equal(m.encodeHookData(want), c.hex, `hookData case ${c.name} encoded`);
    }
  }
  const jc = v.jobIdCases;
  assert.equal(m.JOB_ID_TAG, jc.tag, "JOB_ID_TAG");
  assert.equal(m.JOB_ID_TAG_STRING, jc.tagString, "JOB_ID_TAG_STRING");
  assert.equal(m.jobIdOf(m.settlementFromJson(jc.base.settlement)), jc.base.jobId, "jobId base");
  assert.equal(m.leafOf(m.settlementFromJson(jc.base.settlement)), jc.base.leaf, "leaf base");
  for (const c of jc.cases) {
    const a = m.settlementFromJson(c.a);
    const b = m.settlementFromJson(c.b);
    assert.equal(m.jobIdOf(a), c.jobIdA, `jobIdA ${c.name}`);
    assert.equal(m.jobIdOf(b), c.jobIdB, `jobIdB ${c.name}`);
    assert.equal(m.leafOf(a), c.leafA, `leafA ${c.name}`);
    assert.equal(m.leafOf(b), c.leafB, `leafB ${c.name}`);
    assert.equal(m.jobIdOf(a) === m.jobIdOf(b), c.expectEqual, `jobId equal ${c.name}`);
    if (c.expectEqual) assert.notEqual(m.leafOf(a), m.leafOf(b), `leaves differ ${c.name}`);
  }
}

export function replayScenario(m: M, v: J): void {
  const sc = v.scenario;
  const p = sc.params;
  const chain = big(p.evmChainId);
  const roots = new m.FlopReceiptRootModel({ genesis: p.genesis, startBlock: big(p.startBlock), chainId: chain, verifyingContract: p.rootsAddress });
  const hook = new m.ReceiptJobHookModel(roots, { evmChainId: chain, poolManager: p.poolManager, pools: p.pools });
  const rp = { evmChainId: chain, poolId: p.rewards.poolId as Hex, metric: p.rewards.metric as Lib.RewardMetric, claimWindowEpochs: big(p.rewards.claimWindowEpochs) };
  const rewards: Record<string, Lib.AgentRewardsConsumerModel> = {
    sum: new m.AgentRewardsConsumerModel(roots, hook, { ...rp, mode: p.rewards.consumers.sum }),
    latest: new m.AgentRewardsConsumerModel(roots, hook, { ...rp, mode: p.rewards.consumers.latest }),
  };
  const facts = new Map<string, Lib.UnservedFacts>();
  const attestor: Lib.UnservedAttestor = {
    verifyUnserved(genesis, channelId, epoch) {
      const f = facts.get(`${channelId}:${epoch}`);
      if (genesis !== p.genesis || f === undefined) m.fail(m.ErrorCode.AttestationMismatch, "no attestation");
      return f;
    },
  };
  const mp = {
    evmChainId: chain,
    stalenessBlocks: big(p.minter.stalenessBlocks),
    challengeWindowBlocks: big(p.minter.challengeWindowBlocks),
    reclaimPolicy: p.minter.reclaimPolicy as Lib.ReclaimPolicy,
  };
  const minters: Record<string, Lib.OmerMinterConsumerModel> = {
    stub: new m.OmerMinterConsumerModel(roots, m.UNSERVED_ATTESTOR_STUB, mp),
    attested: new m.OmerMinterConsumerModel(roots, attestor, mp),
  };
  const tuple = (s: Lib.Settled) => [s.owed, s.toProvider, s.toLender, s.toPayer, s.overrun, s.lenderShortfall].map(String);

  for (const [e, ep] of (sc.epochs as J[]).entries()) {
    const built = m.buildEpoch({ ...msgOf(ep.msg), settlements: ep.items.map((it: J) => m.settlementFromJson(it.settlement)) });
    assert.deepEqual(built.msg, msgOf(ep.msg), `epoch ${e + 1} message`);
    for (const it of ep.items) assert.deepEqual(built.items.find((b) => b.leaf === it.leaf)?.proof, it.proof, `epoch ${e + 1} proof`);
  }

  for (const [i, st] of (sc.steps as J[]).entries()) {
    const what = `step ${i} (${st.note})`;
    const ctx = { chainId: big(st.chainId ?? p.evmChainId), caller: (st.caller ?? p.poolManager) as Hex };
    const s = st.settlement ? m.settlementFromJson(st.settlement) : undefined;
    if (s) assert.equal(m.leafOf(s), st.leaf, `${what} leaf`);
    switch (st.op) {
      case "submit":
        assert.equal(roots.digest(msgOf(st.msg)), st.digest, `${what} digest`);
        assert.equal(outcome(m, () => roots.submit(msgOf(st.msg), st.quorum)), st.expect, what);
        break;
      case "freeze":
        assert.equal(outcome(m, () => roots.freeze(msgOf(st.msgA), true, msgOf(st.msgB), true)), st.expect, what);
        break;
      case "tag": {
        if (st.canonical) assert.equal(m.encodeHookData({ epoch: big(st.epoch), settlement: s!, proof: st.proof }), st.hookData, `${what} hookData`);
        let job: string | undefined;
        assert.equal(outcome(m, () => (job = hook.tag(ctx, st.poolId, st.hookData).jobId)), st.expect, what);
        assert.equal(job, st.jobId ?? undefined, `${what} jobId`);
        break;
      }
      case "claim": {
        let r: Lib.RewardClaim | undefined;
        assert.equal(outcome(m, () => (r = rewards[st.consumer]!.claim(ctx, big(st.epoch), s!, st.proof))), st.expect, what);
        assert.equal(r?.credit.toString(), st.credit ?? undefined, `${what} credit`);
        assert.equal(r?.channelEpochTotal.toString(), st.channelEpochTotal ?? undefined, `${what} total`);
        break;
      }
      case "open":
        assert.equal(outcome(m, () => minters[st.consumer]!.open(ctx, lockOf(st.lock))), st.expect, what);
        break;
      case "setUnserved":
        facts.set(`${st.channelId}:${big(st.epoch)}`, { lastFinalizedHeight: big(st.lastFinalizedHeight), owed: big(st.owed) });
        break;
      case "redeem": {
        let r: string[] | undefined;
        assert.equal(outcome(m, () => (r = tuple(minters[st.consumer]!.redeem(ctx, st.lockId, big(st.epoch), s!, st.proof)))), st.expect, what);
        assert.deepEqual(r, st.payouts ?? undefined, `${what} payouts`);
        break;
      }
      case "reclaim": {
        let r: string[] | undefined;
        assert.equal(outcome(m, () => (r = tuple(minters[st.consumer]!.reclaim(ctx, st.lockId, big(st.epoch), st.attestation)))), st.expect, what);
        assert.deepEqual(r, st.payouts ?? undefined, `${what} payouts`);
        break;
      }
      default:
        throw new Error(`unknown op ${String(st.op)}`);
    }
  }
  assert.equal(rewards.sum!.totalCredited().toString(), sc.totals.sum, "sum total");
  assert.equal(rewards.latest!.totalCredited().toString(), sc.totals.latest, "latest total");
}

export function replayAll(m: M, v: J): void {
  replayFormat(m, v);
  replayScenario(m, v);
}
