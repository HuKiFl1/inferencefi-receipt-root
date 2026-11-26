import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { type M, loadVectors, replayAll } from "./replay.js";

/**
 * Single-point mutants of src/. Each must make the vector replay, or the
 * upstream fixture check, fail; otherwise the vectors are not pinning that
 * rule. The unmutated copy must pass.
 */
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const work = join(root, ".mutants");

interface Mutant {
  readonly name: string;
  readonly file: string;
  readonly from: string;
  readonly to: string;
}

const MUTANTS: readonly Mutant[] = [
  { name: "single keccak leaf", file: "format/settlement.ts", from: "keccak256(keccak256(encodeSettlement(s)))", to: "keccak256(encodeSettlement(s))" },
  { name: "unsorted pair hash", file: "format/merkle.ts", from: "compareHex(a, b) <= 0 ? [a, b] : [b, a]", to: "[a, b]" },
  { name: "odd node hashed with itself", file: "format/merkle.ts", from: ": level[i]!);", to: ": pairHash(level[i]!, level[i]!));" },
  { name: "leaves not sorted", file: "format/merkle.ts", from: "[...leaves].sort(compareHex)", to: "[...leaves]" },
  { name: "proof length cap off", file: "format/receiptRoot.ts", from: "this.#frozen || proof.length > MAX_PROOF", to: "this.#frozen" },
  { name: "verify ignores genesis", file: "format/receiptRoot.ts", from: " || s.genesis !== this.params.genesis) return false;", to: ") return false;" },
  { name: "verify ignores block range", file: "format/receiptRoot.ts", from: "if (s.settledBlock < e.fromBlock || s.settledBlock > e.toBlock) return false;", to: "" },
  { name: "verify ignores freeze", file: "format/receiptRoot.ts", from: "if (this.#frozen || proof.length", to: "if (proof.length" },
  { name: "non-contiguous epochs", file: "format/receiptRoot.ts", from: "m.epoch !== this.#lastEpoch + 1n", to: "m.epoch <= this.#lastEpoch" },
  { name: "fromBlock unchecked", file: "format/receiptRoot.ts", from: "if (m.fromBlock !== this.#nextFromBlock) fail", to: "if (false) fail" },
  { name: "submit ignores genesis", file: "format/receiptRoot.ts", from: "if (m.genesis !== this.params.genesis) fail", to: "if (false) fail" },
  { name: "empty root rule off", file: "format/receiptRoot.ts", from: "if ((m.count === 0n) !== (m.root === EMPTY_ROOT)) fail", to: "if (false) fail" },
  { name: "submit ignores quorum", file: "format/receiptRoot.ts", from: "if (!quorum) fail", to: "if (false) fail" },
  { name: "hook ignores pool binding", file: "consumer/hook.ts", from: "bound !== undefined && bound !== poolId", to: "false" },
  { name: "hook ignores model", file: "consumer/hook.ts", from: "if (!models.has(d.settlement.modelHash)) fail", to: "if (false) fail" },
  { name: "hook open to anyone", file: "consumer/hook.ts", from: "if (ctx.caller !== this.params.poolManager) fail", to: "if (false) fail" },
  { name: "rewards no nullifier", file: "consumer/rewards.ts", from: "if (this.#spent.has(leaf)) fail", to: "if (false) fail" },
  { name: "rewards ignore pool", file: "consumer/rewards.ts", from: "if (this.#hook.poolOf(jobId) !== this.params.poolId) fail", to: "if (false) fail" },
  { name: "jobId is the leaf hash", file: "consumer/hook.ts", from: "jobIdOf(d.settlement)", to: "leafOf(d.settlement)" },
  { name: "rewards window off by one", file: "consumer/rewards.ts", from: "this.#roots.lastEpoch > epoch + this.params.claimWindowEpochs", to: "this.#roots.lastEpoch >= epoch + this.params.claimWindowEpochs" },
  { name: "latest mode accepts stale", file: "consumer/rewards.ts", from: "if (!later) fail", to: "if (false) fail" },
  { name: "latest mode credits full amount", file: "consumer/rewards.ts", from: "credit = amount - prev.amount;", to: "credit = amount;" },
  { name: "rewards ignore chain", file: "consumer/rewards.ts", from: "requireChain(ctx, this.params.evmChainId);\n    if (!this.#roots.verify", to: "if (!this.#roots.verify" },
  { name: "redeem ignores parties", file: "consumer/minter.ts", from: "if (s.agent !== lock.agent || s.miner !== lock.miner) fail", to: "if (false) fail" },
  { name: "redeem ignores freshness", file: "consumer/minter.ts", from: "if (s.settledBlock < lock.minFlopBlock) fail", to: "if (false) fail" },
  { name: "redeem by anyone", file: "consumer/minter.ts", from: "if (ctx.caller !== lock.provider) fail", to: "if (false) fail" },
  { name: "reclaim on a stale root", file: "consumer/minter.ts", from: "latest === 0n || epoch !== latest", to: "latest === 0n" },
  { name: "reclaim timeout off by one", file: "consumer/minter.ts", from: "if (checkpoint < opensAt) fail", to: "if (checkpoint <= opensAt) fail" },
  { name: "reclaim while frozen", file: "consumer/minter.ts", from: "if (this.#roots.frozen) fail", to: "if (false) fail" },
  { name: "terminal state not enforced", file: "consumer/minter.ts", from: 'if (lock.status !== "Locked") fail', to: "if (false) fail" },
  { name: "owed rounds up", file: "consumer/minter.ts", from: "(s.aggregateGn * lock.omerPerGnNum) / lock.omerPerGnDen", to: "(s.aggregateGn * lock.omerPerGnNum + lock.omerPerGnDen - 1n) / lock.omerPerGnDen" },
  { name: "waterfall lender before provider", file: "consumer/waterfall.ts", from: "const toProvider = min(owed, escrow);", to: "const toProvider = min(owed, escrow - min(lenderPrincipal, escrow));" },
  { name: "N + W drops W", file: "consumer/waterfall.ts", from: "finalizedHeight + stalenessBlocks + challengeWindowBlocks", to: "finalizedHeight + stalenessBlocks" },
  { name: "hookData offset not checked", file: "format/hookData.ts", from: 'fail(ErrorCode.INVALID_INPUT, "non-canonical proof offset")', to: "void 0" },
];

const vectors = loadVectors();
const fixture = JSON.parse(readFileSync(join(root, "vendor/flop-receipt-root/test/fixtures/epoch.json"), "utf8")) as {
  msg: { root: string };
  items: { fields: Parameters<M["settlementFromJson"]>[0] }[];
};

function battery(m: M): void {
  replayAll(m, vectors);
  const leaves = fixture.items.map((it) => m.leafOf(m.settlementFromJson(it.fields)));
  if (m.buildTree(leaves).root !== fixture.msg.root) throw new Error("upstream fixture root differs");
}

async function load(i: number, mutant?: Mutant): Promise<M> {
  const dir = join(work, String(i));
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  cpSync(join(root, "src"), join(dir, "src"), { recursive: true });
  if (mutant) {
    const f = join(dir, "src", mutant.file);
    const text = readFileSync(f, "utf8");
    if (text.split(mutant.from).length !== 2) throw new Error(`mutant "${mutant.name}": pattern must occur exactly once in ${mutant.file}`);
    writeFileSync(f, text.replace(mutant.from, mutant.to));
  }
  return (await import(pathToFileURL(join(dir, "src", "index.ts")).href)) as M;
}

describe("mutation testing", () => {
  afterAll(() => rmSync(work, { recursive: true, force: true }));

  it("the unmutated copy passes", async () => {
    battery(await load(0));
  });

  for (const [i, mu] of MUTANTS.entries()) {
    it(`kills: ${mu.name}`, async () => {
      const m = await load(i + 1, mu);
      expect(() => battery(m)).toThrow();
    });
  }
});
