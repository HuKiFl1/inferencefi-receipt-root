import assert from "node:assert/strict";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { type M, loadVectors, replayAll } from "./replay.js";

/**
 * Mutation-style check: each mutant injects one realistic bug into a copy of
 * src/, and an independent battery must fail on it. The battery replays the
 * committed JSON vectors and adds a few attacks the vectors cannot express.
 * The unmutated copy must pass the same battery, so a kill cannot come from
 * the harness.
 */

interface Mutant {
  readonly id: string;
  readonly file: string;
  readonly find: string;
  readonly replace: string;
}

const MUTANTS: readonly Mutant[] = [
  // hashes
  { id: "keccak-sha3-padding", file: "hash/keccak.ts", find: "last[message.length - offset]! ^ 0x01;", replace: "last[message.length - offset]! ^ 0x06;" },
  { id: "blake2b-fixed-512-param", file: "hash/blake2b.ts", find: "h[0] = (h[0]! ^ 0x01010000 ^ outLen) >>> 0;", replace: "h[0] = (h[0]! ^ 0x01010000 ^ 64) >>> 0;" },
  // encoding
  { id: "little-endian-integers", file: "bytes.ts", find: "for (let i = width - 1; i >= 0; i--) {", replace: "for (let i = 0; i < width; i++) {" },
  { id: "leaf-without-prefix", file: "leaf.ts", find: "return hash(concatBytes(Uint8Array.of(Prefix.LEAF), encodeLeaf(leaf)));", replace: "return hash(encodeLeaf(leaf));" },
  { id: "leaf-drops-state-root", file: "leaf.ts", find: "    fixedBytes(leaf.stateRoot, 32, \"stateRoot\"),\n  );", replace: "    new Uint8Array(32),\n  );" },
  // tree
  { id: "node-without-prefix", file: "merkle.ts", find: "return hash(concatBytes(Uint8Array.of(Prefix.NODE), left, right));", replace: "return hash(concatBytes(left, right));" },
  { id: "duplicate-odd-node", file: "merkle.ts", find: ": level[i]!);", replace: ": nodeHashBytes(hash, level[i]!, level[i]!));" },
  { id: "empty-root-zero", file: "merkle.ts", find: "return bytesToHex(hash(new Uint8Array(0)));", replace: "return bytesToHex(new Uint8Array(32));" },
  { id: "verify-ignores-leftover-siblings", file: "merkle.ts", find: "return k === siblings.length && bytesToHex(h) === root;", replace: "return bytesToHex(h) === root;" },
  { id: "verify-accepts-index-out-of-range", file: "merkle.ts", find: "index < 0n || index >= leafCount) return false;", replace: "index < 0n) return false;" },
  { id: "tree-unsorted", file: "merkle.ts", find: "const leaves = [...input].sort((a, b) => compareHex(a.channelId, b.channelId));", replace: "const leaves = [...input];" },
  { id: "tree-allows-duplicate-channel", file: "merkle.ts", find: "if (leaves[i]!.channelId === leaves[i - 1]!.channelId) {", replace: "if (false) {" },
  // commitments
  { id: "job-id-without-chain", file: "commitment.ts", find: "        uintBE(c.evmChainId, 8),\n        fixedBytes(c.hook, 20, \"hook\"),", replace: "        fixedBytes(c.hook, 20, \"hook\")," },
  { id: "job-id-without-blake-root", file: "commitment.ts", find: "        fixedBytes(c.blakeRoot, 32, \"blakeRoot\"),\n", replace: "" },
  { id: "job-id-without-leaf-count", file: "commitment.ts", find: "        uintBE(c.leafCount, 8),\n", replace: "" },
  { id: "nullifier-without-epoch", file: "commitment.ts", find: "        fixedBytes(leaf.channelId, 32, \"channelId\"),\n        uintBE(leaf.epoch, 8),\n", replace: "        fixedBytes(leaf.channelId, 32, \"channelId\"),\n" },
  // registry
  { id: "registry-second-root-per-epoch", file: "registry.ts", find: "if (this.#byEpoch.has(c.epoch)) fail(", replace: "if (false) fail(" },
  { id: "registry-no-checkpoint-pin", file: "registry.ts", find: "if (c.checkpointHeight !== checkpointOf(c.epoch, this.params.epochLength)) {", replace: "if (false) {" },
  { id: "registry-ignores-attestation", file: "registry.ts", find: "if (!attested) fail(", replace: "if (false) fail(" },
  // receipt verification
  { id: "receipt-no-epoch-binding", file: "receipt.ts", find: "if (leaf.epoch !== c.epoch) fail(", replace: "if (false) fail(" },
  { id: "receipt-no-domain-check", file: "receipt.ts", find: "if (!sameDomain(leaf, c)) fail(", replace: "if (false) fail(" },
  { id: "receipt-leaf-count-unbound", file: "receipt.ts", find: "if (proof.leafCount !== c.leafCount || !verifyProof(", replace: "if (!verifyProof(" },
  // AgentRewards
  { id: "rewards-no-nullifier", file: "rewards.ts", find: "if (this.#spent.has(nullifier)) fail(", replace: "if (false) fail(" },
  { id: "rewards-credit-uncapped", file: "rewards.ts", find: "const credit = min(leaf.cumulativeOwed, leaf.escrow) - min(lastOwed, leaf.escrow);", replace: "const credit = leaf.cumulativeOwed - lastOwed;" },
  { id: "rewards-accepts-rollback", file: "rewards.ts", find: "if (leaf.nonce < lastNonce) fail(", replace: "if (false) fail(" },
  { id: "rewards-window-off-by-one", file: "rewards.ts", find: "if (latest.epoch > c.epoch + this.#params.claimWindowEpochs) {", replace: "if (latest.epoch >= c.epoch + this.#params.claimWindowEpochs) {" },
  // OmerMinter and settlement
  { id: "minter-reclaim-any-root", file: "minter.ts", find: "if (claim.jobId !== this.#registry.latestJobId()) fail(", replace: "if (false) fail(" },
  { id: "minter-redeem-by-anyone", file: "minter.ts", find: "if (by !== lock.provider) fail(", replace: "if (false) fail(" },
  { id: "minter-settles-twice", file: "minter.ts", find: "if (lock.status !== \"Locked\") fail(", replace: "if (false) fail(" },
  { id: "minter-redeem-unserved", file: "minter.ts", find: "if (claim.leaf.nonce === 0n || claim.leaf.cumulativeOwed === 0n) fail(", replace: "if (false) fail(" },
  { id: "minter-no-escrow-binding", file: "minter.ts", find: "if (leaf.escrow !== lock.escrow) fail(", replace: "if (false) fail(" },
  { id: "timeout-off-by-one", file: "settlement.ts", find: "return checkpointHeight >= earliestReclaimHeight(", replace: "return checkpointHeight > earliestReclaimHeight(" },
  { id: "timeout-ignores-window", file: "settlement.ts", find: "return finalizedHeight + stalenessBlocks + challengeWindowBlocks;", replace: "return finalizedHeight + stalenessBlocks;" },
  { id: "payer-senior-to-lender", file: "settlement.ts", find: "const toLender = min(lenderPrincipal, escrow - toProvider);", replace: "const toLender = escrow - toProvider - min(escrow - lenderPrincipal, escrow - toProvider);" },
  // watchers
  { id: "audit-misses-rollback", file: "audit.ts", find: "if (b.nonce < a.nonce) out.push(", replace: "if (false) out.push(" },
  { id: "audit-misses-blake-mismatch", file: "audit.ts", find: "if (tree.roots.blake2b256 !== c.blakeRoot) out.push(", replace: "if (false) out.push(" },
];

type Hex = `0x${string}`;

/** Attacks the JSON vectors do not express directly. */
function extraChecks(m: M): void {
  const lbl = (s: string): Hex => m.bytesToHex(m.blake2b256(m.utf8(`mutation/${s}`)));
  const domain = { flopGenesis: lbl("g"), evmChainId: 998n, poolId: lbl("p") };
  const hook = `0x${lbl("h").slice(-40)}` as Hex;
  const leaf = (ch: string, epoch: bigint, nonce: bigint, owed: bigint) => ({
    ...domain,
    channelId: lbl(`c/${ch}`),
    provider: lbl(`pr/${ch}`),
    payer: lbl(`pa/${ch}`),
    cumulativeOwed: owed,
    escrow: 100n,
    nonce,
    epoch,
    finalizedHeight: epoch * 10n,
    stateRoot: nonce === 0n ? m.ZERO32 : lbl(`s/${ch}/${nonce}`),
  });
  const code = (fn: () => unknown): string => {
    try {
      fn();
    } catch (e) {
      if (m.isReceiptRootError(e)) return e.code;
      throw e;
    }
    return "OK";
  };

  // leafCount must come from the commitment: index 0 of a 5-leaf tree also verifies at count 6.
  const five = ["a", "b", "c", "d", "e"].map((c) => leaf(c, 1n, 1n, 1n));
  const s = m.buildSnapshot({ domain, hook, epoch: 1n, epochLength: 10n }, five);
  const reg = new m.RootRegistry({ domain, hook, epochLength: 10n });
  reg.accept(s.commitment, true);
  const p0 = s.tree.proof(0, m.KECCAK256);
  assert.equal(code(() => m.verifyReceipt(reg, { jobId: s.jobId, leaf: s.tree.leaves[0]!, proof: { ...p0, leafCount: 6n } })), "INVALID_PROOF");

  // A faulty attester's rollback is visible to watchers.
  const findings = m.auditTransition([leaf("r", 1n, 5n, 50n)], [leaf("r", 2n, 4n, 50n)]).map((f) => f.code);
  assert.ok(findings.includes("STALE_NONCE"));
  const s2 = m.buildSnapshot({ domain, hook, epoch: 2n, epochLength: 10n }, [leaf("x", 2n, 1n, 1n)]);
  const forged = { ...s.commitment, blakeRoot: s2.commitment.blakeRoot };
  assert.deepEqual(m.auditSnapshot(forged, s.tree.leaves, 10n).map((f) => f.code), ["BLAKE_ROOT_MISMATCH"]);
  assert.equal(code(() => reg.accept({ ...s2.commitment }, false)), "UNAUTHORIZED_ATTESTER");

  // Snapshot input order must not matter and a duplicate channel must be refused.
  const rev = m.buildSnapshot({ domain, hook, epoch: 1n, epochLength: 10n }, [...five].reverse());
  assert.equal(rev.jobId, s.jobId);
  assert.equal(code(() => m.buildReceiptTree([five[0]!, { ...five[0]!, nonce: 2n }])), "DUPLICATE_CHANNEL");
}

function battery(m: M): void {
  replayAll(m, loadVectors());
  extraChecks(m);
}

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const workDir = join(root, ".mutants", `run-${process.pid}`);

async function load(id: string, mutate?: Mutant): Promise<M> {
  const dir = join(workDir, id);
  mkdirSync(dir, { recursive: true });
  cpSync(join(root, "src"), join(dir, "src"), { recursive: true });
  if (mutate !== undefined) {
    const path = join(dir, "src", mutate.file);
    const text = readFileSync(path, "utf8");
    const count = text.split(mutate.find).length - 1;
    if (count !== 1) throw new Error(`mutant ${mutate.id}: pattern found ${count} times in ${mutate.file}`);
    writeFileSync(path, text.replace(mutate.find, mutate.replace));
  }
  return (await import(pathToFileURL(join(dir, "src", "index.ts")).href)) as M;
}

afterAll(() => rmSync(workDir, { recursive: true, force: true }));

describe("mutation testing", () => {
  it("the unmutated copy passes the battery", async () => {
    battery(await load("control"));
  });

  it.each(MUTANTS.map((mt) => [mt.id, mt] as const))("kills %s", async (_id, mutant) => {
    const m = await load(mutant.id, mutant);
    expect(() => battery(m), `mutant ${mutant.id} survived`).toThrow();
  });
});
