import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  FlopReceiptRootModel,
  LEAF_TYPE,
  ROOT_TYPE,
  type RootMsg,
  type SettlementJson,
  buildEpoch,
  buildTree,
  digest712,
  leafOf,
  proofFor,
  settlementFromJson,
  type Hex,
  type Settlement,
  JOB_ID_TAG,
  JOB_ID_TAG_STRING,
  jobIdOf,
} from "../src/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const vendor = join(root, "vendor", "flop-receipt-root");

interface Fixture {
  chainId: number;
  contract: Hex;
  attesters: Hex[];
  threshold: number;
  digest: Hex;
  msg: Record<keyof RootMsg, string>;
  sigs: Hex[];
  items: { fields: SettlementJson; leaf: Hex; proof: Hex[] }[];
}

const fixture = JSON.parse(readFileSync(join(vendor, "test/fixtures/epoch.json"), "utf8")) as Fixture;
const msg: RootMsg = {
  genesis: fixture.msg.genesis as Hex,
  epoch: BigInt(fixture.msg.epoch),
  fromBlock: BigInt(fixture.msg.fromBlock),
  toBlock: BigInt(fixture.msg.toBlock),
  toBlockHash: fixture.msg.toBlockHash as Hex,
  count: BigInt(fixture.msg.count),
  root: fixture.msg.root as Hex,
};
const settlements = fixture.items.map((it) => settlementFromJson(it.fields));

describe("vendored flop-receipt-root 19042c3", () => {
  it("is byte-identical to the manifest in VENDORED.md", () => {
    const manifest = readFileSync(join(vendor, "VENDORED.md"), "utf8");
    const rows = [...manifest.matchAll(/^\| `([^`]+)` \| `([0-9a-f]{64})` \|$/gm)];
    expect(rows.length).toBe(9);
    for (const [, file, sha] of rows) {
      expect(createHash("sha256").update(readFileSync(join(vendor, file!))).digest("hex"), file).toBe(sha);
    }
  });

  it("declares the same EIP-712 type strings as FlopReceiptRoot.sol", () => {
    const sol = readFileSync(join(vendor, "contracts/src/FlopReceiptRoot.sol"), "utf8");
    expect(sol).toContain(`"${LEAF_TYPE}"`);
    expect(sol).toContain(`"${ROOT_TYPE}"`);
    expect(sol).toContain(`keccak256("${JOB_ID_TAG_STRING}")`);
  });
});

describe("TypeScript port vs the upstream fixture (99 devnet settlements)", () => {
  it("every leaf hash matches", () => {
    expect(fixture.items.length).toBe(99);
    for (const [i, it] of fixture.items.entries()) expect(leafOf(settlements[i]!), `item ${i}`).toBe(it.leaf);
  });

  it("the tree, every proof, the root and the count match", () => {
    const tree = buildTree(fixture.items.map((it) => it.leaf));
    expect(tree.root).toBe(msg.root);
    expect(BigInt(tree.count)).toBe(msg.count);
    for (const it of fixture.items) expect(proofFor(tree, it.leaf)).toEqual(it.proof);
  });

  it("buildEpoch over the fixture settlements reproduces the signed message", () => {
    const built = buildEpoch({ ...msg, settlements });
    expect(built.msg).toEqual(msg);
    const byLeaf = new Map(fixture.items.map((it) => [it.leaf, it.proof]));
    for (const item of built.items) expect(item.proof).toEqual(byLeaf.get(item.leaf));
  });

  it("the EIP-712 digest matches the one the attesters signed", () => {
    expect(digest712(msg, BigInt(fixture.chainId), fixture.contract)).toBe(fixture.digest);
  });

  it("the contract model accepts the root and verifies every receipt", () => {
    const m = new FlopReceiptRootModel({ genesis: msg.genesis, startBlock: msg.fromBlock, chainId: BigInt(fixture.chainId), verifyingContract: fixture.contract });
    m.submit(msg, true);
    for (const [i, it] of fixture.items.entries()) expect(m.verify(1n, settlements[i]!, it.proof), `item ${i}`).toBe(true);
    expect(m.verify(1n, { ...settlements[0]!, minerPaid: settlements[0]!.minerPaid + 1n }, fixture.items[0]!.proof)).toBe(false);
  });
});

interface JobIdFixture {
  tagString: string;
  tag: Hex;
  encodedBytes: number;
  count: number;
  cases: {
    name: string;
    genesis: Hex;
    channelId: Hex;
    settledBlock: string;
    eventIndex: string;
    encoded: Hex;
    jobId: Hex;
  }[];
}

/** Only the event-key fields matter for jobId; the rest of the leaf is dummy. */
function settlementForJobId(c: JobIdFixture["cases"][number]): Settlement {
  return {
    genesis: c.genesis,
    channelId: c.channelId,
    settledBlock: BigInt(c.settledBlock),
    settledBlockHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
    eventIndex: BigInt(c.eventIndex),
    agent: "0x0000000000000000000000000000000000000000000000000000000000000000",
    miner: "0x0000000000000000000000000000000000000000000000000000000000000000",
    modelHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
    aggregateGn: 0n,
    minerPaid: 0n,
    burned: 0n,
    escrow: 0n,
  };
}

const jobIdFixture = JSON.parse(
  readFileSync(join(vendor, "test/fixtures/jobid_vectors.json"), "utf8"),
) as JobIdFixture;

describe("TypeScript port vs the published jobId vectors", () => {
  it("uses the upstream TAG and encoding", () => {
    expect(JOB_ID_TAG_STRING).toBe(jobIdFixture.tagString);
    expect(JOB_ID_TAG).toBe(jobIdFixture.tag);
    expect(JOB_ID_TAG).toBe("0x748fa4722b652359047a16941d7e978a83dcfab3a169bea48a5a663e7d31bd14");
    expect(jobIdFixture.encodedBytes).toBe(160);
    expect(jobIdFixture.cases.length).toBe(6);
    expect(jobIdFixture.count).toBe(6);
  });

  it("matches every published jobId byte for byte", () => {
    for (const c of jobIdFixture.cases) {
      expect(jobIdOf(settlementForJobId(c)), c.name).toBe(c.jobId);
    }
    // eventIndex+1 of item 0 must differ from item 0, as the fixture states
    expect(jobIdFixture.cases[3]!.jobId).not.toBe(jobIdFixture.cases[0]!.jobId);
  });
});
