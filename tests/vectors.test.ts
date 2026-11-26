import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as m from "../src/index.js";
import { serializeVectors } from "../scripts/vectors.js";
import { loadVectors, replayCommitments, replayMinter, replayPrimitives, replayRewards, replayTrees } from "./replay.js";

describe("test vectors", () => {
  it("the committed JSON is exactly what the generator produces (run `npm run vectors` after a change)", () => {
    const committed = readFileSync(new URL("../vectors/receipt-root-v1.json", import.meta.url), "utf8");
    expect(committed).toBe(serializeVectors());
  });

  const v = loadVectors();
  it("hashes, leaf encodings and nullifiers replay", () => replayPrimitives(m, v));
  it("trees, proofs and negative proofs replay", () => replayTrees(m, v));
  it("jobIds, payouts and reclaim eligibility replay", () => replayCommitments(m, v));
  it("AgentRewards scenario replays", () => replayRewards(m, v));
  it("OmerMinter scenario replays", () => replayMinter(m, v));

  it("covers every negative-proof class and every scenario outcome the threat model names", () => {
    expect(v.negativeProofs.length).toBeGreaterThanOrEqual(13);
    const rewardCodes = new Set(v.rewardsScenario.steps.map((s: { expect: string }) => s.expect));
    for (const c of ["OK", "UNAUTHORIZED_ATTESTER", "ROOT_EXISTS", "EPOCH_REGRESSION", "NULLIFIER_SPENT", "STATE_REPLAYED", "INVALID_PROOF", "DOMAIN_MISMATCH", "EPOCH_MISMATCH", "STALE_NONCE", "EPOCH_EXPIRED", "UNKNOWN_ROOT", "CHECKPOINT_MISMATCH", "EMPTY_ROOT_MISMATCH"]) {
      expect(rewardCodes.has(c), c).toBe(true);
    }
    const minterCodes = new Set(v.minterScenario.steps.map((s: { expect: string }) => s.expect));
    for (const c of ["OK", "DUPLICATE_LOCK", "UNAUTHORIZED", "ALREADY_SETTLED", "TIMEOUT_NOT_REACHED", "NOT_SERVED", "CHANNEL_MISMATCH", "STALE_ROOT", "ESCROW_MISMATCH", "PARTY_MISMATCH"]) {
      expect(minterCodes.has(c), c).toBe(true);
    }
    const jobIds = new Set(v.jobIds.map((j: { jobId: string }) => j.jobId));
    expect(jobIds.size).toBe(v.jobIds.length);
  });
});
