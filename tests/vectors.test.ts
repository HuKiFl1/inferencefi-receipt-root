import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as lib from "../src/index.js";
import { serializeVectors } from "../scripts/vectors.js";
import { VECTORS_PATH, loadVectors, replayAll } from "./replay.js";

describe("vectors/if-d8-v2.json", () => {
  it("is exactly what the generator produces (run `npm run vectors` after changing scripts/vectors.ts)", () => {
    expect(readFileSync(VECTORS_PATH, "utf8")).toBe(serializeVectors());
  });

  it("replays through the reference implementation", () => {
    replayAll(lib, loadVectors());
  });

  it("covers every contract-facing error code and every adversarial case the brief names", () => {
    const v = loadVectors();
    const expects = new Set<string>(v.scenario.steps.map((s: { expect?: string }) => s.expect).filter(Boolean));
    for (const c of Object.values(lib.ErrorCode).filter((c) => c !== "INVALID_INPUT")) expect(expects, c).toContain(c);
    const notes = v.scenario.steps.map((s: { note: string }) => s.note).join("\n");
    for (const needle of ["another genesis", "replayed as epoch 2", "forged proof", "double-claim", "non-contiguous", "not the latest root", "no longer the latest root"]) {
      expect(notes, needle).toContain(needle);
    }
    expect(v.proofCases.cases.map((c: { name: string }) => c.name)).toContain("inner-node-as-raw-leaf");
    const jobNames = v.jobIdCases.cases.map((c: { name: string }) => c.name);
    expect(jobNames).toContain("same event key, different leaf layout");
    expect(jobNames).toContain("different eventIndex");
    expect(v.format.jobIdTagString).toBe("InferenceFi.IF-D8.jobId.v1");
    expect(v.format.jobIdTag).toBe(lib.JOB_ID_TAG);
  });
});
