import fc from "fast-check";
import {
  type BuiltEpoch,
  FlopReceiptRootModel,
  type Hex,
  type Settlement,
  bytesToHex,
  buildEpoch,
  keccak256,
  utf8,
} from "../src/index.js";

export const RUNS = Number(process.env.PROPERTY_RUNS ?? 100);

export const label = (s: string): Hex => bytesToHex(keccak256(utf8(`inferencefi-receipt-root/v2/unit/${s}`)));
export const addr = (s: string): Hex => `0x${label(s).slice(-40)}`;

export const GENESIS = label("genesis");
export const CHAIN = 998n;
export const ROOTS = addr("roots");
export const MODEL = label("model");
export const POOL = label("pool");
export const POOL_2 = label("pool-2");
export const MANAGER = addr("manager");

export function settlement(ch: number, block: bigint, o: Partial<Settlement> = {}): Settlement {
  return {
    genesis: GENESIS,
    channelId: label(`ch/${ch}`),
    settledBlock: block,
    settledBlockHash: label(`bh/${block}`),
    eventIndex: 0n,
    agent: label(`agent/${ch}`),
    miner: label(`miner/${ch}`),
    modelHash: MODEL,
    aggregateGn: 1_000n,
    minerPaid: 100n,
    burned: 0n,
    escrow: 10_000n,
    ...o,
  };
}

export const newRoots = (startBlock = 1n): FlopReceiptRootModel =>
  new FlopReceiptRootModel({ genesis: GENESIS, startBlock, chainId: CHAIN, verifyingContract: ROOTS });

/** Builds and submits consecutive epochs of `len` blocks starting at the roots' next block. */
export function submitEpoch(roots: FlopReceiptRootModel, len: bigint, settlements: readonly Settlement[]): BuiltEpoch {
  const fromBlock = roots.nextFromBlock;
  const e = buildEpoch({ genesis: GENESIS, epoch: roots.lastEpoch + 1n, fromBlock, toBlock: fromBlock + len - 1n, toBlockHash: label(`head/${fromBlock}`), settlements });
  roots.submit(e.msg, true);
  return e;
}

export const proofOf = (e: BuiltEpoch, s: Settlement): readonly Hex[] => {
  const it = e.items.find((i) => i.settlement === s);
  if (it === undefined) throw new Error("settlement not in epoch");
  return it.proof;
};

/** Distinct 32-byte leaves. */
export const arbLeaves = (min: number, max: number) =>
  fc.uniqueArray(fc.uint8Array({ minLength: 32, maxLength: 32 }).map((b) => bytesToHex(b)), { minLength: min, maxLength: max });

export const arbHex32 = fc.uint8Array({ minLength: 32, maxLength: 32 }).map((b) => bytesToHex(b));
