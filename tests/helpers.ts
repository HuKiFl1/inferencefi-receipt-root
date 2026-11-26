import fc from "fast-check";
import {
  type Hex,
  KECCAK256,
  type ReceiptClaim,
  type ReceiptDomain,
  type ReceiptLeaf,
  RootRegistry,
  type Snapshot,
  U128_MAX,
  ZERO32,
  blake2b256,
  buildSnapshot,
  bytesToHex,
  checkpointOf,
  isReceiptRootError,
  utf8,
} from "../src/index.js";

export const RUNS = Number(process.env.PROPERTY_RUNS ?? 100);

export const label = (s: string): Hex => bytesToHex(blake2b256(utf8(`inferencefi-receipt-root/unit/${s}`)));
export const addr = (s: string): Hex => `0x${label(s).slice(-40)}`;

export const DOMAIN: ReceiptDomain = { flopGenesis: label("genesis"), evmChainId: 998n, poolId: label("pool") };
export const HOOK = addr("hook");
export const EPOCH_LENGTH = 1_000n;

export function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    if (isReceiptRootError(e)) return e.code;
    throw e;
  }
  return "OK";
}

export interface Spec {
  readonly ch: string;
  readonly nonce: bigint;
  readonly owed: bigint;
  readonly escrow: bigint;
  readonly height: bigint;
}

export function leafOf(s: Spec, epoch: bigint, domain: ReceiptDomain = DOMAIN): ReceiptLeaf {
  return {
    ...domain,
    channelId: label(`ch/${s.ch}`),
    provider: label(`provider/${s.ch}`),
    payer: label(`payer/${s.ch}`),
    cumulativeOwed: s.owed,
    escrow: s.escrow,
    nonce: s.nonce,
    epoch,
    finalizedHeight: s.height,
    stateRoot: s.nonce === 0n ? ZERO32 : label(`state/${s.ch}/${s.nonce}/${s.owed}`),
  };
}

export function snap(epoch: bigint, leaves: readonly ReceiptLeaf[], domain: ReceiptDomain = DOMAIN, hook: Hex = HOOK): Snapshot {
  return buildSnapshot({ domain, hook, epoch, epochLength: EPOCH_LENGTH }, leaves);
}

export function claimOf(s: Snapshot, channelId: Hex): ReceiptClaim {
  const i = s.tree.indexOf(channelId);
  if (i < 0) throw new Error("channel not in snapshot");
  return { jobId: s.jobId, leaf: s.tree.leaves[i]!, proof: s.tree.proof(i, KECCAK256) };
}

export function registry(domain: ReceiptDomain = DOMAIN, hook: Hex = HOOK): RootRegistry {
  return new RootRegistry({ domain, hook, epochLength: EPOCH_LENGTH });
}

export const arbHex32: fc.Arbitrary<Hex> = fc
  .uint8Array({ minLength: 32, maxLength: 32 })
  .map(bytesToHex)
  .filter((h) => h !== ZERO32);

/** A random valid leaf in `domain` for `epoch`, finalized at or before the checkpoint. */
export function arbLeaf(epoch: bigint, domain: ReceiptDomain = DOMAIN): fc.Arbitrary<ReceiptLeaf> {
  const cp = checkpointOf(epoch, EPOCH_LENGTH);
  return fc
    .record({
      channelId: arbHex32,
      provider: arbHex32,
      payer: arbHex32,
      nonce: fc.bigInt({ min: 0n, max: 1n << 40n }),
      owed: fc.bigInt({ min: 1n, max: U128_MAX }),
      escrow: fc.bigInt({ min: 0n, max: U128_MAX }),
      height: fc.bigInt({ min: 0n, max: cp }),
      stateRoot: arbHex32,
    })
    .filter((r) => r.provider !== r.payer)
    .map((r) => ({
      ...domain,
      channelId: r.channelId,
      provider: r.provider,
      payer: r.payer,
      cumulativeOwed: r.nonce === 0n ? 0n : r.owed,
      escrow: r.escrow,
      nonce: r.nonce,
      epoch,
      finalizedHeight: r.height,
      stateRoot: r.nonce === 0n ? ZERO32 : r.stateRoot,
    }));
}

export function arbLeafSet(epoch: bigint, maxLength = 24, domain: ReceiptDomain = DOMAIN): fc.Arbitrary<ReceiptLeaf[]> {
  return fc.uniqueArray(arbLeaf(epoch, domain), { maxLength, selector: (l) => l.channelId });
}
