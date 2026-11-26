import { ErrorCode, fail } from "../errors.js";

const min = (a: bigint, b: bigint): bigint => (a < b ? a : b);

export interface Payouts {
  readonly toProvider: bigint;
  readonly toLender: bigint;
  readonly toPayer: bigint;
  /** Owed amount escrow does not back. Recorded, never paid, never minted. */
  readonly overrun: bigint;
  /** Lender principal not recovered. */
  readonly lenderShortfall: bigint;
}

/**
 * The Flop reclaim waterfall (Flop SPEC §10): provider owed first, then lender
 * principal, then the remainder to the payer. Requires 0 <= L <= E and owed >= 0.
 */
export function waterfall(escrow: bigint, lenderPrincipal: bigint, owed: bigint): Payouts {
  if (escrow < 0n || owed < 0n || lenderPrincipal < 0n || lenderPrincipal > escrow) {
    fail(ErrorCode.INVALID_INPUT, "waterfall: require 0 <= lenderPrincipal <= escrow and owed >= 0");
  }
  const toProvider = min(owed, escrow);
  const toLender = min(lenderPrincipal, escrow - toProvider);
  const toPayer = escrow - toProvider - toLender;
  return { toProvider, toLender, toPayer, overrun: owed - toProvider, lenderShortfall: lenderPrincipal - toLender };
}

/**
 * First FLOP finalized height at which a reclaim becomes eligible for a channel
 * whose latest finalized state was recorded at `finalizedHeight`: `N` stale
 * blocks plus the `W`-block challenge window (Flop SPEC I5).
 */
export function earliestReclaimHeight(finalizedHeight: bigint, stalenessBlocks: bigint, challengeWindowBlocks: bigint): bigint {
  return finalizedHeight + stalenessBlocks + challengeWindowBlocks;
}

export function reclaimEligible(
  checkpointHeight: bigint,
  finalizedHeight: bigint,
  stalenessBlocks: bigint,
  challengeWindowBlocks: bigint,
): boolean {
  return checkpointHeight >= earliestReclaimHeight(finalizedHeight, stalenessBlocks, challengeWindowBlocks);
}
