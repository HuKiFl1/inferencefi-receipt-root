import { ErrorCode, fail } from "./errors.js";

/** Assumed EVM decimals of OMER. Open question in DESIGN.md. */
export const OMER_DECIMALS = 18n;
export const OMER_UNIT = 10n ** OMER_DECIMALS;
/** 1 OMER = 750k input + 250k output tokens of the tier's reference model. */
export const OMER_INPUT_TOKENS = 750_000n;
export const OMER_OUTPUT_TOKENS = 250_000n;

export interface Usage {
  readonly inputTokens: bigint;
  readonly outputTokens: bigint;
  /** Reference-model price per input token, in any integer unit shared with `outputPrice`. */
  readonly inputPrice: bigint;
  readonly outputPrice: bigint;
}

/**
 * Cumulative OMER owed, in base units, for cumulative token usage:
 *
 *   floor(OMER_UNIT · (in·pIn + out·pOut) / (750_000·pIn + 250_000·pOut))
 *
 * Rounds down, against the provider. Compute it from cumulative counts each
 * time, never by summing per-call results, so total rounding loss stays < 1 base unit.
 */
export function omerFromUsage(u: Usage): bigint {
  for (const k of ["inputTokens", "outputTokens", "inputPrice", "outputPrice"] as const) {
    if (typeof u[k] !== "bigint" || u[k] < 0n) fail(ErrorCode.INVALID_INPUT, `${k} must be a bigint >= 0`);
  }
  const denominator = OMER_INPUT_TOKENS * u.inputPrice + OMER_OUTPUT_TOKENS * u.outputPrice;
  if (denominator === 0n) fail(ErrorCode.INVALID_INPUT, "at least one price must be positive");
  return (OMER_UNIT * (u.inputTokens * u.inputPrice + u.outputTokens * u.outputPrice)) / denominator;
}
