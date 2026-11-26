export const ErrorCode = {
  // Encoding
  INVALID_INPUT: "INVALID_INPUT",
  INVALID_LEAF: "INVALID_LEAF",
  DUPLICATE_CHANNEL: "DUPLICATE_CHANNEL",
  INDEX_OUT_OF_RANGE: "INDEX_OUT_OF_RANGE",
  // Root registry
  INVALID_PARAMS: "INVALID_PARAMS",
  UNAUTHORIZED_ATTESTER: "UNAUTHORIZED_ATTESTER",
  DOMAIN_MISMATCH: "DOMAIN_MISMATCH",
  ROOT_EXISTS: "ROOT_EXISTS",
  EPOCH_REGRESSION: "EPOCH_REGRESSION",
  CHECKPOINT_MISMATCH: "CHECKPOINT_MISMATCH",
  EMPTY_ROOT_MISMATCH: "EMPTY_ROOT_MISMATCH",
  UNKNOWN_ROOT: "UNKNOWN_ROOT",
  // Receipt checks shared by AgentRewards and OmerMinter
  INVALID_PROOF: "INVALID_PROOF",
  EPOCH_MISMATCH: "EPOCH_MISMATCH",
  HEIGHT_BEYOND_CHECKPOINT: "HEIGHT_BEYOND_CHECKPOINT",
  CHANNEL_MISMATCH: "CHANNEL_MISMATCH",
  PARTY_MISMATCH: "PARTY_MISMATCH",
  ESCROW_MISMATCH: "ESCROW_MISMATCH",
  // AgentRewards (IF-F11)
  EPOCH_EXPIRED: "EPOCH_EXPIRED",
  NULLIFIER_SPENT: "NULLIFIER_SPENT",
  STALE_NONCE: "STALE_NONCE",
  STATE_REPLAYED: "STATE_REPLAYED",
  CONFLICTING_STATE: "CONFLICTING_STATE",
  OWED_DECREASED: "OWED_DECREASED",
  // OmerMinter (IF-F12)
  UNKNOWN_LOCK: "UNKNOWN_LOCK",
  DUPLICATE_LOCK: "DUPLICATE_LOCK",
  ALREADY_SETTLED: "ALREADY_SETTLED",
  UNAUTHORIZED: "UNAUTHORIZED",
  NOT_SERVED: "NOT_SERVED",
  STALE_ROOT: "STALE_ROOT",
  TIMEOUT_NOT_REACHED: "TIMEOUT_NOT_REACHED",
} as const;
export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

export class ReceiptRootError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = "ReceiptRootError";
    this.code = code;
  }
}

export function isReceiptRootError(error: unknown, code?: ErrorCode): error is ReceiptRootError {
  return error instanceof ReceiptRootError && (code === undefined || error.code === code);
}

export function fail(code: ErrorCode, message: string): never {
  throw new ReceiptRootError(code, message);
}
