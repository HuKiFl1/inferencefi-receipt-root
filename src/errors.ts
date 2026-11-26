/**
 * Error codes. Codes that FlopReceiptRoot v0.3.2 can raise use its custom
 * error names; consumer codes match the custom errors in `foundry/src`, so a
 * vector's `expect` is the same string on both sides.
 */
export const ErrorCode = {
  // Local input validation (never reaches a contract)
  INVALID_INPUT: "INVALID_INPUT",
  // FlopReceiptRoot.submit / freeze (upstream names)
  IsFrozen: "IsFrozen",
  WrongGenesis: "WrongGenesis",
  WrongEpoch: "WrongEpoch",
  WrongFromBlock: "WrongFromBlock",
  BadRange: "BadRange",
  EmptyRoot: "EmptyRoot",
  /** Stands for every quorum failure the contract can raise (BelowThreshold, NotAttester, BadSignature, ...). */
  BelowThreshold: "BelowThreshold",
  NotEquivocation: "NotEquivocation",
  // Shared consumer checks
  WrongChain: "WrongChain",
  ProofRejected: "ProofRejected",
  // ReceiptJobHook
  BadHookData: "BadHookData",
  NotPoolManager: "NotPoolManager",
  UnknownPool: "UnknownPool",
  ModelNotInPool: "ModelNotInPool",
  JobBoundElsewhere: "JobBoundElsewhere",
  // AgentRewardsConsumer (IF-F11)
  NotBoundToPool: "NotBoundToPool",
  EpochExpired: "EpochExpired",
  LeafSpent: "LeafSpent",
  StaleLeaf: "StaleLeaf",
  AmountDecreased: "AmountDecreased",
  AgentChanged: "AgentChanged",
  // OmerMinterConsumer (IF-F12)
  BadLock: "BadLock",
  DuplicateLock: "DuplicateLock",
  UnknownLock: "UnknownLock",
  AlreadySettled: "AlreadySettled",
  Unauthorized: "Unauthorized",
  ChannelMismatch: "ChannelMismatch",
  PartyMismatch: "PartyMismatch",
  ModelMismatch: "ModelMismatch",
  SettlementTooOld: "SettlementTooOld",
  NotServed: "NotServed",
  RootsFrozen: "RootsFrozen",
  StaleRoot: "StaleRoot",
  UnservedProofUnavailable: "UnservedProofUnavailable",
  AttestationMismatch: "AttestationMismatch",
  TimeoutNotReached: "TimeoutNotReached",
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
