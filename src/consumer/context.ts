import { type Hex, isHex } from "../bytes.js";
import { ErrorCode, fail } from "../errors.js";

/** The EVM call context a consumer sees: `block.chainid` and `msg.sender`. */
export interface CallContext {
  readonly chainId: bigint;
  readonly caller: Hex;
}

export function requireChain(ctx: CallContext, evmChainId: bigint): void {
  if (ctx.chainId !== evmChainId) fail(ErrorCode.WrongChain, `chain ${ctx.chainId}, consumer bound to ${evmChainId}`);
}

export function requireAddress(a: Hex, field: string): void {
  if (!isHex(a, 20) || a === `0x${"00".repeat(20)}`) fail(ErrorCode.INVALID_INPUT, `${field} must be a non-zero address`);
}
