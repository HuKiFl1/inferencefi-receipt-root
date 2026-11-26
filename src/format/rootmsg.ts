import { type Hex, U64_MAX, bytesToHex, concatBytes, isHex, utf8 } from "../bytes.js";
import { ErrorCode, fail } from "../errors.js";
import { keccak256 } from "../hash/index.js";
import { addressWord, bytes32Word, uintWord } from "./abi.js";

/** The message attesters sign for one epoch (FlopReceiptRoot.RootMsg). */
export interface RootMsg {
  readonly genesis: Hex;
  readonly epoch: bigint;
  readonly fromBlock: bigint;
  readonly toBlock: bigint;
  readonly toBlockHash: Hex;
  readonly count: bigint;
  readonly root: Hex;
}

export const ROOT_TYPE =
  "ReceiptRoot(bytes32 genesis,uint64 epoch,uint64 fromBlock,uint64 toBlock,bytes32 toBlockHash,uint32 count,bytes32 root)";
export const ROOT_TYPEHASH: Hex = bytesToHex(keccak256(utf8(ROOT_TYPE)));
export const DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
export const DOMAIN_NAME = "FlopReceiptRoot";
export const DOMAIN_VERSION = "1";

export function validateRootMsg(m: RootMsg): void {
  for (const k of ["genesis", "toBlockHash", "root"] as const) {
    if (!isHex(m[k], 32)) fail(ErrorCode.INVALID_INPUT, `${k} must be 32 bytes of lowercase 0x-hex`);
  }
  for (const k of ["epoch", "fromBlock", "toBlock"] as const) {
    if (typeof m[k] !== "bigint" || m[k] < 0n || m[k] > U64_MAX) fail(ErrorCode.INVALID_INPUT, `${k} must fit uint64`);
  }
  if (typeof m.count !== "bigint" || m.count < 0n || m.count >= 1n << 32n) fail(ErrorCode.INVALID_INPUT, "count must fit uint32");
}

export function rootStructHash(m: RootMsg): Hex {
  validateRootMsg(m);
  return bytesToHex(
    keccak256(
      concatBytes(
        bytes32Word(ROOT_TYPEHASH),
        bytes32Word(m.genesis),
        uintWord(m.epoch, 64),
        uintWord(m.fromBlock, 64),
        uintWord(m.toBlock, 64),
        bytes32Word(m.toBlockHash),
        uintWord(m.count, 32),
        bytes32Word(m.root),
      ),
    ),
  );
}

export function domainSeparator(chainId: bigint, verifyingContract: Hex): Hex {
  return bytesToHex(
    keccak256(
      concatBytes(
        keccak256(utf8(DOMAIN_TYPE)),
        keccak256(utf8(DOMAIN_NAME)),
        keccak256(utf8(DOMAIN_VERSION)),
        uintWord(chainId, 256, "chainId"),
        addressWord(verifyingContract, "verifyingContract"),
      ),
    ),
  );
}

/** The EIP-712 digest each attester signs: `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`. */
export function digest712(m: RootMsg, chainId: bigint, verifyingContract: Hex): Hex {
  return bytesToHex(
    keccak256(concatBytes(Uint8Array.of(0x19, 0x01), bytes32Word(domainSeparator(chainId, verifyingContract)), bytes32Word(rootStructHash(m)))),
  );
}
