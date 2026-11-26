import { type Hex, bytesToHex, concatBytes, utf8 } from "../bytes.js";
import { keccak256 } from "../hash/index.js";
import { bytes32Word, uintWord } from "./abi.js";
import { type Settlement, validateSettlement } from "./settlement.js";

/**
 * Domain tag for the IF-D8 hook jobId. Solidity: `keccak256("InferenceFi.IF-D8.jobId.v1")`,
 * which is keccak-256 of the UTF-8 bytes, not an ABI-encoded string.
 */
export const JOB_ID_TAG_STRING = "InferenceFi.IF-D8.jobId.v1";
export const JOB_ID_TAG: Hex = bytesToHex(keccak256(utf8(JOB_ID_TAG_STRING)));

/**
 * Hook jobId: a stable event key, not the leaf hash.
 *
 * `jobId = keccak256(abi.encode(TAG, genesis, channelId, settledBlock, eventIndex))`
 * where `TAG = keccak256("InferenceFi.IF-D8.jobId.v1")` and the four fields use the
 * flop-receipt-root v0.3.2 ABI widths: `bytes32`, `bytes32`, `uint64`, `uint32`,
 * each encoded as a 32-byte word.
 *
 * `leafOf(s)` remains the Merkle proof input. Two settlements that share this
 * event key have the same jobId even if other leaf fields differ.
 */
export function jobIdOf(s: Settlement): Hex {
  validateSettlement(s);
  return bytesToHex(
    keccak256(
      concatBytes(
        bytes32Word(JOB_ID_TAG),
        bytes32Word(s.genesis, "genesis"),
        bytes32Word(s.channelId, "channelId"),
        uintWord(s.settledBlock, 64, "settledBlock"),
        uintWord(s.eventIndex, 32, "eventIndex"),
      ),
    ),
  );
}
