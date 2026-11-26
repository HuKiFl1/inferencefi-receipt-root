import { blake2b256 } from "./blake2b.js";
import { keccak256 } from "./keccak.js";

export { blake2b, blake2b256 } from "./blake2b.js";
export { keccak256 } from "./keccak.js";

/** The two commitments built over the same bytes: FLOP-native and EVM-native. */
export type HashId = "blake2b256" | "keccak256";

export interface HashFn {
  readonly id: HashId;
  (message: Uint8Array): Uint8Array;
}

function named(id: HashId, fn: (m: Uint8Array) => Uint8Array): HashFn {
  return Object.assign((m: Uint8Array) => fn(m), { id }) as HashFn;
}

export const KECCAK256: HashFn = named("keccak256", keccak256);
export const BLAKE2B256: HashFn = named("blake2b256", blake2b256);
export const HASHES: readonly HashFn[] = [BLAKE2B256, KECCAK256];
