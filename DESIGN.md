# IF-D8: the hook jobId as a Flop receipt root

**Status:** proposal v0.3 for Inference Finance decision IF-D8, pending the
spec owner and palmer, and pending the remaining answers to
[flop-receipt-root issue #4](https://github.com/xbtMelchizedek/flop-receipt-root/issues/4)
(Q4, the hook jobId, is answered in commit 19042c3 and the comment on that
issue). Nothing here is adopted, deployed or audited.

**This version adopts flop-receipt-root 19042c3** (tag `v0.3.2` plus the
normative jobId; leaf and root format unchanged, commit
`19042c3e05d6cc259ae2c1c67294f558143ac990`). Inference Finance consumers should use one receipt-root format,
and that format is xbtMelchizedek's. This repo no longer defines a leaf, a tree
or a root message of its own. It is the **consumer layer** on top of it: the
hook's jobId mapping, AgentRewards (IF-F11) and OmerMinter (IF-F12), written as
a TypeScript reference, Solidity reference contracts, and shared vectors.

## 0. Recommendation

- **hookData** = `abi.encode(uint64 epoch, Settlement s, bytes32[] proof)`.
- **jobId** is the **event key**, not the leaf hash:
  `keccak256(abi.encode(TAG, genesis, channelId, settledBlock, eventIndex))`,
  where `TAG = keccak256("FlopReceiptRoot.jobId.v1")` (keccak of the UTF-8
  bytes of that string; the upstream tag pinned in 19042c3, value
  `0x748fa472…7d31bd14`) and the four fields use the flop-receipt-root
  ABI widths (`bytes32`, `bytes32`, `uint64`, `uint32`), each a 32-byte word.
  The event key is the stable identity of a Settled event; `leafOf(s)` stays
  the Merkle proof input.
- A receipt counts only if `FlopReceiptRoot.verify(epoch, s, proof)` is true.
- Everything the leaf does not name lives in the consumer: the pool binding,
  the EVM chain binding, the dedupe rule, and the lock's EVM addresses.

The v0.1 recommendation was a domain-separated commitment to a per-epoch root
as the jobId. That needed our own leaf, tree and registry. It is withdrawn in
favour of the upstream format. One root contract and one leaf hash for every
consumer is worth more than the extra bindings v0.1 put into the jobId, and
those bindings are restored in the consumers (§4).

## 1. Context and terms

- **Inference Finance** is a Solidity AMM prototype on HyperEVM testnet (chain
  998), owned by another team. It is unaudited and uses TEST mocks only. Its
  credit unit is **OMER**. Its contracts are not public, so this note follows
  only the spec items IF-F11 (AgentRewards credits each receipt once;
  receipts are epoch-bound), IF-F12 (OmerMinter redeem settles on a served
  receipt, or the escrow is reclaimed if unserved) and IF-D8 (this decision).
- **FLOP Network** is a Substrate L1 with no EVM. Compute channels between an
  agent and a miner emit `computeChannel.Settled` (and `force_settled`) when
  they close. Finality is AlephBFT: an ordered block is irreversible.
- **flop-receipt-root** (xbtMelchizedek, MIT) commits those Settled events to
  the EVM. At each epoch, a k-of-n attester set signs one Merkle root over the
  epoch's events, and `FlopReceiptRoot` checks single events against it.
- **Flop reclaim** ([github.com/HuKiFl1/Flop](https://github.com/HuKiFl1/Flop))
  supplies the terms this note reuses unchanged: the last finalized state at
  height `h`, `N` staleness blocks, the `W`-block challenge window, the
  earliest reclaim height `h + N + W`, and the payout waterfall (provider
  owed first, then lender principal, then the payer remainder; overrun is
  recorded and never minted).
- **TCLK race rule** (Technocore Lock Protocol): a timeout makes a refund
  eligible but does not expire a claim. A served claim still wins until the
  refund is included.

All amounts and heights are integers (`bigint` in TypeScript, `uint64` or
`uint128` in Solidity). There are no floats.

## 2. What moved

| Concern | v0.1 (this repo, withdrawn) | v0.2 / v0.3 (adopts flop-receipt-root; v0.3 uses the upstream jobId TAG) |
|---|---|---|
| Leaf | per-channel **state** leaf (nonce, cumulative owed, state root, height), with pool and chain inside | one leaf per **Settled / force_settled event**: `(genesis, channelId, settledBlock, settledBlockHash, eventIndex, agent, miner, modelHash, aggregateGn, minerPaid, burned, escrow)` |
| Leaf hash | `keccak(0x00 ‖ fields)`, plus a parallel BLAKE2b tree | `keccak(keccak(abi.encode(LEAF_TYPEHASH, …)))` |
| Tree | RFC 6962 with prefixes, `leafCount` and index bound | OpenZeppelin sorted-pair tree; a proof is `bytes32[]` of siblings |
| Root message | our registry commitment over root, chain, hook, pool, epoch, height, count | EIP-712 `ReceiptRoot(genesis, epoch, fromBlock, toBlock, toBlockHash, count, root)` signed by a majority k-of-n |
| Epochs | fixed `epochLength` | contiguous FLOP block ranges; `epoch = last + 1`, `fromBlock = last.toBlock + 1` |
| Root store | our `ReceiptRootRegistry` model | `FlopReceiptRoot` (vendored); equivocation freezes it for good |
| jobId | commitment to the root and its domain | event key `keccak256(abi.encode(TAG, genesis, channelId, settledBlock, eventIndex))`; the leaf hash is the proof input |
| Pool and chain binding | inside the leaf and the jobId | in the consumers (§4) |
| Dedupe (IF-F11) | one nullifier per (channel, epoch) over state leaves | spent set per leaf hash, plus a switch for how leaves of one (channel, epoch) add up (§4.2) |
| Reclaim (IF-F12) | proven by the channel's state leaf in the latest root | **cannot be proven** from a Settled-only tree; behind an attestor interface with a stub (§4.3, §6) |
| Hashes in TS | keccak-256 and BLAKE2b | keccak-256 only; BLAKE2b and the dual root are removed |
| Watchers | `auditSnapshot`, `auditTransition` | removed; they audited our own format |

Removed from `src/`: the leaf, tree, commitment, registry, receipt check,
rewards and minter models of v0.1, and BLAKE2b. The payout waterfall and the
`h + N + W` timeout moved to `src/consumer/waterfall.ts` unchanged.

## 3. The upstream format, as ported

`src/format/` is a clean port of the rules in `FlopReceiptRoot.sol`. It is
byte-identical on the upstream fixture `test/fixtures/epoch.json` (99 devnet
settlements, one epoch): `tests/upstream.test.ts` recomputes every leaf, the
tree, every proof, the root, the EIP-712 digest, and the contract's
`verify` result for each item.

- **Leaf.** `encodeSettlement` is the 13-word `abi.encode` (416 bytes);
  `leafOf` hashes it twice, so a 64-byte inner node can never be presented as
  a leaf.
- **Tree.** Leaves are sorted ascending, duplicates are refused, an odd node
  is promoted, and a pair hashes as `keccak(min ‖ max)`. An empty epoch has
  `count = 0` and the zero root.
- **Root message.** `digest712(msg, chainId, contract)` is the EIP-712 digest
  over the domain `("FlopReceiptRoot", "1", chainId, contract)`.
- **Contract model.** `FlopReceiptRootModel` follows `submit`'s check order
  (`IsFrozen`, `WrongGenesis`, `WrongEpoch`, `WrongFromBlock`, `BadRange`,
  `EmptyRoot`, then quorum), `freeze` (`NotEquivocation` unless two different
  messages for one epoch), and the `verify` view (false when frozen, when the
  proof has more than 64 siblings, for an unknown or empty epoch, for another
  genesis, or when `settledBlock` lies outside the epoch's range).
- **Signatures.** The TypeScript model takes the quorum as a boolean. It has
  no secp256k1 code (§6, G8). The Solidity tests sign with `vm.sign` against
  the real contract, using attester keys derived at runtime from a public
  label.

The vendored copy (`vendor/flop-receipt-root/`) holds the two contracts, the
upstream Foundry tests, the fixture and the licence, with forge-std as a
submodule. `vendor/flop-receipt-root/VENDORED.md` lists the sha256 of every
vendored file, and a test checks them. Upstream's JavaScript builder was read
but not vendored or executed; the fixture is used as data.

## 4. The consumer layer

Each consumer exists twice, with the same rules and error names:
`src/consumer/*.ts` (reference models) and `foundry/src/*.sol` (reference
contracts). Each checks `block.chainid` against the EVM chain it was built
for (`WrongChain`).

### 4.1 Hook: jobId is the event key (IF-D8)

`ReceiptJobHook.tag(poolId, hookData)` is the body a v4 `beforeSwap` would
run. Checks in order:

1. `WrongChain`; `NotPoolManager` (only the PoolManager may call);
   `UnknownPool`.
2. `BadHookData` unless `hookData` is the **canonical** ABI encoding. Solidity's
   `abi.decode` alone accepts trailing bytes and other offsets; the contract
   re-encodes and compares. The jobId does not depend on the encoding, but
   one receipt should travel as one byte string.
3. `ModelNotInPool`: each pool lists the Flop model hashes it serves.
4. `ProofRejected` unless `FlopReceiptRoot.verify(epoch, s, proof)`.
5. `JobBoundElsewhere`: the first pool to tag a jobId owns it on this chain.
   Tagging it again in the same pool is fine.

The jobId is derived only from the event key (`genesis`, `channelId`,
`settledBlock`, `eventIndex`), domain-separated by `TAG`. Two leaves that
name the same event, even if the other fields (`minerPaid`, `agent`,
`settledBlockHash`, …) differ, share one jobId and therefore one pool
binding. A different `eventIndex` is a different job. `leafOf(s)` is still
what `verify` and the Merkle proof use. The `jobIdCases` in
`vectors/if-d8-v2.json` pin this split and are offered to upstream as
normative vectors for the hook jobId.

The leaf names no pool, so a receipt cannot say where it may be used. The
hook's first-tag binding is what keeps one event from being counted by
two pools.

### 4.2 AgentRewards (IF-F11)

`claim(epoch, s, proof)` credits `s.agent`. Checks in order: `WrongChain`,
`ProofRejected`, `NotBoundToPool` (the hook must have tagged this event's jobId to this
consumer's pool), `EpochExpired` (epoch `e` closes once
`lastEpoch > e + claimWindowEpochs`), and `LeafSpent` (each leaf hash is
spent once).

How several leaves of one channel in one epoch add up depends on issue #4
question 3 (and question 2), which is open, so the dedupe unit is a
constructor switch:

- **`per-leaf-sum`**: every leaf adds its amount. This is right if amounts are
  per event.
- **`latest-per-channel`**: only the latest leaf of a (channel, epoch) counts,
  ordered by `(settledBlock, eventIndex)`. A later leaf tops the credit up to
  its own amount. An earlier leaf after a later one fails with `StaleLeaf`, a
  smaller amount with `AmountDecreased`, and a different agent with
  `AgentChanged`. This is right if amounts are cumulative.

The credited field is also a switch: `minerPaid` (the default in the vectors)
or `aggregateGn`. On the same scenario the two modes credit 2120 and 1320.
Both totals are in the vectors.

### 4.3 OmerMinter (IF-F12)

The OMER locked in the EVM minter is the channel's escrow, `E = L + D`
(lender principal plus payer deposit). One lock backs one channel
(`DuplicateLock`). A lock names the channel, the Flop `agent` and `miner`
keys, the model, the payer, provider and lender EVM addresses, the price
`owed = floor(aggregateGn · num / den)`, and `minFlopBlock`.

| | Redeem (served) | Reclaim (unserved) |
|---|---|---|
| TCLK analogue | claim | refund after the deadline |
| Caller | the provider only | the channel parties, or anyone (policy switch) |
| Proof | a Settled leaf of this channel in **any** accepted epoch | an `IUnservedAttestor` statement for the **latest** epoch (`StaleRoot` otherwise) |
| Must show | same channel, agent, miner and model as the lock; `settledBlock ≥ minFlopBlock`; `aggregateGn > 0` | the latest root's `toBlock ≥ lastFinalizedHeight + N + W` (`TimeoutNotReached`) |
| When | any time while the lock is open, including after the timeout | from the timeout on, while the roots are not frozen (`RootsFrozen`) |
| Payout | waterfall over `owed` | waterfall over the attested `owed` |

**Race rule.** Whichever terminal call is included first settles the lock,
and the other gets `AlreadySettled`. After the timeout, a served redeem still
succeeds until a reclaim is included.

**Why reclaim is behind an interface.** A Settled-only tree proves that an
event happened. It cannot prove that one did not: no leaf shows that a
channel was never settled, and nothing gives the height of its last finalized
state. So reclaim calls

```solidity
interface IUnservedAttestor {
    function verifyUnserved(bytes32 genesis, bytes32 channelId, uint64 epoch, bytes calldata attestation)
        external view returns (uint64 lastFinalizedHeight, uint128 owed);
}
```

`UnservedAttestorStub` is the only implementation shipped. It **always
reverts** with `UnservedProofUnavailable`, so reclaim fails closed. The vectors
exercise reclaim with a test-only attestor that returns whatever the test
sets. That attestor tests the consumer's rules (timeout, latest root, race,
waterfall). It is not a proposal for how unserved channels should be proven.

## 5. Trust

| Property | Enforced on the EVM | Trusted |
|---|---|---|
| A settlement is in an attested epoch's root, on this genesis, inside the epoch's blocks | yes (`verify`) | |
| One root per epoch, contiguous epochs and blocks, majority quorum | yes (`submit`) | |
| Two different roots for one epoch freeze everything | yes (`freeze`, by anyone holding both) | |
| Each leaf is a real, finalized Settled event | no | attesters |
| The epoch contains every Settled event of its range (completeness) | no | attesters |
| `count` matches the tree | no | attesters |
| A channel was not served (reclaim) | no; nothing exists yet | attestor (stub) |
| Lock addresses belong to the Flop keys in the leaf | no | lock opener (§6, G4) |
| Liveness: a root every epoch | no | attesters |

## 6. Honest gaps

- **G1. Reclaim of unserved escrow cannot be proven.** See §4.3. Until
  upstream or someone else provides an unserved or completeness statement,
  reclaim is a stub and escrow for an unserved channel stays locked. Options
  are listed in §7, question 1.
- **G2. The sorted-pair tree binds no index and no leaf count.** A raw hash
  check accepts an inner node with the rest of the path (vector
  `inner-node-as-raw-leaf`). `FlopReceiptRoot.verify` is safe because it takes
  the settlement struct and double-hashes it, so no consumer may verify a raw
  leaf hash. `verifyRawProof` exists in the TS reference for vectors only.
  `count` in the root message is signed but cannot be checked against a
  proof.
- **G3. Attesters are trusted** for correctness, completeness and liveness
  (§5). There is no FLOP light client on the EVM. Equivocation freezes the
  contract, which is fail-closed. After a freeze, every open lock is stranded:
  `verify` returns false, so no redeem; `RootsFrozen` blocks reclaim. A stalled
  attester set also blocks reclaim, because it needs the latest root.
- **G4. The leaf carries Flop keys, not EVM addresses.** `agent` and `miner`
  are `bytes32` Flop keys. The lock maps them to payer and provider addresses,
  and nothing checks that mapping. If the payer opens the lock, it chooses
  the provider address that receives a redeem. A real minter needs the miner
  to bind its address, for example with a signature by its Flop key.
- **G5. The leaf carries no intent id, pool or EVM chain.** The hook binds
  pool and chain at first tag (§4.1). A receipt tagged first on a pool the
  miner did not intend is still that pool's.
- **G6. Per-event vs cumulative amounts are unknown** (issue #4, question 2).
  `latest-per-channel` assumes monotone amounts and orders by
  `(settledBlock, eventIndex)` because the leaf has no nonce.
- **G7. TypeScript has no signature code.** Quorum is a boolean in the model;
  ECDSA, low-s and ascending-signer rules are tested only on the Solidity side
  against the real contract. This avoids a secp256k1 dependency.
- **G8. Upstream's JavaScript builder was not run.** The fixture was used as
  data. Our TS builder (`buildEpoch`) reproduces the fixture's root, which is
  the cross-check.
- **G9. Not audited, not deployed, not wired into v4.** `tag` is the hook body
  without PoolManager plumbing. Upstream marks its contract "local/anvil use
  only".
- **G10. Migration.** A redeployed AgentRewards starts with an empty spent set,
  so leaves could be claimed again unless the spent set or the claim window
  moves with it.

## 7. Open questions

Questions 1–4 are those asked in
[issue #4](https://github.com/xbtMelchizedek/flop-receipt-root/issues/4).
Q1–Q3 are still open. Q4 is answered in flop-receipt-root 19042c3 (see
below). The rest are for the Inference Finance spec owner.

1. **Unserved channels (issue #4, Q1).** Reclaim needs one of: (a) leaves for
   open or unserved channels at each checkpoint, such as
   `(channelId, lastFinalizedHeight, owed, status)`; (b) a signed completeness
   statement, for example a second tree sorted by `channelId` that allows
   non-membership proofs; or (c) keeping reclaim outside the EVM. Until then,
   `UnservedAttestorStub` stays in place.
2. **Amount semantics (issue #4, Q2).** Are `minerPaid` and `aggregateGn` per
   event or cumulative per channel? Could the leaf gain a nonce or another
   monotone field? The answer decides between `per-leaf-sum` and
   `latest-per-channel`.
3. **Dedupe unit for IF-F11 (issue #4, Q3).** Nullify and sum every leaf, or
   count only the latest leaf per (channel, epoch)? Both are implemented
   behind a switch.
4. **Hook jobId (issue #4, Q4).** Answered in flop-receipt-root 19042c3 and
   the comment on issue #4. This proposal uses that mapping: `jobId` is
   `keccak256(abi.encode(TAG, genesis, channelId, settledBlock, eventIndex))`
   with `TAG = keccak256("FlopReceiptRoot.jobId.v1")`, and `leafOf(s)` remains
   the proof input. `hookData` is still `(epoch, settlement, proof)`. The
   `jobIdCases` in `vectors/if-d8-v2.json` check same-key / different-index
   behaviour; `tests/upstream.test.ts` and the vendored Foundry suite also
   replay the six published upstream vectors, including the three devnet
   fixture settlements.
5. **Metric.** Should AgentRewards credit `minerPaid` (FLOP paid) or
   `aggregateGn` (compute)? Who is credited: the agent (this proposal), the
   miner, or both?
6. **Key-to-address mapping** (G4). How do Flop `agent` and `miner` keys map
   to EVM payer and provider addresses?
7. **Epoch clock and claim window.** Epochs are now attester-chosen FLOP
   block ranges of varying length. Is a window counted in epochs (this
   proposal) acceptable, or should it be in FLOP blocks?
8. **Unserved attestor candidates.** If upstream will not add unserved
   leaves, who would sign an unserved statement, under which trust model,
   and should it reuse the receipt-root attester set?
9. **Frozen roots** (G3). Is a stranded lock after a freeze acceptable, or
   should a lock have an absolute fallback deadline? A deadline weakens
   provider safety.
10. **Partial redemption.** Locks settle once. Should a provider be able to
    redeem against several Settled events of one channel?

## 8. Threat model

| # | Threat | Mitigation | Enforced by | Vectors (step notes or case names) |
|---|---|---|---|---|
| T1 | Wrong genesis | root and leaf must name the contract's genesis | `submit`, `verify` | "root for another Flop network", "leaf claims another genesis", verify case "leaf of another genesis inside a signed root" |
| T2 | Replay across epochs | `verify` uses the given epoch's root and block range | `verify` | "epoch-1 leaf replayed as epoch 2", "…replayed into epoch 2 at the hook", "epoch not accepted yet" |
| T3 | Replay across chains | `block.chainid` check in every consumer; EIP-712 domain for roots | consumers, `submit` | "hook bound to chain 998, called on 999", "consumer bound to chain 998…" |
| T4 | Replay across pools | first-tag binding; rewards require the hook's pool | hook, AgentRewards | "pool B serves model X too, but the job is pool A's", "pool B's job in pool A's rewards" |
| T5 | Forged proof | sorted-pair recomputation; any edited field changes the leaf | `verify` | "forged proof", "inflated minerPaid under the original proof", proof cases `forged-sibling`, `truncated`, `extended`, `reordered`, `other-tree-root` |
| T6 | 64-byte node as leaf | double-hashed leaf; consumers never verify raw hashes | `leafOf`, `verify` | proof cases `inner-node-as-raw-leaf` (raw check passes, documented) and `inner-node-preimage-double-hashed` (fails) |
| T7 | Double-claim | spent set per leaf hash; latest mode orders leaves | AgentRewards | "sum: the same leaf again (double-claim)", "latest: the same leaf again (double-claim)", "latest: the earlier C1@1100 is stale" |
| T8 | Non-contiguous epochs | `epoch = last + 1`, `fromBlock = next` | `submit` | "non-contiguous epoch: 3 before 2", "epoch 2 leaving a block gap", "epoch 1 replayed" |
| T9 | Stale root for reclaim | reclaim only against the latest epoch | OmerMinter | "epoch 2 is not the latest root", "epoch 3 is no longer the latest root" |
| T10 | Equivocation | two signed roots for one epoch freeze the contract | `freeze` | "two quorum-signed roots for epoch 4", then every "frozen roots verify nothing" step |
| T11 | Redeem/reclaim race | first terminal call wins; redeem allowed past the timeout | OmerMinter | "past the timeout a served redeem still wins…", "K2 refund included first wins", "4999 is one block short…", "unserved exactly at 4879 + 100 + 20 = 4999…" |
| T12 | Oversized proof | more than 64 siblings is refused | `verify` | "proof longer than MAX_PROOF", verify cases for 64 and 65 siblings |
| T13 | Malleable hookData | canonical encoding only | hook | "valid receipt in non-canonical hookData (trailing word)", `hookDataCases` |
| T14 | Wrong settlement for a lock | channel, parties, model and freshness must match | OmerMinter | "settlement of another channel", "…another miner than the lock", "lock expects model Y", "settled before the lock's minFlopBlock" |
| T15 | Job identity vs proof identity | event-key jobId is stable across leaf layout; a different eventIndex is a different job; leaf hash stays the proof input and spent-set key | hook, `jobIdOf` | jobId cases "same event key, different leaf layout", "different eventIndex" |

## 9. Where things are

| Concern | TypeScript | Solidity | Vectors (`vectors/if-d8-v2.json`) |
|---|---|---|---|
| Upstream format | `src/format/` | `vendor/flop-receipt-root/contracts/src/FlopReceiptRoot.sol` | `format`, `leaves`, `trees`, `proofCases`, `verifyCases` |
| Hook, hookData | `src/consumer/hook.ts`, `src/format/hookData.ts` | `foundry/src/ReceiptJobHook.sol` | `hookDataCases`, scenario `tag` steps |
| AgentRewards | `src/consumer/rewards.ts` | `foundry/src/AgentRewardsConsumer.sol` | scenario `claim` steps, `totals` |
| OmerMinter | `src/consumer/minter.ts`, `src/consumer/waterfall.ts` | `foundry/src/OmerMinterConsumer.sol`, `IUnservedAttestor.sol`, `UnservedAttestorStub.sol` | scenario `open`, `redeem`, `reclaim` steps |
| Upstream cross-check | `tests/upstream.test.ts` | `vendor/flop-receipt-root/contracts/test/` | upstream `test/fixtures/epoch.json` |

Every expected outcome in `scripts/vectors.ts` is written by hand, and the
generator throws if a model disagrees. Each step also carries the Solidity
revert selector, and `foundry/test/ConsumerVectors.t.sol` replays every step
against the real `FlopReceiptRoot` and the reference contracts.

## 10. References

Only public specifications are cited. No third-party code is copied except
the vendored, MIT-licensed flop-receipt-root files, which are attributed in
`vendor/flop-receipt-root/VENDORED.md`.

- flop-receipt-root 19042c3 (v0.3.2 + normative jobId) by xbtMelchizedek, MIT:
  [github.com/xbtMelchizedek/flop-receipt-root](https://github.com/xbtMelchizedek/flop-receipt-root),
  and [issue #4](https://github.com/xbtMelchizedek/flop-receipt-root/issues/4).
- EIP-712, *Typed structured data hashing and signing*.
- Solidity ABI specification (`abi.encode` of static structs and dynamic arrays).
- The sorted-pair Merkle proof rule as published in the OpenZeppelin
  `MerkleProof` documentation (described here, not copied).
- NIST FIPS 202 (Keccak-f[1600]; the EVM uses the original Keccak padding).
- CVE-2012-2459: Merkle tree duplicate-leaf ambiguity.
- Uniswap v4 core specification: `PoolId`, hooks and `hookData`.
- *Aleph: Efficient Atomic Broadcast in Asynchronous Networks with Byzantine
  Nodes* (ACM AFT 2019).
- Flop reclaim: [github.com/HuKiFl1/Flop](https://github.com/HuKiFl1/Flop).
