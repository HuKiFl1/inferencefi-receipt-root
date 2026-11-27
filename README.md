# inferencefi-receipt-root

The **consumer layer** for Inference Finance on top of xbtMelchizedek's
[flop-receipt-root](https://github.com/xbtMelchizedek/flop-receipt-root)
**19042c3** (v0.3.2 plus the normative jobId; leaf and root format unchanged).
Inference Finance is a Solidity AMM prototype on HyperEVM testnet
(chain 998). It is unaudited and uses TEST mocks only. It integrates the
**FLOP Network** through Settled compute-channel receipts.

This repo is a **proposal for decision IF-D8**, pending the spec owner and
palmer. Nothing in it is adopted, deployed or audited.

**Short answer:** a swap's `hookData` is `(epoch, settlement, proof)` and its
`jobId` is the event key
`keccak256(abi.encode(TAG, genesis, channelId, settledBlock, eventIndex))`,
with `TAG = keccak256("FlopReceiptRoot.jobId.v1")` (the upstream tag pinned in 19042c3 / issue #4). The leaf hash stays the
proof input. There is one root format, and it is upstream's. The argument, the
consumer rules, the open
questions (tied to upstream
[issue #4](https://github.com/xbtMelchizedek/flop-receipt-root/issues/4)) and
the gaps are in [DESIGN.md](DESIGN.md).

## What is here

| Path | What it is |
|---|---|
| [`DESIGN.md`](DESIGN.md) | Design note v0.3: it adopts flop-receipt-root 19042c3 (v0.3.2 + normative jobId), lists what moved from v0.1, gives the consumer rules, trust, gaps, open questions and the threat model. |
| `src/format/` | TypeScript port of the upstream format: Settlement leaf, sorted-pair tree and proofs, EIP-712 root message, a model of `FlopReceiptRoot`, and the hookData codec. It is byte-identical to the upstream fixture. |
| `src/consumer/` | Reference models of the hook (jobId is the event key; the leaf hash is the proof input), AgentRewards (IF-F11, with a dedupe switch) and OmerMinter (IF-F12: redeem by Settled leaf, reclaim behind an unserved-attestor interface with a stub). |
| `foundry/src/` | The same consumers as Solidity reference contracts, built on the vendored `FlopReceiptRoot`. |
| `foundry/test/` | Replays the vectors against the real `FlopReceiptRoot` and the reference contracts, plus fuzz tests of the consumer rules. |
| `vectors/if-d8-v2.json` | Shared vectors in the upstream format: leaves, trees, adversarial proofs, `verify`, hookData and jobId cases, and a 109-step hook, rewards and minter scenario. Each step has its Solidity revert selector. jobId cases use the upstream TAG; `tests/upstream.test.ts` also replays the six published flop-receipt-root jobId vectors. |
| `vendor/flop-receipt-root/` | Vendored upstream 19042c3 (contracts, Foundry tests, epoch and jobId fixtures, licence; forge-std as a submodule). See [`VENDORED.md`](vendor/flop-receipt-root/VENDORED.md). |
| `tests/` | vitest: upstream cross-check, format and consumer property tests (fast-check), vector replay, and mutation tests. |

## Running it

Requirements: Node.js 20 or newer, and [Foundry](https://book.getfoundry.sh/)
for the Solidity tests (solc 0.8.28 is fetched on first run). Clone with
submodules, or run `git submodule update --init` to fetch forge-std.

```bash
npm ci                    # or: npm install
npm test                  # vitest
npm run typecheck
npm run build             # emits dist/
npm run vectors           # regenerates vectors/if-d8-v2.json (byte-identical)
npm run forge             # both Foundry suites:
npm run forge:consumers   #   cd foundry && forge test
npm run forge:upstream    #   cd vendor/flop-receipt-root && forge test
npm run check             # typecheck + vitest + both Foundry suites
```

Property tests run 100 cases each. Run more with `PROPERTY_RUNS=1000 npm test`.
`tests/vectors.test.ts` fails if the committed JSON differs from what the
generator produces.

`tests/mutation.test.ts` applies 33 single-point bugs to a copy of `src/`, for
example a single-hashed leaf, an unsorted pair hash, `verify` ignoring the
genesis or the block range, no spent set, reclaim on a stale root, a timeout
off by one, or owed rounded up. Each mutant must make the vector replay fail,
and the unmutated copy must pass.

## What this does not solve

- **Reclaim of unserved escrow cannot be proven** from a Settled-only root. It
  runs through `IUnservedAttestor`, and the only shipped implementation,
  `UnservedAttestorStub`, always reverts. The tests use a test-only attestor
  to exercise the consumer's timeout and race rules.
- **Attesters are trusted** for correctness, completeness and liveness. A
  freeze strands open locks.
- **Flop keys are not EVM addresses.** The mapping from the leaf's
  `agent` and `miner` to payout addresses is open.

The full list is in DESIGN.md §6.

## Attribution and clean room

`vendor/flop-receipt-root/` is xbtMelchizedek's work, MIT licensed
(Copyright (c) 2026 xbtMelchizedek), vendored unchanged at commit `19042c3`.
Everything else is original. The TypeScript port was written from the
contract's rules and checked against the upstream fixture. keccak-256 is
implemented from NIST FIPS 202, and `@noble/hashes` (MIT) is a dev-only
oracle in the tests. There is no secp256k1 code in TypeScript; signatures are
tested in Foundry only.

## Licence

MIT. Copyright (c) 2026 HuKiFl1. See [LICENSE](LICENSE). The vendored
directory keeps its own licence.
