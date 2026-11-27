# Vendored: flop-receipt-root 19042c3

These files are an unmodified copy of part of
[github.com/xbtMelchizedek/flop-receipt-root](https://github.com/xbtMelchizedek/flop-receipt-root)
at commit `19042c3e05d6cc259ae2c1c67294f558143ac990` (tag `v0.3.2` plus the
normative jobId added on top; the leaf and root format are unchanged). They
are MIT-licensed, Copyright (c) 2026 xbtMelchizedek; see [`LICENSE`](LICENSE),
which travels with them.

They are here so that:

- our consumer contracts in `foundry/` compile against the real
  `FlopReceiptRoot.sol`, not a re-typed copy, and can call its `jobIdOf`;
- `tests/upstream.test.ts` cross-checks our TypeScript port of the leaf
  encoding, sorted-pair tree, EIP-712 digest and jobId against his fixtures
  (`test/fixtures/epoch.json`: 99 finalized devnet settlements, 2-of-3 test
  attester signatures; `test/fixtures/jobid_vectors.json`: the six published
  jobId cases);
- his own Foundry tests still run here: `cd vendor/flop-receipt-root && forge test`.

Only his Solidity, Foundry config, fixtures and the licence are copied. His
JavaScript, CLI, web page and scripts are not. `lib/forge-std` is a git
submodule pinned to the commit he pins (`77041d2`, forge-std v1.9.7, MIT or
Apache-2.0).

`tests/upstream.test.ts` fails if any file below changes.

| File | sha256 |
|---|---|
| `LICENSE` | `31aa4b29f05b8a89be2c2e20e95ee7b116477a166afdf30a57f64a6ba2aea712` |
| `foundry.toml` | `739c28d147db767f5090a705e727136726c74c3e690b01708d564d0ff52cb65d` |
| `contracts/src/FlopReceiptRoot.sol` | `8ac5dbed3de4522424195efed39470ca74dba807ea8822623dd2fc6618494240` |
| `contracts/src/IntentEscrow.sol` | `05a8ff996f0cb9803604f74969f431471fe44f74478f5fd4de4f26969387b33b` |
| `contracts/test/FlopReceiptRoot.t.sol` | `1f5f98879ff1fc4bdb7fb901b21beb603315c987c4c016c482012cd796a95f75` |
| `contracts/test/IntentEscrow.t.sol` | `28f0373060ba6feb77324618868a54930c3a27383e34a19ba133e1fba0d172bc` |
| `contracts/test/mocks/MockUSDC.sol` | `48a18e66f99c940d21191e9e7ef963833d75999ece37556518691032e3c45759` |
| `test/fixtures/epoch.json` | `09cd2c3e963ed631706771ad90e8ec73a7e51e689da24c8a0d7dfdf11de76da6` |
| `test/fixtures/jobid_vectors.json` | `f4e40f8b874edc3462cf11885933a6460528330ae76e9008b3a20d10dfcc96f8` |
