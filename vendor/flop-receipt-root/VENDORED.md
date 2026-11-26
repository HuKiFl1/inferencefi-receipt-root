# Vendored: flop-receipt-root v0.3.2

These files are an unmodified copy of part of
[github.com/xbtMelchizedek/flop-receipt-root](https://github.com/xbtMelchizedek/flop-receipt-root)
at tag `v0.3.2` (commit `aa2fa591da38e6981a37693fb101c4f14835826d`). They are
MIT-licensed, Copyright (c) 2026 xbtMelchizedek; see [`LICENSE`](LICENSE),
which travels with them.

They are here so that:

- our consumer contracts in `foundry/` compile against the real
  `FlopReceiptRoot.sol`, not a re-typed copy;
- `tests/upstream.test.ts` cross-checks our TypeScript port of the leaf
  encoding, sorted-pair tree and EIP-712 digest against his fixture
  (`test/fixtures/epoch.json`: 99 finalized devnet settlements, 2-of-3 test
  attester signatures);
- his own Foundry tests still run here: `cd vendor/flop-receipt-root && forge test`.

Only his Solidity, Foundry config, one fixture and the licence are copied. His
JavaScript, CLI, web page and scripts are not. `lib/forge-std` is a git
submodule pinned to the commit he pins (`77041d2`, forge-std v1.9.7, MIT or
Apache-2.0).

`tests/upstream.test.ts` fails if any file below changes.

| File | sha256 |
|---|---|
| `LICENSE` | `31aa4b29f05b8a89be2c2e20e95ee7b116477a166afdf30a57f64a6ba2aea712` |
| `foundry.toml` | `739c28d147db767f5090a705e727136726c74c3e690b01708d564d0ff52cb65d` |
| `contracts/src/FlopReceiptRoot.sol` | `297e4bbd03df3bd90fb707e77a6d9ae41bc97a92131dee48d40a985b5233ac60` |
| `contracts/src/IntentEscrow.sol` | `05a8ff996f0cb9803604f74969f431471fe44f74478f5fd4de4f26969387b33b` |
| `contracts/test/FlopReceiptRoot.t.sol` | `97b7d37cd098601c1589e70d0c3f9bb9a1e2c5a9c287654a8bd74e474253476e` |
| `contracts/test/IntentEscrow.t.sol` | `28f0373060ba6feb77324618868a54930c3a27383e34a19ba133e1fba0d172bc` |
| `contracts/test/mocks/MockUSDC.sol` | `48a18e66f99c940d21191e9e7ef963833d75999ece37556518691032e3c45759` |
| `test/fixtures/epoch.json` | `09cd2c3e963ed631706771ad90e8ec73a7e51e689da24c8a0d7dfdf11de76da6` |
