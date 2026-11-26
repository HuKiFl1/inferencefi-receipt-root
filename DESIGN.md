# IF-D8: the hook jobId as a Flop receipt root

**Status:** proposal v0.1 for Inference Finance decision IF-D8, pending the spec
owner and palmer. Nothing here is adopted. The reference code is in `src/`, the
vectors are in `vectors/receipt-root-v1.json`, and every rule below is covered
by `tests/` or `foundry/test/ReceiptRootVectors.sol`.

## 0. Recommendation

**Yes, the hook's `jobId` should commit to a Flop receipt root, but it should
not be the raw root.** It should be a domain-separated keccak-256 commitment
over the root, the place it may be used (EVM chain, hook, pool, FLOP network),
the epoch, the FLOP checkpoint height, the leaf count, and a parallel
blake2b-256 root over the same leaves:

```
jobId = keccak256(0x02 ‖ uint8 1 ‖ flopGenesis ‖ uint64 evmChainId ‖ address hook ‖ poolId
                  ‖ uint64 epoch ‖ uint64 checkpointHeight ‖ uint64 leafCount ‖ keccakRoot ‖ blakeRoot)
```

A raw root is the same value on every chain, pool and epoch that happens to
see the same leaves. It says nothing about how many leaves it has, which the
verifier needs (§5.4). Binding those facts into the jobId makes replay across
chains, pools and epochs fail by construction, and it gives one 32-byte key
that the hook, AgentRewards (IF-F11) and OmerMinter (IF-F12) can all look up in
a single root registry.

| Option | jobId | Verdict |
|---|---|---|
| A | raw Merkle root | Rejected. It is not bound to chain, pool or epoch, and the leaf count is not committed. |
| **B** | **domain-separated commitment to the root (above)** | **Recommended.** |
| C | per-session leaf hash, posted one by one | Rejected. It costs one registry write per session, and there is no batch to attest. |
| D | opaque off-chain id | Rejected. Nothing on the EVM can check a receipt against it. |

## 1. Context, sources and terms

- **Inference Finance** is a Solidity AMM prototype on HyperEVM testnet (chain
  998), owned by another team. It is unaudited and uses TEST mocks only. Its
  credit unit is **OMER**: 1 OMER = 750k input + 250k output tokens of a tier's
  reference model. Its contracts are not public, so this note describes them
  only at the level of the spec items IF-F11 (AgentRewards checks each receipt
  once per epoch; receipts are epoch-bound), IF-F12 (OmerMinter redeem settles
  on a spend receipt or is reclaimed if unserved) and IF-D8 (this decision).
- **FLOP Network** is a Substrate L1 with no EVM. It has payment and compute
  channels, where a session is the unit of work, plus escrow and HTLC via the
  Technocore Lock Protocol (TCLK). Its finality is AlephBFT: an ordered block is
  irreversible. Source: the FLOP whitepaper as summarised in the Flop repo's
  `FLOP.md`. Items that depend on the not-yet-final Yellow Paper are marked
  **[YP]**.
- **Flop reclaim** ([github.com/HuKiFl1/Flop](https://github.com/HuKiFl1/Flop)) is
  our existing stale-channel reclaim rule. This note reuses its terms and does
  not change them:
  - finalized state `σ = (nonce, owed, root, h)` (Flop SPEC §4.2) and the
    implicit opening state `σ₀ = (0, 0, ⊥, h_open)`;
  - `N` (staleness blocks) and `W` (challenge window blocks);
  - the earliest reclaim height `latest(c).h + N + W` (Flop SPEC I5);
  - the payout waterfall: provider owed first, then lender principal, then the
    payer remainder (Flop SPEC §10), with overrun recorded and never minted;
  - the error names `STALE_NONCE`, `STATE_REPLAYED`, `CONFLICTING_STATE`,
    `OWED_DECREASED`, `ALREADY_SETTLED` and `UNAUTHORIZED`.
- **TCLK semantics** (as stated in Flop `FLOP.md` §1): a timeout makes a refund
  eligible, but it does not expire a hashlock claim. A claim with an accepted
  preimage still wins until the refund is included.

Conventions: all amounts, heights, nonces and epochs are non-negative integers
(`bigint` in TypeScript, `uint64`/`uint128` on the EVM). There are no floats.
Every height is a **FLOP finalized height**. "Proposal" means a design
suggestion, not a FLOP or Inference Finance fact.

## 2. The objects

```
FLOP channel (Flop reclaim)          attester / keeper                EVM (HyperEVM 998)
--------------------------           ------------------------         ---------------------------------------
latest finalized state σ per    ──►  at each epoch checkpoint:   ──►  RootRegistry: jobId → RootCommitment
channel (nonce, owed, root, h)       one leaf per unsettled           ├─ v4 hook tags work with jobId
                                     channel, two roots               ├─ AgentRewards: claim once per epoch
                                     (blake2b, keccak), jobId         └─ OmerMinter: redeem / reclaim a lock
```

## 3. Receipt leaf

A leaf is the **latest finalized state of one channel at an epoch checkpoint**,
plus the channel's fixed identity. It is encoded as fixed-width big-endian
fields, 257 bytes in total:

| Offset | Field | Type | Meaning (Flop term) |
|---:|---|---|---|
| 0 | version | uint8 | Always `1`. |
| 1 | `flopGenesis` | bytes32 | FLOP network identity (genesis hash). Part of the domain. |
| 33 | `evmChainId` | uint64 | EVM chain the receipt is consumed on (998). Part of the domain. |
| 41 | `poolId` | bytes32 | Uniswap-v4 `PoolId`, which commits to the hook address through `PoolKey`. Part of the domain. |
| 73 | `channelId` | bytes32 | Channel id. Never reused (Flop I3). |
| 105 | `provider` | bytes32 | Provider (miner) FLOP account. |
| 137 | `payer` | bytes32 | Payer (agent) FLOP account. |
| 169 | `cumulativeOwed` | uint128 | `σ.owed`: cumulative OMER owed to the provider, in base units. |
| 185 | `escrow` | uint128 | `E = L + D`, fixed at open. |
| 201 | `nonce` | uint64 | `σ.nonce`, strictly increasing per channel. |
| 209 | `epoch` | uint64 | Epoch of the snapshot root that contains this leaf. |
| 217 | `finalizedHeight` | uint64 | `σ.h`: FLOP finalized height at which the state was recorded. |
| 225 | `stateRoot` | bytes32 | `σ.root`: the co-signed channel state root. |

Validity (`validateLeaf`): every id is non-zero, `payer ≠ provider`, and
`evmChainId ≥ 1`. A leaf with `nonce = 0` is the opening state `σ₀`, so it
must have `cumulativeOwed = 0` and `stateRoot = 0`. A leaf with `nonce ≥ 1`
must have a non-zero `stateRoot` (Flop SPEC §9, rule 2). `cumulativeOwed > escrow`
is valid, because Flop accepts overrun and caps it (Flop SPEC §9).

**Why this encoding.** It is byte-identical to Solidity
`abi.encodePacked(uint8, bytes32, uint64, bytes32, bytes32, bytes32, bytes32,
uint128, uint128, uint64, uint64, uint64, bytes32)`. Packed encoding of
fixed-size types is unambiguous, cheap on the EVM, and trivial to reproduce in
a FLOP native module. SCALE (Substrate's codec) uses little-endian and compact
integers, which the EVM would have to re-encode. Padded `abi.encode` would
double the bytes hashed. `BrokenPaddedEncoding` in the Foundry template shows
that the vectors catch the padded form.

**Two fields beyond the minimum.** `stateRoot` ties the leaf to the exact
co-signed state, so equivocation (two contents for one nonce) is visible.
`escrow` lets every consumer cap credit at escrow-backed spend without a
second lookup (T7). Both are flagged in §12 for the spec owner.

OMER units: `omerFromUsage` converts cumulative token counts to OMER base units
(18 decimals assumed) with
`floor(10^18 · (in·pIn + out·pOut) / (750_000·pIn + 250_000·pOut))`. It is
always computed from cumulative counts, so total rounding loss stays below one
base unit.

## 4. Hashing and domain separation

Every hashed preimage starts with exactly one type byte. Every body that can
be consumed starts with a version byte and carries its full domain:

| Prefix | Object | Preimage | Hashes |
|---|---|---|---|
| `0x00` | leaf | `0x00 ‖ leaf (257 bytes)` | blake2b-256 and keccak-256 |
| `0x01` | node | `0x01 ‖ left ‖ right` | blake2b-256 and keccak-256 |
| `0x02` | jobId | `0x02 ‖ 1 ‖ flopGenesis ‖ evmChainId ‖ hook ‖ poolId ‖ epoch ‖ checkpointHeight ‖ leafCount ‖ keccakRoot ‖ blakeRoot` | keccak-256 |
| `0x03` | nullifier | `0x03 ‖ 1 ‖ flopGenesis ‖ evmChainId ‖ poolId ‖ channelId ‖ epoch` | keccak-256 |
| (none) | empty root | the empty string | blake2b-256 and keccak-256 |

The `0x00`/`0x01` split is RFC 6962's. The preimages also have different fixed
lengths (258, 65, 182 and 114 bytes), so no preimage of one type parses as
another.

### 4.1 Why two hash functions

- **blake2b-256 on the FLOP side.** It is Substrate's native hash (`blake2_256`,
  and the `BlakeTwo256` hasher behind headers and storage tries). A FLOP
  native module, an escrow spend condition or a future light client sees
  blake2b commitments natively. Whether TCLK hash locks and typed escrow hash
  conditions can use blake2b, keccak or both is **[YP]**.
- **keccak-256 on the EVM side.** It is an EVM opcode. blake2b is only
  available on the EVM as the EIP-152 compression precompile (address `0x09`).
  Using it needs a wrapper for padding and the counter, and it is not known
  whether HyperEVM exposes it (§12).

### 4.2 Dual commitment

Both trees are built over **the same leaf bytes in the same order** (§5.1), so
they have the same shape and every proof has the same length in both. Only
the keccak root is checked on the EVM. The blake root is carried inside the
jobId, so it cannot be changed after the commitment is accepted.

- The EVM verifies keccak proofs (`verifyReceipt`).
- A FLOP-side party verifies blake proofs against the same commitment
  (`verifyReceiptFlop`).
- Anyone holding the published leaf set can rebuild both roots. A commitment
  whose two roots are not over the same leaves is a provable attester fault
  (`auditSnapshot` returns `KECCAK_ROOT_MISMATCH` or `BLAKE_ROOT_MISMATCH`; T11).

### 4.3 Bridge note: the honest gap

There is **no FLOP light client on the EVM** and **no on-chain FLOP credit
token**. Nothing on HyperEVM can check that a blake root corresponds to
finalized FLOP state. That binding rests on the attesters (§9). The dual
commitment keeps the door open for three later upgrades without changing leaf
bytes or jobIds:

1. An EVM light client that checks AlephBFT finality and a FLOP state proof
   for the blake root. The EVM would then verify blake proofs through EIP-152,
   or keep verifying keccak proofs and accept the pair as bound by the jobId.
2. A FLOP native module, adopted through governance, that verifies keccak
   receipts directly. Substrate's runtime offers keccak-256, so the
   commitment would not need to change.
3. A fraud-proof window in which watchers submit `auditSnapshot` or
   `auditTransition` evidence and a guardian freezes a jobId. This is an open
   question, because it adds a trusted role.

## 5. Merkle tree

### 5.1 Sorted leaves

Leaves are sorted by `channelId` as unsigned 32-byte values in ascending
order, and a channel may appear only once (`DUPLICATE_CHANNEL`). The sort key
does not depend on the hash function, so the blake and keccak trees share one
order and one index per channel. Input order never changes the roots.

### 5.2 Construction, odd-node rule and empty root

The tree is RFC 6962 §2.1 (`MTH`) with `H ∈ {blake2b-256, keccak-256}`:

```
MTH({})      = H("")                                         empty root
MTH({d})     = H(0x00 ‖ d)                                   leaf
MTH(D[0:n])  = H(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]))           k = largest power of two < n
```

It is built level by level. Nodes are paired from the left, and **an odd last
node is promoted to the next level unchanged. It is never hashed with itself.**
`tests/merkle.test.ts` checks against an independent recursive RFC 6962
implementation that the level-wise build produces the same root and audit path
for every size and index.

Bitcoin's rule (duplicate the last node) lets `[a, b, c]` and `[a, b, c, c]`
share a root (CVE-2012-2459). Here they differ (T9), and
`BrokenDuplicateOddNode` is rejected by the vectors.

The empty root is `H("")`: keccak
`0xc5d2…a470` and blake2b-256 `0x0e57…e3a8`. A root with `leafCount = 0` must
use both empty roots, and a non-empty root must use neither
(`EMPTY_ROOT_MISMATCH`). No proof verifies against an empty tree.

### 5.3 Proofs and verification

A proof is `(index, leafCount, siblings[])`, with siblings listed from the leaf
level upward. A promoted level contributes no sibling.

```
verify(root, leafHash, index, leafCount, siblings):
    require 1 ≤ leafCount ≤ 2^64−1 and index < leafCount
    h, i, n, k = leafHash, index, leafCount, 0
    while n > 1:
        if i is odd:          h = H(0x01 ‖ siblings[k++] ‖ h)
        else if i + 1 < n:    h = H(0x01 ‖ h ‖ siblings[k++])
        else:                 (promoted, no sibling)
        i, n = i / 2, ceil(n / 2)
    return k == len(siblings) and h == root
```

Verification is position-checked. Sorted-pair (commutative) node hashing is
rejected, because it would not bind a leaf to an index
(`BrokenSortedPairHashing`).

### 5.4 Second-preimage protection

Four independent measures:

1. **Prefixes** `0x00` (leaf) and `0x01` (node) put leaves and nodes in
   different hash domains (RFC 6962).
2. **The verifier hashes the leaf fields itself.** It never accepts a
   caller-supplied leaf hash, and a 258-byte leaf preimage cannot equal a
   65-byte node preimage.
3. **`leafCount` comes from the committed root, never from the prover.** This
   is a real requirement, not belt-and-braces. With a caller-chosen count, the
   internal node `H(0x01 ‖ h0 ‖ h1)` verifies as "leaf 0" of a 4-leaf tree
   against the root of a 7-leaf tree. A real leaf proof for index 0 of a
   5-leaf tree also verifies at count 6 (`tests/threat-model.property.test.ts`,
   T9). `leafCount` is therefore bound into the jobId, and the receipt check
   requires `proof.leafCount == commitment.leafCount`.
4. **Every sibling must be consumed and `index < leafCount` must hold.**
   Without the second check, index 14 aliases the promoted leaf 6 of a 7-leaf
   tree (vector `index-aliases-past-leaf-count`, `BrokenNoIndexBound`). That
   would also defeat a leaf-index bitmap.

## 6. Root to jobId for the hook

`RootCommitment = (flopGenesis, evmChainId, poolId, hook, epoch,
checkpointHeight, leafCount, keccakRoot, blakeRoot)`, and `jobId` is its
keccak commitment (§0). The **RootRegistry** accepts a commitment only if all
of the following hold, checked in this order:

1. it carries the attester threshold (`UNAUTHORIZED_ATTESTER`);
2. its domain and hook equal the registry's (`DOMAIN_MISMATCH`);
3. no root exists for that epoch (`ROOT_EXISTS`), and the epoch is not older
   than the latest one (`EPOCH_REGRESSION`). Gaps are allowed;
4. `checkpointHeight = (epoch + 1) · epochLength − 1` (`CHECKPOINT_MISMATCH`);
5. the empty-root rule of §5.2 (`EMPTY_ROOT_MISMATCH`).

Accepted commitments are immutable.

**In the hook (proposal).** `hookData` carries the jobId (or the full
commitment, from which the hook recomputes the jobId). The hook checks that
the registry knows the jobId, and that the commitment's `hook = address(this)`,
`evmChainId = block.chainid` and `poolId = key.toId()`. It then tags the swap
or fee with the jobId, for example in an event. The hook does not verify
individual receipts. AgentRewards and OmerMinter do, against the same jobId.
What the hook does with a tagged swap beyond attribution is a spec-owner
decision (§12).

## 7. Epoch binding and once-per-epoch dedup (AgentRewards, IF-F11)

**Epochs** are measured in FLOP finalized heights. Epoch `e` covers
`[e·L, (e+1)·L − 1]`, and its checkpoint is the last height. A snapshot for
`e` contains `latest(c)` as of the checkpoint for every unsettled channel, so
an unchanged channel reappears with the new `epoch` field. Because the leaf
carries the epoch, roots of consecutive epochs differ even when no channel
moved, and a leaf proven for epoch `e` fails against the root of `e+1` with
`EPOCH_MISMATCH` (T1).

**Claim**, checked in this order (`AgentRewardsModel.claim`):

1. The receipt verifies against an accepted root: known jobId, valid leaf,
   same domain, `leaf.epoch = root.epoch`, `finalizedHeight ≤ checkpoint`, and
   a keccak proof with the committed `leafCount`.
2. `latestEpoch ≤ e + claimWindowEpochs`, otherwise `EPOCH_EXPIRED`.
3. The nullifier is unspent, otherwise `NULLIFIER_SPENT`.
4. Consistency with the last credited state of the channel. Changed parties
   or escrow fail with `PARTY_MISMATCH` or `ESCROW_MISMATCH`. Then, following
   Flop SPEC §9 and invariant I4: a lower nonce fails with `STALE_NONCE`; the
   same nonce with the same content fails with `STATE_REPLAYED`; the same
   nonce with different content fails with `CONFLICTING_STATE`; a higher
   nonce with lower owed fails with `OWED_DECREASED`. A channel with no
   credited state is compared against `σ₀`.
5. Credit `min(owed, E) − min(lastOwed, E)` (escrow-backed spend only;
   overrun earns nothing), then spend the nullifier.

Because credit is a delta of cumulative owed, skipping an epoch loses
nothing, and re-presenting an old state earns nothing. The opening state
`σ₀` is never credited.

**Nullifier, not bitmap.** The nullifier is keyed by the receipt's identity
`(flopGenesis, evmChainId, poolId, channelId, epoch)`. It is deliberately
independent of the root, the leaf index and the nonce: a newer state of the
same channel in the same epoch hits the same nullifier (vector
`same-receipt-newer-nonce`). A bitmap over `(epoch, leafIndex)` is cheaper (one
storage word per 256 claims) and safe only if every root lists a channel at
most once. A single proof cannot show that. A faulty attester listing a
channel twice gets two claims past a bitmap but one past the nullifier (T4,
`EpochClaimBitmap`). Recommendation: nullifiers. A bitmap is acceptable as a
gas optimisation only together with the attester-trust assumption on
uniqueness.

## 8. OmerMinter redeem vs reclaim (IF-F12)

Since there is no on-chain FLOP credit token, the OMER **locked in the EVM
minter is the channel's escrow**: `E = L + D`, with lender principal `L` and
payer deposit `D`. The FLOP channel meters the session, and roots carry its
state to the EVM. One lock backs one channel (`DUPLICATE_LOCK`).

| | Redeem (served) | Reclaim (unserved, after timeout) |
|---|---|---|
| TCLK analogue | claim with a preimage | refund after the deadline |
| Caller | the provider only | `channel-parties` (payer, lender, provider) or `anyone`, as Flop's `triggerPolicy` (SPEC §8) |
| Root | any accepted root | **the latest accepted root** (`STALE_ROOT` otherwise) |
| Leaf must show | `nonce ≥ 1` and `owed > 0` (`NOT_SERVED`) | `checkpoint ≥ σ.h + N + W` (`TIMEOUT_NOT_REACHED`) |
| When | any time while the lock is open, **including after the timeout** | from the timeout on |
| Binding (both) | same channel, provider, payer and escrow as the lock (`CHANNEL_MISMATCH`, `PARTY_MISMATCH`, `ESCROW_MISMATCH`) | same |
| Payout (both) | Flop waterfall over `σ.owed`: provider, then lender principal, then payer; overrun recorded | same |

**Race rule (TCLK).** Reaching the timeout makes a reclaim eligible, but it
does not expire the provider's claim. Whichever terminal transition is
included first settles the lock, and the other fails with `ALREADY_SETTLED`.
After the timeout, a redeem still succeeds until a reclaim is included (vector
step "past the timeout a claim still wins until a refund is included").

**Why the asymmetry.** Payouts depend on which receipt is shown. The provider
gains from showing its highest state, so it may pick any root, and choosing an
older one only hurts itself. The payer and lender gain from showing a lower
state, so a reclaim must use the latest root. That way an older snapshot with
lower owed cannot shortchange the provider (T5). Either way the provider is
paid first, so Flop's provider-safety invariant (I2) holds with respect to the
receipt that settled.

**Consistency with Flop.** The timeout `σ.h + N + W` is the Flop liveness
bound I5 for a reclaim initiated as soon as the channel is stale. Flop's hard
window close (SPEC §7 and §13, item 3) still applies **on FLOP**: the channel ledger
accepts no state at `h ≥ s + W`, so no honest root can contain one. The TCLK
race applies **on the EVM** and governs which terminal transaction lands
first. It does not admit any state that Flop rejected, so the two rules do
not contradict each other. They answer Flop `FLOP.md` §5, question 1, for the
EVM leg only.

The EVM has no explicit `ReclaimInitiated` step. The staleness clock is
observed through attested checkpoints instead. If the spec owner wants
Flop's explicit two-step reclaim on the EVM side, see §12, question 5.

## 9. Who publishes roots, and what is trusted

**Publisher:** a k-of-n **attester (keeper) set**. At each epoch checkpoint it
reads only FLOP-finalized state (AlephBFT, so no reorg window) and builds the
snapshot (`buildSnapshot`). It publishes the full leaf set off-chain, for
example as a content-addressed blob, and submits the commitment with k
signatures to the registry. Who the attesters are, how they are selected and
what they stake is an open question.

| Property | Enforced on the EVM | Detectable by a watcher | Trusted |
|---|---|---|---|
| Domain, epoch and leaf-count binding; one immutable root per epoch; checkpoint pin | yes | | |
| Receipt is in the committed tree (keccak) | yes | | |
| Monotone per channel across epochs | partly (AgentRewards rejects rollback) | yes (`auditTransition`) | |
| keccak root and blake root cover the same leaves | no | yes (`auditSnapshot`) | attesters |
| Each leaf is the true latest finalized FLOP state | no | yes, with a FLOP node | attesters |
| Completeness: every unsettled channel is listed | no | yes, with a FLOP node | attesters |
| Liveness: a root every epoch | no | yes | attesters |

**Honest gap.** There is no on-chain FLOP credit token and no FLOP light
client on the EVM. Today the attesters are trusted for correctness,
completeness and liveness. Watchers can prove most faults off-chain, but the
EVM side cannot act on that evidence yet. A stalled attester set freezes
reclaims (redeems still work against older roots). That is safe for the
provider but a liveness risk for lenders and payers.

## 10. Threat model

| # | Threat | Attack | Mitigation | Enforced by | Test |
|---|---|---|---|---|---|
| T1 | Replay across epochs | Reuse an epoch-`e` receipt in `e+1` | `epoch` in leaf, jobId and nullifier; `leaf.epoch = root.epoch` | receipt check | `T1`, rewards step "epoch-10 leaf replayed…", `BrokenNoEpochBinding` |
| T2 | Replay across chains | Use a chain-999 receipt on 998, or a receipt from another FLOP network | `evmChainId` and `flopGenesis` in leaf, jobId and nullifier; registry domain | receipt check, registry | `T2/T3`, `BrokenJobIdWithoutChainId` |
| T3 | Replay across pools or hooks | Claim pool A's receipt in pool B | `poolId` (commits to the hook) in leaf and nullifier; `hook` in jobId | receipt check, registry | `T2/T3`, rewards step "receipt for another pool" |
| T4 | Double-claim | Claim twice in an epoch; list a channel twice | nullifier per (domain, channel, epoch); builder rejects duplicates; nullifier is independent of index and root | AgentRewards | `T4`, `BrokenRewardsNoNullifier`, `BrokenNullifierWithoutEpoch` |
| T5 | Stale root | Rival root for a past epoch; reclaim against an older, lower-owed snapshot | one immutable root per epoch, forward-only; reclaim needs the latest root | registry, OmerMinter | `T5`, `BrokenRegistryRootPerEpoch`, `BrokenReclaimAnyRoot` |
| T6 | Reorg | Build on a FLOP block that is later replaced | finalized heights only (AlephBFT); `finalizedHeight ≤ checkpoint`; checkpoint pinned to the epoch end | builder, receipt check, registry | `T6` |
| T7 | Inflated cumulative | Edit `cumulativeOwed` after proving; sign `owed ≫ escrow` | leaf fields are hashed by the verifier; payouts capped at `E` (overrun recorded); rewards credit capped at `E` | receipt check, waterfall, AgentRewards | `T7`, rewards step "inflated cumulative owed…" |
| T8 | Nonce rollback, equivocation | Faulty root rolls a channel back; two contents for one nonce | AgentRewards rejects `STALE_NONCE`, `CONFLICTING_STATE` and `OWED_DECREASED`; watchers flag transitions | AgentRewards, `auditTransition` | `T8`, rewards step "nonce rolled back" |
| T9 | Second preimage, tree malleability | Internal node as a leaf; padded or aliased proofs; duplicate-last padding | prefixes; committed `leafCount`; all siblings consumed; `index < leafCount`; promotion, not duplication | verifier | `T9`, 14 negative-proof vectors, `BrokenNoLeafPrefix`, `BrokenIgnoresLeftoverSiblings`, `BrokenNoIndexBound`, `BrokenDuplicateOddNode`, `BrokenSortedPairHashing` |
| T10 | Redeem/reclaim race | Payer reclaims early; both paths pay | reclaim only at `σ.h + N + W` on the latest root; first included terminal transition wins | OmerMinter | `T10`, minter scenario, `BrokenSettlesTwice`, `BrokenTimeoutExclusive` |
| T11 | Dual-root mismatch | Attester commits a blake root over different leaves | jobId binds both roots; watchers rebuild both | `auditSnapshot` | `T11` |

## 11. Where things are

| Concern | Code | Vectors (`vectors/receipt-root-v1.json`) |
|---|---|---|
| keccak-256, BLAKE2b | `src/hash/` (from FIPS 202 and RFC 7693) | `hashes` |
| Leaf | `src/leaf.ts` | `leafEncodings` |
| Tree, proofs | `src/merkle.ts` | `trees`, `negativeProofs` |
| jobId, nullifier, epochs, snapshot | `src/commitment.ts` | `jobIds`, `nullifiers` |
| Registry | `src/registry.ts` | both scenarios |
| Receipt check | `src/receipt.ts` | both scenarios |
| AgentRewards | `src/rewards.ts` | `rewardsScenario` |
| OmerMinter, waterfall, timeout | `src/minter.ts`, `src/settlement.ts` | `minterScenario`, `payouts`, `reclaimEligibility` |
| Watchers | `src/audit.ts` | (unit and property tests) |

Scenario expectations in `scripts/vectors.ts` are written by hand. The
generator throws if the models disagree, so the JSON is a specification, not
a snapshot of the code.

## 12. Open questions for the spec owner

1. **jobId granularity.** Is one jobId per (pool, epoch) the right unit for
   the hook, or should a swap name a single session (jobId plus leaf index)?
   What does the hook do with a tagged swap beyond attribution?
2. **Epoch clock.** Are AgentRewards epochs meant to be FLOP heights (this
   proposal), EVM blocks or wall-clock time? What are `epochLength` and the
   claim window?
3. **Who is rewarded.** Is the payer (agent), the provider, or both credited
   for a receipt? Is the credit unit escrow-backed OMER spend (this proposal)?
4. **Leaf fields.** Is it acceptable to add `escrow` and `stateRoot` to the
   minimum field set? Should `lender` be in the leaf as well?
5. **Explicit reclaim initiation.** Flop requires an explicit
   `ReclaimInitiated` and then a `W`-block window. This proposal uses the
   earliest bound `σ.h + N + W`, observed through attested checkpoints, and
   relies on the TCLK race to protect the provider. Should the EVM side
   instead have a two-step `initiateReclaim` / `reclaim`?
6. **Partial redemption.** Locks settle once, as Flop channels do. Should a
   provider be able to redeem incrementally against cumulative receipts?
7. **Party mapping.** Leaves carry FLOP account ids (bytes32). How does the
   EVM map them to payout addresses and to `msg.sender` for the provider-only
   redeem?
8. **Attesters.** Who they are, k-of-n values, stake, slashing, and whether a
   guardian may freeze a jobId on watcher evidence (§4.3, item 3).
9. **HyperEVM precompiles.** Does HyperEVM expose EIP-152 (BLAKE2 F at `0x09`)?
   If it does, blake proofs could be verified on the EVM directly.
10. **OMER decimals and rounding.** Are 18 decimals and floor rounding
    (against the provider) right for `cumulativeOwed`?
11. **Stalled attesters.** Should a lock have an absolute fallback deadline
    for when no root arrives? Any such deadline weakens provider safety.
12. **Nullifier migration.** If AgentRewards is redeployed, the spent set
    must move with it, or receipts can be claimed again on the new contract.

## 13. References

Only public specifications and papers are cited. All code here is original
and MIT-licensed.

- RFC 6962 and RFC 9162, *Certificate Transparency*: Merkle tree hash, audit
  paths, and the `0x00`/`0x01` prefixes.
- RFC 7693, *The BLAKE2 Cryptographic Hash and Message Authentication Code*.
- NIST FIPS 202, *SHA-3 Standard: Permutation-Based Hash and Extendable-Output
  Functions* (Keccak-f[1600]; the EVM uses the original Keccak padding).
- EIP-152, *Add BLAKE2 compression function F precompile*.
- CVE-2012-2459: Merkle tree duplicate-leaf ambiguity in Bitcoin.
- Uniswap v4 core specification: `PoolKey`, `PoolId`, hooks and `hookData`.
- *Aleph: Efficient Atomic Broadcast in Asynchronous Networks with Byzantine
  Nodes* (ACM AFT 2019): the AlephBFT finality FLOP uses.
- FLOP Network whitepaper (draft, as summarised in the Flop repo's `FLOP.md`).
- Flop reclaim: [github.com/HuKiFl1/Flop](https://github.com/HuKiFl1/Flop),
  `SPEC.md` and `FLOP.md`.
