// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HuKiFl1
pragma solidity ^0.8.24;

/*
 * ReceiptRootVectors: a Foundry TEST TEMPLATE for the Inference Finance IF-D8
 * proposal (hook jobId as a Flop receipt root).
 *
 * This is NOT a product contract. Nothing here is audited or meant to be
 * deployed. The mocks are test-only reference behaviour, and the vectors use
 * synthetic identifiers.
 *
 * How to use it:
 *   1. Implement `IReceiptRootHooks` (pure encoding / hashing / proof / payout
 *      functions) and `IReceiptSystemHarness` (an adapter over your registry,
 *      AgentRewards and OmerMinter that returns a status code instead of
 *      reverting).
 *   2. Add a test contract:
 *
 *        contract SpecOwnerVectorsTest is ReceiptRootVectorsTest {
 *            function _hooks() internal override returns (IReceiptRootHooks) { return new MyHooks(); }
 *            function _newHarness() internal override returns (IReceiptSystemHarness) { return new MyAdapter(); }
 *            // Return false to compare only accept/reject, not the exact status code.
 *            function _strictCodes() internal pure override returns (bool) { return true; }
 *        }
 *
 *   3. `forge test` replays ../vectors/receipt-root-v1.json through your hooks.
 *
 * `MockVerifierVectorsTest` must pass. Every contract named `Broken*` carries
 * exactly one deliberate bug, and `BrokenVerifiersMustFailTest` asserts the
 * vectors reject each of them.
 */

// ------------------------------------------------------------------ cheatcodes

/// The subset of Foundry cheatcodes this template uses, declared from the Foundry Book.
interface Vm {
    function readFile(string calldata path) external view returns (string memory);
    function projectRoot() external view returns (string memory);
    function toString(uint256 value) external pure returns (string memory);
    function keyExistsJson(string calldata json, string calldata key) external view returns (bool);
    function parseJsonUint(string calldata json, string calldata key) external pure returns (uint256);
    function parseJsonBool(string calldata json, string calldata key) external pure returns (bool);
    function parseJsonBytes32(string calldata json, string calldata key) external pure returns (bytes32);
    function parseJsonBytes(string calldata json, string calldata key) external pure returns (bytes memory);
    function parseJsonAddress(string calldata json, string calldata key) external pure returns (address);
    function parseJsonString(string calldata json, string calldata key) external pure returns (string memory);
    function parseJsonBytes32Array(string calldata json, string calldata key) external pure returns (bytes32[] memory);
}

// ------------------------------------------------------------------ types

/// A finalized FLOP channel state. Field order is the encoding order.
struct Leaf {
    bytes32 flopGenesis;
    uint64 evmChainId;
    bytes32 poolId;
    bytes32 channelId;
    bytes32 provider;
    bytes32 payer;
    uint128 cumulativeOwed;
    uint128 escrow;
    uint64 nonce;
    uint64 epoch;
    uint64 finalizedHeight;
    bytes32 stateRoot;
}

struct RootCommitment {
    bytes32 flopGenesis;
    uint64 evmChainId;
    bytes32 poolId;
    address hook;
    uint64 epoch;
    uint64 checkpointHeight;
    uint64 leafCount;
    bytes32 keccakRoot;
    bytes32 blakeRoot;
}

struct Claim {
    bytes32 jobId;
    Leaf leaf;
    uint256 index;
    uint256 leafCount;
    bytes32[] siblings;
}

struct Lock {
    bytes32 lockId;
    bytes32 channelId;
    bytes32 provider;
    bytes32 payer;
    bytes32 lender;
    uint128 lenderPrincipal;
    uint128 payerDeposit;
}

struct Payouts {
    uint256 toProvider;
    uint256 toLender;
    uint256 toPayer;
    uint256 overrun;
    uint256 lenderShortfall;
}

struct SystemParams {
    bytes32 flopGenesis;
    uint64 evmChainId;
    bytes32 poolId;
    address hook;
    uint64 epochLength;
    uint64 claimWindowEpochs;
    uint64 stalenessBlocks;
    uint64 challengeWindowBlocks;
    bool reclaimByAnyone;
}

// ------------------------------------------------------------------ hooks the spec owner implements

/// Pure functions. Each must match the TypeScript reference byte for byte.
interface IReceiptRootHooks {
    /// 257 bytes: abi.encodePacked(uint8 1, flopGenesis, evmChainId, poolId, channelId, provider, payer,
    /// cumulativeOwed, escrow, nonce, epoch, finalizedHeight, stateRoot).
    function encodeLeaf(Leaf calldata leaf) external view returns (bytes memory);
    /// keccak256(0x00 ‖ encodeLeaf(leaf)).
    function leafHash(Leaf calldata leaf) external view returns (bytes32);
    /// keccak256(0x01 ‖ left ‖ right).
    function nodeHash(bytes32 left, bytes32 right) external view returns (bytes32);
    /// keccak256("").
    function emptyRoot() external view returns (bytes32);
    /// RFC 6962 shape: pair left to right, promote an odd last node unchanged.
    function rootOf(bytes32[] calldata leafHashes) external view returns (bytes32);
    /// Position-checked proof. `leafCount` must come from the committed root; every sibling must be used.
    function verifyProof(bytes32 root, bytes32 leaf, uint256 index, uint256 leafCount, bytes32[] calldata siblings)
        external
        view
        returns (bool);
    function jobId(RootCommitment calldata c) external view returns (bytes32);
    function nullifier(bytes32 flopGenesis, uint64 evmChainId, bytes32 poolId, bytes32 channelId, uint64 epoch)
        external
        view
        returns (bytes32);
    /// Flop waterfall: provider owed, then lender principal, then payer.
    function payouts(uint256 escrow, uint256 lenderPrincipal, uint256 owed) external view returns (Payouts memory);
    /// checkpointHeight >= finalizedHeight + N + W.
    function reclaimEligible(uint64 checkpointHeight, uint64 finalizedHeight, uint64 n, uint64 w)
        external
        view
        returns (bool);
}

/// Stateful adapter over registry + AgentRewards + OmerMinter. Return bytes32("OK") or the
/// TypeScript error code (e.g. bytes32("NULLIFIER_SPENT")); state must not change on rejection.
interface IReceiptSystemHarness {
    function initialize(SystemParams calldata p) external;
    function acceptRoot(RootCommitment calldata c, bool attested) external returns (bytes32 code);
    function claimReward(Claim calldata c) external returns (bytes32 code, uint256 credit);
    function openLock(Lock calldata l) external returns (bytes32 code);
    function redeem(bytes32 lockId, Claim calldata c, bytes32 by) external returns (bytes32 code, Payouts memory p);
    function reclaim(bytes32 lockId, Claim calldata c, bytes32 by) external returns (bytes32 code, Payouts memory p);
}

// ------------------------------------------------------------------ vector runner

contract ReceiptRootVectorRunner {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant OK = "OK";
    string private vectorsPath;

    constructor(string memory path) {
        vectorsPath = path;
    }

    // ---- JSON helpers

    function _json() internal view returns (string memory) {
        return vm.readFile(vectorsPath);
    }

    function _at(string memory key, uint256 i) internal pure returns (string memory) {
        return string.concat(key, "[", vm.toString(i), "]");
    }

    function _len(string memory j, string memory key) internal view returns (uint256 n) {
        while (vm.keyExistsJson(j, _at(key, n))) n++;
    }

    function _u(string memory j, string memory key) internal pure returns (uint256) {
        return vm.parseJsonUint(j, key);
    }

    function _b(string memory j, string memory key) internal pure returns (bytes32) {
        return vm.parseJsonBytes32(j, key);
    }

    function _code(string memory j, string memory key) internal pure returns (bytes32) {
        return bytes32(bytes(vm.parseJsonString(j, key)));
    }

    function _leaf(string memory j, string memory k) internal pure returns (Leaf memory l) {
        l.flopGenesis = _b(j, string.concat(k, ".flopGenesis"));
        l.evmChainId = uint64(_u(j, string.concat(k, ".evmChainId")));
        l.poolId = _b(j, string.concat(k, ".poolId"));
        l.channelId = _b(j, string.concat(k, ".channelId"));
        l.provider = _b(j, string.concat(k, ".provider"));
        l.payer = _b(j, string.concat(k, ".payer"));
        l.cumulativeOwed = uint128(_u(j, string.concat(k, ".cumulativeOwed")));
        l.escrow = uint128(_u(j, string.concat(k, ".escrow")));
        l.nonce = uint64(_u(j, string.concat(k, ".nonce")));
        l.epoch = uint64(_u(j, string.concat(k, ".epoch")));
        l.finalizedHeight = uint64(_u(j, string.concat(k, ".finalizedHeight")));
        l.stateRoot = _b(j, string.concat(k, ".stateRoot"));
    }

    function _commitment(string memory j, string memory k) internal pure returns (RootCommitment memory c) {
        c.flopGenesis = _b(j, string.concat(k, ".flopGenesis"));
        c.evmChainId = uint64(_u(j, string.concat(k, ".evmChainId")));
        c.poolId = _b(j, string.concat(k, ".poolId"));
        c.hook = vm.parseJsonAddress(j, string.concat(k, ".hook"));
        c.epoch = uint64(_u(j, string.concat(k, ".epoch")));
        c.checkpointHeight = uint64(_u(j, string.concat(k, ".checkpointHeight")));
        c.leafCount = uint64(_u(j, string.concat(k, ".leafCount")));
        c.keccakRoot = _b(j, string.concat(k, ".keccakRoot"));
        c.blakeRoot = _b(j, string.concat(k, ".blakeRoot"));
    }

    function _claim(string memory j, string memory k) internal pure returns (Claim memory c) {
        c.jobId = _b(j, string.concat(k, ".jobId"));
        c.leaf = _leaf(j, string.concat(k, ".leaf"));
        c.index = _u(j, string.concat(k, ".proof.index"));
        c.leafCount = _u(j, string.concat(k, ".proof.leafCount"));
        c.siblings = vm.parseJsonBytes32Array(j, string.concat(k, ".proof.siblings"));
    }

    function _payouts(string memory j, string memory k) internal pure returns (Payouts memory p) {
        p.toProvider = _u(j, string.concat(k, ".toProvider"));
        p.toLender = _u(j, string.concat(k, ".toLender"));
        p.toPayer = _u(j, string.concat(k, ".toPayer"));
        p.overrun = _u(j, string.concat(k, ".overrun"));
        p.lenderShortfall = _u(j, string.concat(k, ".lenderShortfall"));
    }

    function _params(string memory j, string memory k) internal view returns (SystemParams memory p) {
        p.flopGenesis = _b(j, string.concat(k, ".flopGenesis"));
        p.evmChainId = uint64(_u(j, string.concat(k, ".evmChainId")));
        p.poolId = _b(j, string.concat(k, ".poolId"));
        p.hook = vm.parseJsonAddress(j, string.concat(k, ".hook"));
        p.epochLength = uint64(_u(j, string.concat(k, ".epochLength")));
        if (vm.keyExistsJson(j, string.concat(k, ".claimWindowEpochs"))) {
            p.claimWindowEpochs = uint64(_u(j, string.concat(k, ".claimWindowEpochs")));
        }
        if (vm.keyExistsJson(j, string.concat(k, ".stalenessBlocks"))) {
            p.stalenessBlocks = uint64(_u(j, string.concat(k, ".stalenessBlocks")));
            p.challengeWindowBlocks = uint64(_u(j, string.concat(k, ".challengeWindowBlocks")));
            p.reclaimByAnyone = keccak256(bytes(vm.parseJsonString(j, string.concat(k, ".reclaimPolicy"))))
                == keccak256("anyone");
        }
    }

    function _eq(Payouts memory a, Payouts memory b) internal pure returns (bool) {
        return a.toProvider == b.toProvider && a.toLender == b.toLender && a.toPayer == b.toPayer
            && a.overrun == b.overrun && a.lenderShortfall == b.lenderShortfall;
    }

    function _checkCode(bytes32 got, bytes32 expected, bool strict, string memory what) internal pure {
        if (strict) require(got == expected, string.concat("status code mismatch: ", what));
        else require((got == OK) == (expected == OK), string.concat("accept/reject mismatch: ", what));
    }

    // ---- pure vectors

    function runPure(IReceiptRootHooks h) external view {
        string memory j = _json();
        _encodings(h, j);
        _trees(h, j);
        _negatives(h, j);
        _commitments(h, j);
        _settlement(h, j);
    }

    function _encodings(IReceiptRootHooks h, string memory j) internal view {
        require(h.emptyRoot() == _b(j, ".encoding.emptyRoots.keccak256"), "empty root");
        require(h.rootOf(new bytes32[](0)) == h.emptyRoot(), "root of no leaves");
        uint256 n = _len(j, ".leafEncodings");
        for (uint256 i = 0; i < n; i++) {
            string memory k = _at(".leafEncodings", i);
            Leaf memory l = _leaf(j, string.concat(k, ".leaf"));
            bytes memory enc = h.encodeLeaf(l);
            require(enc.length == 257, "leaf is 257 bytes");
            require(keccak256(enc) == keccak256(vm.parseJsonBytes(j, string.concat(k, ".encoded"))), "leaf encoding");
            require(h.leafHash(l) == _b(j, string.concat(k, ".keccakLeafHash")), "leaf hash");
            require(
                h.nullifier(l.flopGenesis, l.evmChainId, l.poolId, l.channelId, l.epoch)
                    == _b(j, string.concat(k, ".nullifier")),
                "leaf nullifier"
            );
        }
    }

    function _trees(IReceiptRootHooks h, string memory j) internal view {
        uint256 n = _len(j, ".trees");
        for (uint256 t = 0; t < n; t++) {
            string memory k = _at(".trees", t);
            RootCommitment memory c = _commitment(j, string.concat(k, ".commitment"));
            require(h.jobId(c) == _b(j, string.concat(k, ".jobId")), "tree jobId");
            bytes32[] memory kh = vm.parseJsonBytes32Array(j, string.concat(k, ".keccakLeafHashes"));
            require(kh.length == c.leafCount, "leaf count");
            require(h.rootOf(kh) == c.keccakRoot, "tree root");
            for (uint256 i = 0; i < kh.length; i++) {
                require(h.leafHash(_leaf(j, _at(string.concat(k, ".leaves"), i))) == kh[i], "tree leaf hash");
                bytes32[] memory s =
                    vm.parseJsonBytes32Array(j, string.concat(_at(string.concat(k, ".proofs"), i), ".keccakSiblings"));
                require(h.verifyProof(c.keccakRoot, kh[i], i, c.leafCount, s), "valid proof rejected");
            }
        }
    }

    function _negatives(IReceiptRootHooks h, string memory j) internal view {
        uint256 n = _len(j, ".negativeProofs");
        require(n > 0, "no negative vectors");
        for (uint256 i = 0; i < n; i++) {
            string memory k = _at(".negativeProofs", i);
            bool ok = h.verifyProof(
                _b(j, string.concat(k, ".root")),
                _b(j, string.concat(k, ".leafHash")),
                _u(j, string.concat(k, ".index")),
                _u(j, string.concat(k, ".leafCount")),
                vm.parseJsonBytes32Array(j, string.concat(k, ".siblings"))
            );
            require(!ok, string.concat("negative proof accepted: ", vm.parseJsonString(j, string.concat(k, ".name"))));
        }
    }

    function _commitments(IReceiptRootHooks h, string memory j) internal view {
        uint256 n = _len(j, ".jobIds");
        for (uint256 i = 0; i < n; i++) {
            string memory k = _at(".jobIds", i);
            require(h.jobId(_commitment(j, string.concat(k, ".commitment"))) == _b(j, string.concat(k, ".jobId")), "jobId");
        }
        n = _len(j, ".nullifiers");
        for (uint256 i = 0; i < n; i++) {
            string memory k = _at(".nullifiers", i);
            bytes32 got = h.nullifier(
                _b(j, string.concat(k, ".flopGenesis")),
                uint64(_u(j, string.concat(k, ".evmChainId"))),
                _b(j, string.concat(k, ".poolId")),
                _b(j, string.concat(k, ".channelId")),
                uint64(_u(j, string.concat(k, ".epoch")))
            );
            require(got == _b(j, string.concat(k, ".nullifier")), "nullifier");
        }
    }

    function _settlement(IReceiptRootHooks h, string memory j) internal view {
        uint256 n = _len(j, ".payouts");
        for (uint256 i = 0; i < n; i++) {
            string memory k = _at(".payouts", i);
            Payouts memory got = h.payouts(
                _u(j, string.concat(k, ".escrow")), _u(j, string.concat(k, ".lenderPrincipal")), _u(j, string.concat(k, ".owed"))
            );
            require(_eq(got, _payouts(j, k)), "waterfall");
        }
        n = _len(j, ".reclaimEligibility");
        for (uint256 i = 0; i < n; i++) {
            string memory k = _at(".reclaimEligibility", i);
            bool got = h.reclaimEligible(
                uint64(_u(j, string.concat(k, ".checkpointHeight"))),
                uint64(_u(j, string.concat(k, ".finalizedHeight"))),
                uint64(_u(j, string.concat(k, ".stalenessBlocks"))),
                uint64(_u(j, string.concat(k, ".challengeWindowBlocks")))
            );
            require(got == vm.parseJsonBool(j, string.concat(k, ".eligible")), "reclaim eligibility");
        }
    }

    // ---- stateful scenarios

    function runRewards(IReceiptSystemHarness s, bool strict) external {
        string memory j = _json();
        s.initialize(_params(j, ".rewardsScenario.params"));
        uint256 n = _len(j, ".rewardsScenario.steps");
        uint256 total;
        for (uint256 i = 0; i < n; i++) {
            string memory k = _at(".rewardsScenario.steps", i);
            string memory note = vm.parseJsonString(j, string.concat(k, ".note"));
            bytes32 expected = _code(j, string.concat(k, ".expect"));
            bytes32 op = _code(j, string.concat(k, ".op"));
            if (op == "acceptRoot") {
                bytes32 got = s.acceptRoot(
                    _commitment(j, string.concat(k, ".commitment")), vm.parseJsonBool(j, string.concat(k, ".attested"))
                );
                _checkCode(got, expected, strict, note);
            } else {
                (bytes32 got, uint256 credit) = s.claimReward(_claim(j, k));
                _checkCode(got, expected, strict, note);
                require(credit == _u(j, string.concat(k, ".credit")), string.concat("credit: ", note));
                total += credit;
            }
        }
        require(total == _u(j, ".rewardsScenario.totalCredited"), "total credited");
    }

    function runMinter(IReceiptSystemHarness s, bool strict) external {
        string memory j = _json();
        s.initialize(_params(j, ".minterScenario.params"));
        uint256 n = _len(j, ".minterScenario.steps");
        for (uint256 i = 0; i < n; i++) {
            string memory k = _at(".minterScenario.steps", i);
            string memory note = vm.parseJsonString(j, string.concat(k, ".note"));
            bytes32 expected = _code(j, string.concat(k, ".expect"));
            bytes32 op = _code(j, string.concat(k, ".op"));
            if (op == "acceptRoot") {
                _checkCode(s.acceptRoot(_commitment(j, string.concat(k, ".commitment")), true), expected, strict, note);
            } else if (op == "open") {
                _checkCode(s.openLock(_lock(j, string.concat(k, ".lock"))), expected, strict, note);
            } else {
                _settleStep(s, j, k, op, expected, strict, note);
            }
        }
    }

    function _settleStep(
        IReceiptSystemHarness s,
        string memory j,
        string memory k,
        bytes32 op,
        bytes32 expected,
        bool strict,
        string memory note
    ) internal {
        bytes32 lockId = _b(j, string.concat(k, ".lockId"));
        bytes32 by = _b(j, string.concat(k, ".by"));
        Claim memory c = _claim(j, k);
        (bytes32 got, Payouts memory p) = op == "redeem" ? s.redeem(lockId, c, by) : s.reclaim(lockId, c, by);
        _checkCode(got, expected, strict, note);
        require(_eq(p, _payouts(j, string.concat(k, ".payouts"))), string.concat("payouts: ", note));
    }

    function _lock(string memory j, string memory k) internal pure returns (Lock memory l) {
        l.lockId = _b(j, string.concat(k, ".lockId"));
        l.channelId = _b(j, string.concat(k, ".channelId"));
        l.provider = _b(j, string.concat(k, ".provider"));
        l.payer = _b(j, string.concat(k, ".payer"));
        l.lender = _b(j, string.concat(k, ".lender"));
        l.lenderPrincipal = uint128(_u(j, string.concat(k, ".lenderPrincipal")));
        l.payerDeposit = uint128(_u(j, string.concat(k, ".payerDeposit")));
    }
}

// ------------------------------------------------------------------ test base the spec owner extends

abstract contract ReceiptRootVectorsTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    ReceiptRootVectorRunner internal runner;

    function setUp() public virtual {
        runner = new ReceiptRootVectorRunner(string.concat(vm.projectRoot(), "/../vectors/receipt-root-v1.json"));
    }

    function _hooks() internal virtual returns (IReceiptRootHooks);
    function _newHarness() internal virtual returns (IReceiptSystemHarness);

    function _strictCodes() internal pure virtual returns (bool) {
        return true;
    }

    function test_pureVectors() public {
        runner.runPure(_hooks());
    }

    function test_rewardsScenario() public {
        runner.runRewards(_newHarness(), _strictCodes());
    }

    function test_minterScenario() public {
        runner.runMinter(_newHarness(), _strictCodes());
    }
}

// ------------------------------------------------------------------ TEST-ONLY mock implementation

/// Test-only reference hooks. Internal seams are virtual so each Broken* variant changes one thing.
contract MockReceiptRootHooks is IReceiptRootHooks {
    bytes32 internal constant EMPTY_KECCAK_ROOT = keccak256("");

    function encodeLeaf(Leaf calldata l) external view virtual returns (bytes memory) {
        return _encode(l);
    }

    function leafHash(Leaf calldata l) external view returns (bytes32) {
        return _leafHash(l);
    }

    function nodeHash(bytes32 left, bytes32 right) external view returns (bytes32) {
        return _node(left, right);
    }

    function emptyRoot() external pure returns (bytes32) {
        return EMPTY_KECCAK_ROOT;
    }

    function rootOf(bytes32[] calldata leafHashes) external view returns (bytes32) {
        uint256 n = leafHashes.length;
        if (n == 0) return EMPTY_KECCAK_ROOT;
        bytes32[] memory level = leafHashes;
        while (n > 1) {
            uint256 m = (n + 1) / 2;
            for (uint256 i = 0; i < m; i++) {
                level[i] = 2 * i + 1 < n ? _node(level[2 * i], level[2 * i + 1]) : _odd(level[2 * i]);
            }
            n = m;
        }
        return level[0];
    }

    function verifyProof(bytes32 root, bytes32 leaf, uint256 index, uint256 leafCount, bytes32[] calldata siblings)
        external
        view
        virtual
        returns (bool)
    {
        if (leafCount == 0 || leafCount > type(uint64).max || !_indexInRange(index, leafCount)) return false;
        bytes32 h = leaf;
        uint256 i = index;
        uint256 n = leafCount;
        uint256 k = 0;
        while (n > 1) {
            if (i & 1 == 1) {
                if (k >= siblings.length) return false;
                h = _node(siblings[k++], h);
            } else if (i + 1 < n) {
                if (k >= siblings.length) return false;
                h = _node(h, siblings[k++]);
            } else {
                h = _odd(h);
            }
            i >>= 1;
            n = (n + 1) >> 1;
        }
        return _allConsumed(k, siblings.length) && h == root;
    }

    function jobId(RootCommitment calldata c) external view virtual returns (bytes32) {
        return keccak256(
            bytes.concat(
                abi.encodePacked(bytes1(0x02), uint8(1), c.flopGenesis, c.evmChainId, c.hook, c.poolId),
                abi.encodePacked(c.epoch, c.checkpointHeight, c.leafCount, c.keccakRoot, c.blakeRoot)
            )
        );
    }

    function nullifier(bytes32 flopGenesis, uint64 evmChainId, bytes32 poolId, bytes32 channelId, uint64 epoch)
        external
        view
        virtual
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(bytes1(0x03), uint8(1), flopGenesis, evmChainId, poolId, channelId, epoch));
    }

    function payouts(uint256 escrow, uint256 lenderPrincipal, uint256 owed) external view virtual returns (Payouts memory p) {
        require(lenderPrincipal <= escrow, "lenderPrincipal > escrow");
        p.toProvider = owed < escrow ? owed : escrow;
        uint256 rest = escrow - p.toProvider;
        p.toLender = lenderPrincipal < rest ? lenderPrincipal : rest;
        p.toPayer = rest - p.toLender;
        p.overrun = owed - p.toProvider;
        p.lenderShortfall = lenderPrincipal - p.toLender;
    }

    function reclaimEligible(uint64 checkpointHeight, uint64 finalizedHeight, uint64 n, uint64 w)
        external
        view
        virtual
        returns (bool)
    {
        return uint256(checkpointHeight) >= uint256(finalizedHeight) + n + w;
    }

    function _encode(Leaf memory l) internal view virtual returns (bytes memory) {
        return bytes.concat(
            abi.encodePacked(uint8(1), l.flopGenesis, l.evmChainId, l.poolId, l.channelId, l.provider),
            abi.encodePacked(l.payer, l.cumulativeOwed, l.escrow, l.nonce, l.epoch, l.finalizedHeight, l.stateRoot)
        );
    }

    function _leafHash(Leaf memory l) internal view virtual returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x00), _encode(l)));
    }

    function _node(bytes32 left, bytes32 right) internal view virtual returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x01), left, right));
    }

    function _odd(bytes32 h) internal view virtual returns (bytes32) {
        return h;
    }

    function _indexInRange(uint256 index, uint256 leafCount) internal view virtual returns (bool) {
        return index < leafCount;
    }

    function _allConsumed(uint256 used, uint256 given) internal view virtual returns (bool) {
        return used == given;
    }
}

/// Test-only registry + AgentRewards + OmerMinter with the TypeScript reference's check order.
contract MockReceiptSystem is IReceiptSystemHarness {
    bytes32 internal constant OK = "OK";
    bytes32 internal constant EMPTY_KECCAK_ROOT = keccak256("");
    bytes32 internal constant EMPTY_BLAKE_ROOT = 0x0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8;

    struct Credited {
        bool exists;
        uint64 nonce;
        uint128 owed;
        bytes32 stateRoot;
        bytes32 provider;
        bytes32 payer;
        uint128 escrow;
    }

    struct LockState {
        bool exists;
        bool settled;
        Lock lock;
        uint256 escrow;
    }

    MockReceiptRootHooks internal immutable hooks = new MockReceiptRootHooks();
    SystemParams internal p;

    mapping(bytes32 => RootCommitment) internal roots;
    mapping(bytes32 => bool) internal known;
    mapping(uint64 => bool) internal epochUsed;
    bool internal hasLatest;
    uint64 internal latestEpoch;
    bytes32 internal latestJobId;

    mapping(bytes32 => bool) internal spent;
    mapping(bytes32 => Credited) internal credited;

    mapping(bytes32 => LockState) internal locks;
    mapping(bytes32 => bool) internal channelLocked;

    function initialize(SystemParams calldata params) external {
        p = params;
    }

    // ---- registry

    function acceptRoot(RootCommitment calldata c, bool attested) external returns (bytes32) {
        if (!attested) return "UNAUTHORIZED_ATTESTER";
        if (c.flopGenesis != p.flopGenesis || c.evmChainId != p.evmChainId || c.poolId != p.poolId || c.hook != p.hook) {
            return "DOMAIN_MISMATCH";
        }
        if (_epochTaken(c.epoch)) return "ROOT_EXISTS";
        if (hasLatest && c.epoch < latestEpoch) return "EPOCH_REGRESSION";
        if (uint256(c.checkpointHeight) != (uint256(c.epoch) + 1) * p.epochLength - 1) return "CHECKPOINT_MISMATCH";
        bool consistent = c.leafCount == 0
            ? c.keccakRoot == EMPTY_KECCAK_ROOT && c.blakeRoot == EMPTY_BLAKE_ROOT
            : c.keccakRoot != EMPTY_KECCAK_ROOT && c.blakeRoot != EMPTY_BLAKE_ROOT;
        if (!consistent) return "EMPTY_ROOT_MISMATCH";
        bytes32 id = hooks.jobId(c);
        roots[id] = c;
        known[id] = true;
        epochUsed[c.epoch] = true;
        hasLatest = true;
        latestEpoch = c.epoch;
        latestJobId = id;
        return OK;
    }

    function _validLeaf(Leaf calldata l) internal pure returns (bool) {
        if (l.flopGenesis == 0 || l.poolId == 0 || l.channelId == 0 || l.evmChainId == 0) return false;
        if (l.provider == 0 || l.payer == 0 || l.provider == l.payer) return false;
        if (l.nonce == 0) return l.cumulativeOwed == 0 && l.stateRoot == 0;
        return l.stateRoot != 0;
    }

    function _verifyReceipt(Claim calldata cl) internal view returns (bytes32, RootCommitment memory c) {
        if (!known[cl.jobId]) return ("UNKNOWN_ROOT", c);
        c = roots[cl.jobId];
        Leaf calldata l = cl.leaf;
        if (!_validLeaf(l)) return ("INVALID_LEAF", c);
        if (l.flopGenesis != c.flopGenesis || l.evmChainId != c.evmChainId || l.poolId != c.poolId) {
            return ("DOMAIN_MISMATCH", c);
        }
        if (_epochUnbound(l.epoch, c.epoch)) return ("EPOCH_MISMATCH", c);
        if (l.finalizedHeight > c.checkpointHeight) return ("HEIGHT_BEYOND_CHECKPOINT", c);
        if (cl.leafCount != c.leafCount || !hooks.verifyProof(c.keccakRoot, hooks.leafHash(l), cl.index, cl.leafCount, cl.siblings)) {
            return ("INVALID_PROOF", c);
        }
        return (OK, c);
    }

    // ---- AgentRewards (IF-F11)

    function claimReward(Claim calldata cl) external returns (bytes32, uint256) {
        (bytes32 code, RootCommitment memory c) = _verifyReceipt(cl);
        if (code != OK) return (code, 0);
        Leaf calldata l = cl.leaf;
        if (uint256(latestEpoch) > uint256(c.epoch) + p.claimWindowEpochs) return ("EPOCH_EXPIRED", 0);
        bytes32 nf = hooks.nullifier(l.flopGenesis, l.evmChainId, l.poolId, l.channelId, l.epoch);
        if (_nullifierSpent(nf)) return ("NULLIFIER_SPENT", 0);
        Credited storage last = credited[l.channelId];
        if (last.exists) {
            if (l.provider != last.provider || l.payer != last.payer) return ("PARTY_MISMATCH", 0);
            if (l.escrow != last.escrow) return ("ESCROW_MISMATCH", 0);
        }
        if (l.nonce < last.nonce) return ("STALE_NONCE", 0);
        if (l.nonce == last.nonce) {
            if (l.cumulativeOwed == last.owed && l.stateRoot == last.stateRoot) return ("STATE_REPLAYED", 0);
            return ("CONFLICTING_STATE", 0);
        }
        if (l.cumulativeOwed < last.owed) return ("OWED_DECREASED", 0);
        uint256 credit = _min(l.cumulativeOwed, l.escrow) - _min(last.owed, l.escrow);
        spent[nf] = true;
        credited[l.channelId] = Credited(true, l.nonce, l.cumulativeOwed, l.stateRoot, l.provider, l.payer, l.escrow);
        return (OK, credit);
    }

    // ---- OmerMinter (IF-F12)

    function openLock(Lock calldata l) external returns (bytes32) {
        if (l.lockId == 0 || l.channelId == 0 || l.provider == 0 || l.payer == 0 || l.lender == 0 || l.payer == l.provider) {
            return "INVALID_INPUT";
        }
        if (locks[l.lockId].exists || channelLocked[l.channelId]) return "DUPLICATE_LOCK";
        locks[l.lockId] = LockState(true, false, l, uint256(l.lenderPrincipal) + l.payerDeposit);
        channelLocked[l.channelId] = true;
        return OK;
    }

    function redeem(bytes32 lockId, Claim calldata cl, bytes32 by) external returns (bytes32, Payouts memory none) {
        LockState storage s = locks[lockId];
        if (!s.exists) return ("UNKNOWN_LOCK", none);
        if (!_open(s)) return ("ALREADY_SETTLED", none);
        if (by != s.lock.provider) return ("UNAUTHORIZED", none);
        (bytes32 code,) = _verifyReceipt(cl);
        if (code != OK) return (code, none);
        code = _bind(s, cl.leaf);
        if (code != OK) return (code, none);
        if (cl.leaf.nonce == 0 || cl.leaf.cumulativeOwed == 0) return ("NOT_SERVED", none);
        return (OK, _settle(s, cl.leaf.cumulativeOwed));
    }

    function reclaim(bytes32 lockId, Claim calldata cl, bytes32 by) external returns (bytes32, Payouts memory none) {
        LockState storage s = locks[lockId];
        if (!s.exists) return ("UNKNOWN_LOCK", none);
        if (!_open(s)) return ("ALREADY_SETTLED", none);
        if (!p.reclaimByAnyone && by != s.lock.payer && by != s.lock.lender && by != s.lock.provider) {
            return ("UNAUTHORIZED", none);
        }
        (bytes32 code, RootCommitment memory c) = _verifyReceipt(cl);
        if (code != OK) return (code, none);
        if (_staleRoot(cl.jobId)) return ("STALE_ROOT", none);
        code = _bind(s, cl.leaf);
        if (code != OK) return (code, none);
        if (!hooks.reclaimEligible(c.checkpointHeight, cl.leaf.finalizedHeight, p.stalenessBlocks, p.challengeWindowBlocks)) {
            return ("TIMEOUT_NOT_REACHED", none);
        }
        return (OK, _settle(s, cl.leaf.cumulativeOwed));
    }

    function _bind(LockState storage s, Leaf calldata l) internal view returns (bytes32) {
        if (l.channelId != s.lock.channelId) return "CHANNEL_MISMATCH";
        if (l.provider != s.lock.provider || l.payer != s.lock.payer) return "PARTY_MISMATCH";
        if (l.escrow != s.escrow) return "ESCROW_MISMATCH";
        return OK;
    }

    function _settle(LockState storage s, uint256 owed) internal returns (Payouts memory) {
        s.settled = true;
        return hooks.payouts(s.escrow, s.lock.lenderPrincipal, owed);
    }

    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    // ---- seams for the Broken* variants

    function _epochTaken(uint64 epoch) internal view virtual returns (bool) {
        return epochUsed[epoch];
    }

    function _epochUnbound(uint64 leafEpoch, uint64 rootEpoch) internal view virtual returns (bool) {
        return leafEpoch != rootEpoch;
    }

    function _nullifierSpent(bytes32 nf) internal view virtual returns (bool) {
        return spent[nf];
    }

    function _staleRoot(bytes32 id) internal view virtual returns (bool) {
        return id != latestJobId;
    }

    function _open(LockState storage s) internal view virtual returns (bool) {
        return !s.settled;
    }
}

// ------------------------------------------------------------------ the mock passes

contract MockVerifierVectorsTest is ReceiptRootVectorsTest {
    function _hooks() internal override returns (IReceiptRootHooks) {
        return new MockReceiptRootHooks();
    }

    function _newHarness() internal override returns (IReceiptSystemHarness) {
        return new MockReceiptSystem();
    }
}

// ------------------------------------------------------------------ deliberately broken verifiers (must fail)

/// Leaf hashed without the 0x00 prefix: leaves and nodes share one domain.
contract BrokenNoLeafPrefix is MockReceiptRootHooks {
    function _leafHash(Leaf memory l) internal view override returns (bytes32) {
        return keccak256(_encode(l));
    }
}

/// abi.encode instead of abi.encodePacked: 32-byte padded fields, wrong leaf bytes.
contract BrokenPaddedEncoding is MockReceiptRootHooks {
    function _encode(Leaf memory l) internal pure override returns (bytes memory) {
        return bytes.concat(
            abi.encode(uint8(1), l.flopGenesis, l.evmChainId, l.poolId, l.channelId, l.provider),
            abi.encode(l.payer, l.cumulativeOwed, l.escrow, l.nonce, l.epoch, l.finalizedHeight, l.stateRoot)
        );
    }
}

/// Commutative (sorted-pair) node hashing: position is not bound, so leaf index is not either.
contract BrokenSortedPairHashing is MockReceiptRootHooks {
    function _node(bytes32 a, bytes32 b) internal pure override returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(bytes1(0x01), a, b)) : keccak256(abi.encodePacked(bytes1(0x01), b, a));
    }
}

/// Bitcoin-style odd-node rule: the last node is hashed with itself (CVE-2012-2459 class).
contract BrokenDuplicateOddNode is MockReceiptRootHooks {
    function _odd(bytes32 h) internal pure override returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x01), h, h));
    }
}

/// Ignores leftover siblings, so a padded proof still passes.
contract BrokenIgnoresLeftoverSiblings is MockReceiptRootHooks {
    function _allConsumed(uint256, uint256) internal pure override returns (bool) {
        return true;
    }
}

/// No `index < leafCount` check: index 14 aliases leaf 6 of a 7-leaf tree.
contract BrokenNoIndexBound is MockReceiptRootHooks {
    function _indexInRange(uint256, uint256) internal pure override returns (bool) {
        return true;
    }
}

/// jobId without the EVM chain id: the same root is valid on every chain.
contract BrokenJobIdWithoutChainId is MockReceiptRootHooks {
    function jobId(RootCommitment calldata c) external pure override returns (bytes32) {
        return keccak256(
            bytes.concat(
                abi.encodePacked(bytes1(0x02), uint8(1), c.flopGenesis, c.hook, c.poolId),
                abi.encodePacked(c.epoch, c.checkpointHeight, c.leafCount, c.keccakRoot, c.blakeRoot)
            )
        );
    }
}

/// Nullifier without the epoch: a channel can be rewarded once ever, not once per epoch.
contract BrokenNullifierWithoutEpoch is MockReceiptRootHooks {
    function nullifier(bytes32 flopGenesis, uint64 evmChainId, bytes32 poolId, bytes32 channelId, uint64)
        external
        pure
        override
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(bytes1(0x03), uint8(1), flopGenesis, evmChainId, poolId, channelId));
    }
}

/// Payer repaid before the lender: wrong seniority.
contract BrokenPayerSeniorToLender is MockReceiptRootHooks {
    function payouts(uint256 escrow, uint256 lenderPrincipal, uint256 owed) external pure override returns (Payouts memory p) {
        p.toProvider = owed < escrow ? owed : escrow;
        uint256 rest = escrow - p.toProvider;
        uint256 deposit = escrow - lenderPrincipal;
        p.toPayer = deposit < rest ? deposit : rest;
        p.toLender = rest - p.toPayer;
        p.overrun = owed - p.toProvider;
        p.lenderShortfall = lenderPrincipal - p.toLender;
    }
}

/// Timeout off by one: refund one block late.
contract BrokenTimeoutExclusive is MockReceiptRootHooks {
    function reclaimEligible(uint64 checkpointHeight, uint64 finalizedHeight, uint64 n, uint64 w)
        external
        pure
        override
        returns (bool)
    {
        return uint256(checkpointHeight) > uint256(finalizedHeight) + n + w;
    }
}

/// AgentRewards without the nullifier set: double-claim in one epoch.
contract BrokenRewardsNoNullifier is MockReceiptSystem {
    function _nullifierSpent(bytes32) internal pure override returns (bool) {
        return false;
    }
}

/// Leaf epoch not bound to the root epoch: cross-epoch replay.
contract BrokenNoEpochBinding is MockReceiptSystem {
    function _epochUnbound(uint64, uint64) internal pure override returns (bool) {
        return false;
    }
}

/// Registry accepts a second root for an epoch: stale or rival roots.
contract BrokenRegistryRootPerEpoch is MockReceiptSystem {
    function _epochTaken(uint64) internal pure override returns (bool) {
        return false;
    }
}

/// Reclaim proven against any accepted root, not the latest: stale-root shortchanging.
contract BrokenReclaimAnyRoot is MockReceiptSystem {
    function _staleRoot(bytes32) internal pure override returns (bool) {
        return false;
    }
}

/// A settled lock can settle again: redeem and reclaim both pay.
contract BrokenSettlesTwice is MockReceiptSystem {
    function _open(LockState storage) internal pure override returns (bool) {
        return true;
    }
}

contract BrokenVerifiersMustFailTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    ReceiptRootVectorRunner internal runner;

    function setUp() public {
        runner = new ReceiptRootVectorRunner(string.concat(vm.projectRoot(), "/../vectors/receipt-root-v1.json"));
    }

    /// Only a vector-mismatch `require` counts as a rejection; a panic or custom error fails the test.
    function _mustFailPure(IReceiptRootHooks h) internal view {
        try runner.runPure(h) {
            revert("broken hooks passed the vectors");
        } catch Error(string memory) {}
    }

    function _mustFailRewards(IReceiptSystemHarness s) internal {
        try runner.runRewards(s, true) {
            revert("broken rewards passed the vectors");
        } catch Error(string memory) {}
    }

    function _mustFailMinter(IReceiptSystemHarness s) internal {
        try runner.runMinter(s, true) {
            revert("broken minter passed the vectors");
        } catch Error(string memory) {}
    }

    function test_noLeafPrefix_isRejected() public {
        _mustFailPure(new BrokenNoLeafPrefix());
    }

    function test_paddedEncoding_isRejected() public {
        _mustFailPure(new BrokenPaddedEncoding());
    }

    function test_sortedPairHashing_isRejected() public {
        _mustFailPure(new BrokenSortedPairHashing());
    }

    function test_duplicateOddNode_isRejected() public {
        _mustFailPure(new BrokenDuplicateOddNode());
    }

    function test_ignoresLeftoverSiblings_isRejected() public {
        _mustFailPure(new BrokenIgnoresLeftoverSiblings());
    }

    function test_noIndexBound_isRejected() public {
        _mustFailPure(new BrokenNoIndexBound());
    }

    function test_jobIdWithoutChainId_isRejected() public {
        _mustFailPure(new BrokenJobIdWithoutChainId());
    }

    function test_nullifierWithoutEpoch_isRejected() public {
        _mustFailPure(new BrokenNullifierWithoutEpoch());
    }

    function test_payerSeniorToLender_isRejected() public {
        _mustFailPure(new BrokenPayerSeniorToLender());
    }

    function test_timeoutExclusive_isRejected() public {
        _mustFailPure(new BrokenTimeoutExclusive());
    }

    function test_rewardsNoNullifier_isRejected() public {
        _mustFailRewards(new BrokenRewardsNoNullifier());
    }

    function test_noEpochBinding_isRejected() public {
        _mustFailRewards(new BrokenNoEpochBinding());
    }

    function test_registryRootPerEpoch_isRejected() public {
        _mustFailRewards(new BrokenRegistryRootPerEpoch());
    }

    function test_reclaimAnyRoot_isRejected() public {
        _mustFailMinter(new BrokenReclaimAnyRoot());
    }

    function test_settlesTwice_isRejected() public {
        _mustFailMinter(new BrokenSettlesTwice());
    }

    /// Guards the guard: the same harness must pass with the unbroken mocks.
    function test_controlPasses() public {
        runner.runPure(new MockReceiptRootHooks());
        runner.runRewards(new MockReceiptSystem(), true);
        runner.runMinter(new MockReceiptSystem(), true);
    }
}
