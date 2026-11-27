// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {FlopReceiptRoot} from "flop-receipt-root/FlopReceiptRoot.sol";
import {AgentRewardsConsumer} from "../src/AgentRewardsConsumer.sol";
import {OmerMinterConsumer} from "../src/OmerMinterConsumer.sol";
import {ReceiptJobHook} from "../src/ReceiptJobHook.sol";
import {UnservedAttestorStub} from "../src/UnservedAttestorStub.sol";
import {MockUnservedAttestor} from "./mocks/MockUnservedAttestor.sol";
import {Base} from "./Base.t.sol";

/// Replays vectors/if-d8-v2.json against the vendored FlopReceiptRoot v0.3.2 and the reference
/// consumers. Every step's revert selector must equal the vector's `selector`.
contract ConsumerVectorsTest is Base {
    ReceiptJobHook hook;
    AgentRewardsConsumer sumRewards;
    AgentRewardsConsumer latestRewards;
    OmerMinterConsumer stubMinter;
    OmerMinterConsumer attestedMinter;
    MockUnservedAttestor attestor;
    uint256 chain;
    string constant P = ".scenario.params";

    function setUp() public {
        _load();
        chain = _u(string.concat(P, ".evmChainId"));
    }

    function _deployAll() internal {
        _deployRoots(uint64(_u(string.concat(P, ".startBlock"))));
        uint256 n;
        while (_has(_at(string.concat(P, ".pools"), n))) ++n;
        ReceiptJobHook.PoolConfig[] memory pools = new ReceiptJobHook.PoolConfig[](n);
        for (uint256 i; i < n; ++i) {
            string memory p = _at(string.concat(P, ".pools"), i);
            pools[i] = ReceiptJobHook.PoolConfig(_b(string.concat(p, ".poolId")), _proof(string.concat(p, ".modelHashes")));
        }
        hook = new ReceiptJobHook(roots, chain, vm.parseJsonAddress(json, string.concat(P, ".poolManager")), pools);
        bytes32 poolId = _b(string.concat(P, ".rewards.poolId"));
        assertEq(_s(string.concat(P, ".rewards.metric")), "minerPaid");
        uint64 window = uint64(_u(string.concat(P, ".rewards.claimWindowEpochs")));
        sumRewards = new AgentRewardsConsumer(
            roots, hook, chain, poolId, AgentRewardsConsumer.DedupeMode.PerLeafSum, AgentRewardsConsumer.RewardMetric.MinerPaid, window
        );
        latestRewards = new AgentRewardsConsumer(
            roots, hook, chain, poolId, AgentRewardsConsumer.DedupeMode.LatestPerChannel, AgentRewardsConsumer.RewardMetric.MinerPaid, window
        );
        attestor = new MockUnservedAttestor(roots.GENESIS());
        uint64 nBlocks = uint64(_u(string.concat(P, ".minter.stalenessBlocks")));
        uint64 wBlocks = uint64(_u(string.concat(P, ".minter.challengeWindowBlocks")));
        assertEq(_s(string.concat(P, ".minter.reclaimPolicy")), "channel-parties");
        stubMinter = new OmerMinterConsumer(
            roots, new UnservedAttestorStub(), chain, nBlocks, wBlocks, OmerMinterConsumer.ReclaimPolicy.ChannelParties
        );
        attestedMinter = new OmerMinterConsumer(roots, attestor, chain, nBlocks, wBlocks, OmerMinterConsumer.ReclaimPolicy.ChannelParties);
    }

    // ---------------------------------------------------------------- static sections

    function test_typehashesAndDomain() public {
        _deployRoots(uint64(_u(string.concat(P, ".startBlock"))));
        assertEq(roots.LEAF_TYPEHASH(), _b(".format.leafTypehash"));
        assertEq(roots.ROOT_TYPEHASH(), _b(".format.rootTypehash"));
        assertEq(roots.domainSeparator(), _b(".format.domain.separator"));
    }

    function test_leaves() public {
        _deployRoots(1);
        for (uint256 i; _has(_at(".leaves", i)); ++i) {
            string memory p = _at(".leaves", i);
            FlopReceiptRoot.Settlement memory s = _settlement(string.concat(p, ".settlement"));
            bytes memory enc = abi.encode(
                roots.LEAF_TYPEHASH(),
                s.genesis,
                s.channelId,
                s.settledBlock,
                s.settledBlockHash,
                s.eventIndex,
                s.agent,
                s.miner,
                s.modelHash,
                s.aggregateGn,
                s.minerPaid,
                s.burned,
                s.escrow
            );
            assertEq(enc, vm.parseJsonBytes(json, string.concat(p, ".encoding")), _s(string.concat(p, ".name")));
            assertEq(roots.leafOf(s), _b(string.concat(p, ".leaf")), _s(string.concat(p, ".name")));
        }
    }

    /// Each tree is rooted in a real FlopReceiptRoot epoch and every member is verified by it.
    function test_treesVerifyOnChain() public {
        uint256 trees;
        for (uint256 t; _has(_at(".trees", t)); ++t) {
            string memory p = _at(".trees", t);
            uint256 snap = vm.snapshotState();
            _deployRoots(1_000);
            uint256 n;
            uint64 maxBlock;
            while (_has(_at(string.concat(p, ".settlements"), n))) {
                uint64 b = _settlement(_at(string.concat(p, ".settlements"), n)).settledBlock;
                if (b > maxBlock) maxBlock = b;
                ++n;
            }
            bytes32 root = _b(string.concat(p, ".root"));
            _submit(FlopReceiptRoot.RootMsg(roots.GENESIS(), 1, 1_000, maxBlock, keccak256("tree head"), uint32(n), root));
            bytes32[] memory leaves = _proof(string.concat(p, ".leaves"));
            for (uint256 i; i < n; ++i) {
                FlopReceiptRoot.Settlement memory s = _settlement(_at(string.concat(p, ".settlements"), i));
                bytes32[] memory proof = _proof(_at(string.concat(p, ".proofs"), i));
                assertEq(roots.leafOf(s), leaves[i]);
                assertEq(_process(leaves[i], proof), root);
                assertTrue(roots.verify(1, s, proof), _s(string.concat(p, ".name")));
            }
            vm.revertToState(snap);
            ++trees;
        }
        assertEq(trees, 9);
    }

    function test_proofCases() public view {
        string memory p = ".proofCases";
        bytes32 l = _b(string.concat(p, ".nodeAsLeaf.left"));
        bytes32 r = _b(string.concat(p, ".nodeAsLeaf.right"));
        assertEq(keccak256(abi.encodePacked(l, r)), _b(string.concat(p, ".nodeAsLeaf.node")));
        assertEq(vm.parseJsonBytes(json, string.concat(p, ".nodeAsLeaf.preimage")), abi.encodePacked(l, r));
        for (uint256 i; _has(_at(string.concat(p, ".cases"), i)); ++i) {
            string memory c = _at(string.concat(p, ".cases"), i);
            bool got = _process(_b(string.concat(c, ".leaf")), _proof(string.concat(c, ".proof"))) == _b(string.concat(c, ".root"));
            assertEq(got, vm.parseJsonBool(json, string.concat(c, ".expect")), _s(string.concat(c, ".name")));
        }
    }

    function test_verifyCases() public {
        uint256 n;
        for (uint256 i; _has(_at(".verifyCases", i)); ++i) {
            string memory c = _at(".verifyCases", i);
            uint256 snap = vm.snapshotState();
            FlopReceiptRoot.RootMsg memory m = _msg(string.concat(c, ".msg"));
            _deployRoots(m.fromBlock);
            assertEq(roots.digest(m), _b(string.concat(c, ".digest")));
            _submit(m);
            bool got = roots.verify(
                uint64(_u(string.concat(c, ".epoch"))), _settlement(string.concat(c, ".settlement")), _proof(string.concat(c, ".proof"))
            );
            assertEq(got, vm.parseJsonBool(json, string.concat(c, ".expect")), _s(string.concat(c, ".name")));
            vm.revertToState(snap);
            ++n;
        }
        assertEq(n, 9);
    }

    function test_hookDataCases() public {
        _deployAll();
        string memory d = ".hookDataCases.decoded";
        FlopReceiptRoot.Settlement memory want = _settlement(string.concat(d, ".settlement"));
        for (uint256 i; _has(_at(".hookDataCases.cases", i)); ++i) {
            string memory c = _at(".hookDataCases.cases", i);
            bytes memory hex_ = vm.parseJsonBytes(json, string.concat(c, ".hex"));
            bytes4 sel = bytes4(vm.parseJsonBytes(json, string.concat(c, ".selector")));
            bytes memory ret = _expect(address(hook), address(this), abi.encodeCall(hook.decodeHookData, (hex_)), sel, _s(string.concat(c, ".name")));
            if (sel == bytes4(0)) {
                (uint64 epoch, FlopReceiptRoot.Settlement memory s, bytes32[] memory proof) =
                    abi.decode(ret, (uint64, FlopReceiptRoot.Settlement, bytes32[]));
                assertEq(epoch, _u(string.concat(d, ".epoch")));
                assertEq(keccak256(abi.encode(s)), keccak256(abi.encode(want)));
                assertEq(proof, _proof(string.concat(d, ".proof")));
            }
        }
    }

    function test_jobIdCases() public {
        _deployAll();
        assertEq(hook.JOB_ID_TAG(), keccak256("FlopReceiptRoot.jobId.v1"));
        assertEq(hook.JOB_ID_TAG(), roots.JOB_ID_TAG());
        assertEq(hook.JOB_ID_TAG(), bytes32(0x748fa4722b652359047a16941d7e978a83dcfab3a169bea48a5a663e7d31bd14));
        assertEq(hook.JOB_ID_TAG(), _b(".jobIdCases.tag"));
        assertEq(_s(".jobIdCases.tagString"), "FlopReceiptRoot.jobId.v1");
        FlopReceiptRoot.Settlement memory base = _settlement(".jobIdCases.base.settlement");
        assertEq(hook.jobIdOf(base), _b(".jobIdCases.base.jobId"));
        assertEq(hook.jobIdOf(base), roots.jobIdOf(base));
        assertEq(roots.leafOf(base), _b(".jobIdCases.base.leaf"));
        assertEq(
            hook.jobIdOf(base),
            keccak256(abi.encode(hook.JOB_ID_TAG(), base.genesis, base.channelId, base.settledBlock, base.eventIndex))
        );
        uint256 n;
        for (uint256 i; _has(_at(".jobIdCases.cases", i)); ++i) {
            string memory c = _at(".jobIdCases.cases", i);
            FlopReceiptRoot.Settlement memory a = _settlement(string.concat(c, ".a"));
            FlopReceiptRoot.Settlement memory b = _settlement(string.concat(c, ".b"));
            bytes32 ja = hook.jobIdOf(a);
            bytes32 jb = hook.jobIdOf(b);
            assertEq(ja, roots.jobIdOf(a), _s(string.concat(c, ".name")));
            assertEq(jb, roots.jobIdOf(b), _s(string.concat(c, ".name")));
            assertEq(ja, _b(string.concat(c, ".jobIdA")), _s(string.concat(c, ".name")));
            assertEq(jb, _b(string.concat(c, ".jobIdB")), _s(string.concat(c, ".name")));
            assertEq(roots.leafOf(a), _b(string.concat(c, ".leafA")));
            assertEq(roots.leafOf(b), _b(string.concat(c, ".leafB")));
            if (vm.parseJsonBool(json, string.concat(c, ".expectEqual"))) {
                assertEq(ja, jb, _s(string.concat(c, ".name")));
                assertTrue(roots.leafOf(a) != roots.leafOf(b), _s(string.concat(c, ".name")));
            } else {
                assertTrue(ja != jb, _s(string.concat(c, ".name")));
            }
            ++n;
        }
        assertEq(n, 5);
    }

    /// Every epoch item's proof verifies in the real contract once the epochs are submitted in order.
    function test_epochsVerifyOnChain() public {
        _deployRoots(uint64(_u(string.concat(P, ".startBlock"))));
        uint256 items;
        for (uint256 e; _has(_at(".scenario.epochs", e)); ++e) {
            string memory p = _at(".scenario.epochs", e);
            FlopReceiptRoot.RootMsg memory m = _msg(string.concat(p, ".msg"));
            _submit(m);
            for (uint256 i; _has(_at(string.concat(p, ".items"), i)); ++i) {
                string memory it = _at(string.concat(p, ".items"), i);
                FlopReceiptRoot.Settlement memory s = _settlement(string.concat(it, ".settlement"));
                assertEq(roots.leafOf(s), _b(string.concat(it, ".leaf")));
                assertTrue(roots.verify(m.epoch, s, _proof(string.concat(it, ".proof"))));
                ++items;
            }
        }
        assertEq(roots.lastEpoch(), 4);
        assertEq(items, 20);
    }

    // ---------------------------------------------------------------- scenario

    function test_scenario() public {
        _deployAll();
        uint256 steps;
        for (uint256 i; _has(_at(".scenario.steps", i)); ++i) {
            string memory st = _at(".scenario.steps", i);
            string memory op = _s(string.concat(st, ".op"));
            string memory what = string.concat("step ", vm.toString(i), " (", _s(string.concat(st, ".note")), ")");
            if (_eq(op, "submit")) _stepSubmit(st, what);
            else if (_eq(op, "freeze")) _stepFreeze(st, what);
            else if (_eq(op, "tag")) _stepTag(st, what);
            else if (_eq(op, "claim")) _stepClaim(st, what);
            else if (_eq(op, "open")) _stepOpen(st, what);
            else if (_eq(op, "setUnserved")) _stepSetUnserved(st);
            else if (_eq(op, "redeem")) _stepRedeem(st, what);
            else if (_eq(op, "reclaim")) _stepReclaim(st, what);
            else revert(string.concat("unknown op ", op));
            vm.chainId(chain);
            ++steps;
        }
        assertEq(steps, 109);
        assertEq(sumRewards.totalCredited(), _u(".scenario.totals.sum"));
        assertEq(latestRewards.totalCredited(), _u(".scenario.totals.latest"));
    }

    function _sel(string memory st) internal view returns (bytes4) {
        return bytes4(vm.parseJsonBytes(json, string.concat(st, ".selector")));
    }

    function _withChain(string memory st) internal {
        vm.chainId(_u(string.concat(st, ".chainId")));
    }

    function _stepSubmit(string memory st, string memory what) internal {
        FlopReceiptRoot.RootMsg memory m = _msg(string.concat(st, ".msg"));
        assertEq(roots.digest(m), _b(string.concat(st, ".digest")), what);
        uint256 n = vm.parseJsonBool(json, string.concat(st, ".quorum")) ? 2 : 1;
        _expect(address(roots), address(this), abi.encodeCall(roots.submit, (m, _sign(m, n))), _sel(st), what);
    }

    function _stepFreeze(string memory st, string memory what) internal {
        FlopReceiptRoot.RootMsg memory a = _msg(string.concat(st, ".msgA"));
        FlopReceiptRoot.RootMsg memory b = _msg(string.concat(st, ".msgB"));
        _expect(address(roots), address(this), abi.encodeCall(roots.freeze, (a, _sign(a, 2), b, _sign(b, 2))), _sel(st), what);
    }

    function _stepTag(string memory st, string memory what) internal {
        FlopReceiptRoot.Settlement memory s = _settlement(string.concat(st, ".settlement"));
        bytes32[] memory proof = _proof(string.concat(st, ".proof"));
        uint64 epoch = uint64(_u(string.concat(st, ".epoch")));
        bytes memory hd = vm.parseJsonBytes(json, string.concat(st, ".hookData"));
        assertEq(roots.leafOf(s), _b(string.concat(st, ".leaf")), what);
        if (vm.parseJsonBool(json, string.concat(st, ".canonical"))) assertEq(abi.encode(epoch, s, proof), hd, what);
        _withChain(st);
        bytes4 sel = _sel(st);
        bytes memory ret = _expect(
            address(hook),
            vm.parseJsonAddress(json, string.concat(st, ".caller")),
            abi.encodeCall(hook.tag, (_b(string.concat(st, ".poolId")), hd)),
            sel,
            what
        );
        if (sel == bytes4(0)) assertEq(abi.decode(ret, (bytes32)), _b(string.concat(st, ".jobId")), what);
    }

    function _stepClaim(string memory st, string memory what) internal {
        AgentRewardsConsumer r = _eq(_s(string.concat(st, ".consumer")), "sum") ? sumRewards : latestRewards;
        FlopReceiptRoot.Settlement memory s = _settlement(string.concat(st, ".settlement"));
        assertEq(roots.leafOf(s), _b(string.concat(st, ".leaf")), what);
        _withChain(st);
        bytes4 sel = _sel(st);
        bytes memory ret = _expect(
            address(r),
            address(this),
            abi.encodeCall(r.claim, (uint64(_u(string.concat(st, ".epoch"))), s, _proof(string.concat(st, ".proof")))),
            sel,
            what
        );
        if (sel == bytes4(0)) {
            (uint256 credit, uint256 total) = abi.decode(ret, (uint256, uint256));
            assertEq(credit, _u(string.concat(st, ".credit")), what);
            assertEq(total, _u(string.concat(st, ".channelEpochTotal")), what);
        }
    }

    function _minter(string memory st) internal view returns (OmerMinterConsumer) {
        return _eq(_s(string.concat(st, ".consumer")), "stub") ? stubMinter : attestedMinter;
    }

    function _lock(string memory p) internal view returns (OmerMinterConsumer.LockInput memory l) {
        l.lockId = _b(string.concat(p, ".lockId"));
        l.channelId = _b(string.concat(p, ".channelId"));
        l.agent = _b(string.concat(p, ".agent"));
        l.miner = _b(string.concat(p, ".miner"));
        l.modelHash = _b(string.concat(p, ".modelHash"));
        l.payer = vm.parseJsonAddress(json, string.concat(p, ".payer"));
        l.provider = vm.parseJsonAddress(json, string.concat(p, ".provider"));
        l.lender = vm.parseJsonAddress(json, string.concat(p, ".lender"));
        l.lenderPrincipal = uint128(_u(string.concat(p, ".lenderPrincipal")));
        l.payerDeposit = uint128(_u(string.concat(p, ".payerDeposit")));
        l.omerPerGnNum = uint128(_u(string.concat(p, ".omerPerGnNum")));
        l.omerPerGnDen = uint128(_u(string.concat(p, ".omerPerGnDen")));
        l.minFlopBlock = uint128(_u(string.concat(p, ".minFlopBlock")));
    }

    function _stepOpen(string memory st, string memory what) internal {
        OmerMinterConsumer m = _minter(st);
        _withChain(st);
        _expect(address(m), address(this), abi.encodeCall(m.open, (_lock(string.concat(st, ".lock")))), _sel(st), what);
    }

    function _stepSetUnserved(string memory st) internal {
        attestor.set(
            _b(string.concat(st, ".channelId")),
            uint64(_u(string.concat(st, ".epoch"))),
            uint64(_u(string.concat(st, ".lastFinalizedHeight"))),
            uint128(_u(string.concat(st, ".owed")))
        );
    }

    function _checkPayout(string memory st, bytes memory ret, string memory what) internal view {
        OmerMinterConsumer.Payout memory p = abi.decode(ret, (OmerMinterConsumer.Payout));
        string memory k = string.concat(st, ".payouts");
        assertEq(p.owed, _u(_at(k, 0)), what);
        assertEq(p.toProvider, _u(_at(k, 1)), what);
        assertEq(p.toLender, _u(_at(k, 2)), what);
        assertEq(p.toPayer, _u(_at(k, 3)), what);
        assertEq(p.overrun, _u(_at(k, 4)), what);
        assertEq(p.lenderShortfall, _u(_at(k, 5)), what);
    }

    function _stepRedeem(string memory st, string memory what) internal {
        OmerMinterConsumer m = _minter(st);
        FlopReceiptRoot.Settlement memory s = _settlement(string.concat(st, ".settlement"));
        assertEq(roots.leafOf(s), _b(string.concat(st, ".leaf")), what);
        bytes memory data = abi.encodeCall(
            m.redeem, (_b(string.concat(st, ".lockId")), uint64(_u(string.concat(st, ".epoch"))), s, _proof(string.concat(st, ".proof")))
        );
        _withChain(st);
        bytes4 sel = _sel(st);
        bytes memory ret = _expect(address(m), vm.parseJsonAddress(json, string.concat(st, ".caller")), data, sel, what);
        if (sel == bytes4(0)) _checkPayout(st, ret, what);
    }

    function _stepReclaim(string memory st, string memory what) internal {
        OmerMinterConsumer m = _minter(st);
        bytes memory data = abi.encodeCall(
            m.reclaim,
            (_b(string.concat(st, ".lockId")), uint64(_u(string.concat(st, ".epoch"))), vm.parseJsonBytes(json, string.concat(st, ".attestation")))
        );
        _withChain(st);
        bytes4 sel = _sel(st);
        bytes memory ret = _expect(address(m), vm.parseJsonAddress(json, string.concat(st, ".caller")), data, sel, what);
        if (sel == bytes4(0)) _checkPayout(st, ret, what);
    }
}
