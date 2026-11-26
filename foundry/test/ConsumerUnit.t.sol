// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {FlopReceiptRoot} from "flop-receipt-root/FlopReceiptRoot.sol";
import {AgentRewardsConsumer} from "../src/AgentRewardsConsumer.sol";
import {OmerMinterConsumer} from "../src/OmerMinterConsumer.sol";
import {ReceiptJobHook} from "../src/ReceiptJobHook.sol";
import {UnservedAttestorStub} from "../src/UnservedAttestorStub.sol";
import {MockUnservedAttestor} from "./mocks/MockUnservedAttestor.sol";
import {Base} from "./Base.t.sol";

/// Property tests of the consumer rules against the real FlopReceiptRoot, independent of the vectors.
contract ConsumerUnitTest is Base {
    uint64 constant N = 100;
    uint64 constant W = 20;
    bytes32 constant POOL = keccak256("unit/pool");
    bytes32 constant MODEL = keccak256("unit/model");
    address constant MANAGER = address(0xA11CE);
    address constant PAYER = address(0xBA1);
    address constant PROVIDER = address(0xB0B);
    address constant LENDER = address(0x1E4D);

    ReceiptJobHook hook;
    MockUnservedAttestor attestor;
    OmerMinterConsumer minter;

    function setUp() public {
        _load();
        _deployRoots(1);
        bytes32[] memory models = new bytes32[](1);
        models[0] = MODEL;
        ReceiptJobHook.PoolConfig[] memory pools = new ReceiptJobHook.PoolConfig[](1);
        pools[0] = ReceiptJobHook.PoolConfig(POOL, models);
        hook = new ReceiptJobHook(roots, block.chainid, MANAGER, pools);
        attestor = new MockUnservedAttestor(roots.GENESIS());
        minter = new OmerMinterConsumer(roots, attestor, block.chainid, N, W, OmerMinterConsumer.ReclaimPolicy.ChannelParties);
    }

    function _settle(uint256 ch, uint64 block_, uint32 idx, uint128 gn, uint128 paid)
        internal
        view
        returns (FlopReceiptRoot.Settlement memory s)
    {
        s.genesis = roots.GENESIS();
        s.channelId = keccak256(abi.encode("unit/channel", ch));
        s.settledBlock = block_;
        s.settledBlockHash = keccak256(abi.encode("unit/block", block_));
        s.eventIndex = idx;
        s.agent = keccak256(abi.encode("unit/agent", ch));
        s.miner = keccak256(abi.encode("unit/miner", ch));
        s.modelHash = MODEL;
        s.aggregateGn = gn;
        s.minerPaid = paid;
        s.escrow = 1;
    }

    /// Submits the next epoch of `len` blocks holding `a` and `b` (2-leaf tree) or `a` alone.
    function _epoch(uint64 len, FlopReceiptRoot.Settlement memory a, FlopReceiptRoot.Settlement memory b, bool two)
        internal
        returns (uint64 epoch, bytes32[] memory pa, bytes32[] memory pb)
    {
        bytes32 la = roots.leafOf(a);
        bytes32 lb = roots.leafOf(b);
        bytes32 root = la;
        pa = new bytes32[](two ? 1 : 0);
        pb = new bytes32[](1);
        pb[0] = la;
        if (two) {
            pa[0] = lb;
            root = la <= lb ? keccak256(abi.encodePacked(la, lb)) : keccak256(abi.encodePacked(lb, la));
        }
        uint64 from = roots.nextFromBlock();
        epoch = roots.lastEpoch() + 1;
        _submit(FlopReceiptRoot.RootMsg(roots.GENESIS(), epoch, from, from + len - 1, keccak256("head"), two ? 2 : 1, root));
    }

    function _emptyEpoch(uint64 len) internal returns (uint64 epoch) {
        uint64 from = roots.nextFromBlock();
        epoch = roots.lastEpoch() + 1;
        _submit(FlopReceiptRoot.RootMsg(roots.GENESIS(), epoch, from, from + len - 1, keccak256("head"), 0, bytes32(0)));
    }

    function _lock(bytes32 channelId, uint128 lp, uint128 dep, uint128 num, uint128 den)
        internal
        view
        returns (OmerMinterConsumer.LockInput memory l)
    {
        uint256 ch = uint256(channelId) == uint256(_settle(1, 1, 0, 0, 0).channelId) ? 1 : 2;
        l = OmerMinterConsumer.LockInput({
            lockId: keccak256(abi.encode("unit/lock", channelId)),
            channelId: channelId,
            agent: keccak256(abi.encode("unit/agent", ch)),
            miner: keccak256(abi.encode("unit/miner", ch)),
            modelHash: MODEL,
            payer: PAYER,
            provider: PROVIDER,
            lender: LENDER,
            lenderPrincipal: lp,
            payerDeposit: dep,
            omerPerGnNum: num,
            omerPerGnDen: den,
            minFlopBlock: 1
        });
    }

    // ---------------------------------------------------------------- minter

    /// N + W: a reclaim against the latest root lands iff its checkpoint is at or past h + N + W.
    function testFuzz_reclaimOpensExactlyAtNPlusW(uint64 h, uint64 len) public {
        h = uint64(bound(h, 0, 10_000));
        len = uint64(bound(len, 1, 20_000));
        OmerMinterConsumer.LockInput memory l = _lock(_settle(1, 1, 0, 0, 0).channelId, 600, 400, 1, 1);
        minter.open(l);
        uint64 e = _emptyEpoch(len);
        attestor.set(l.channelId, e, h, 0);
        vm.prank(LENDER);
        (bool ok, bytes memory ret) = address(minter).call(abi.encodeCall(minter.reclaim, (l.lockId, e, "")));
        if (uint256(len) >= uint256(h) + N + W) {
            assertTrue(ok);
            OmerMinterConsumer.Payout memory p = abi.decode(ret, (OmerMinterConsumer.Payout));
            assertEq(p.toLender, 600);
            assertEq(p.toPayer, 400);
        } else {
            assertEq(bytes4(ret), OmerMinterConsumer.TimeoutNotReached.selector);
        }
    }

    /// TCLK: past the timeout a served redeem still wins until a reclaim is included; then the lock is final.
    function test_servedRedeemWinsPastTimeoutThenFinal() public {
        FlopReceiptRoot.Settlement memory s = _settle(1, 1, 0, 3, 0);
        OmerMinterConsumer.LockInput memory l = _lock(s.channelId, 600, 400, 1, 1);
        minter.open(l);
        (, bytes32[] memory pa,) = _epoch(10, s, s, false);
        uint64 e2 = _emptyEpoch(1_000);
        attestor.set(l.channelId, e2, 0, 0);
        vm.prank(PROVIDER);
        OmerMinterConsumer.Payout memory p = minter.redeem(l.lockId, 1, s, pa);
        assertEq(p.toProvider, 3);
        vm.prank(LENDER);
        vm.expectRevert(OmerMinterConsumer.AlreadySettled.selector);
        minter.reclaim(l.lockId, e2, "");
        vm.prank(PROVIDER);
        vm.expectRevert(OmerMinterConsumer.AlreadySettled.selector);
        minter.redeem(l.lockId, 1, s, pa);
    }

    /// owed = floor(aggregateGn * num / den); the waterfall conserves escrow.
    function testFuzz_redeemPaysTheWaterfall(uint128 gn, uint128 num, uint128 den, uint128 lp, uint128 dep) public {
        gn = uint128(bound(gn, 1, type(uint64).max));
        num = uint128(bound(num, 0, type(uint64).max));
        den = uint128(bound(den, 1, type(uint64).max));
        lp = uint128(bound(lp, 0, type(uint96).max));
        dep = uint128(bound(dep, 0, type(uint96).max));
        FlopReceiptRoot.Settlement memory s = _settle(1, 1, 0, gn, 0);
        OmerMinterConsumer.LockInput memory l = _lock(s.channelId, lp, dep, num, den);
        minter.open(l);
        (, bytes32[] memory pa,) = _epoch(10, s, s, false);
        vm.prank(PROVIDER);
        OmerMinterConsumer.Payout memory p = minter.redeem(l.lockId, 1, s, pa);
        uint256 owed = uint256(gn) * num / den;
        assertEq(p.owed, owed);
        assertEq(p.toProvider + p.toLender + p.toPayer, uint256(lp) + dep);
        assertEq(p.toProvider + p.overrun, owed);
        assertEq(p.toLender + p.lenderShortfall, lp);
    }

    function testFuzz_stubFailsEveryReclaim(uint64 len, bytes calldata attestation) public {
        len = uint64(bound(len, 1, 1_000_000));
        OmerMinterConsumer stubbed =
            new OmerMinterConsumer(roots, new UnservedAttestorStub(), block.chainid, N, W, OmerMinterConsumer.ReclaimPolicy.Anyone);
        OmerMinterConsumer.LockInput memory l = _lock(_settle(1, 1, 0, 0, 0).channelId, 1, 1, 1, 1);
        stubbed.open(l);
        uint64 e = _emptyEpoch(len);
        vm.expectRevert(UnservedAttestorStub.UnservedProofUnavailable.selector);
        stubbed.reclaim(l.lockId, e, attestation);
        assertEq(uint8(stubbed.status(l.lockId)), uint8(OmerMinterConsumer.Status.Locked));
    }

    // ---------------------------------------------------------------- hook and rewards

    function testFuzz_hookDataIsCanonical(uint64 epoch, uint8 n, bytes calldata tail) public {
        vm.assume(tail.length > 0 && tail.length <= 96);
        bytes32[] memory proof = new bytes32[](n % 8);
        for (uint256 i; i < proof.length; ++i) proof[i] = keccak256(abi.encode(i));
        FlopReceiptRoot.Settlement memory s = _settle(1, 1, 0, 1, 1);
        bytes memory hd = abi.encode(epoch, s, proof);
        (uint64 e,, bytes32[] memory p) = hook.decodeHookData(hd);
        assertEq(e, epoch);
        assertEq(p, proof);
        vm.expectRevert(ReceiptJobHook.BadHookData.selector);
        hook.decodeHookData(bytes.concat(hd, tail));
    }

    function _rewards(AgentRewardsConsumer.DedupeMode mode) internal returns (AgentRewardsConsumer) {
        return new AgentRewardsConsumer(roots, hook, block.chainid, POOL, mode, AgentRewardsConsumer.RewardMetric.MinerPaid, 10);
    }

    /// One credit per leaf hash, in both modes, whatever the claim order.
    function testFuzz_eachLeafCreditsOnce(uint128 p1, uint128 p2, bool reverseOrder, bool latestMode) public {
        p1 = uint128(bound(p1, 0, type(uint64).max));
        p2 = uint128(bound(p2, p1, type(uint64).max));
        FlopReceiptRoot.Settlement memory a = _settle(1, 5, 0, 1, p1);
        FlopReceiptRoot.Settlement memory b = _settle(1, 6, 0, 1, p2);
        (uint64 e, bytes32[] memory pa, bytes32[] memory pb) = _epoch(10, a, b, true);
        vm.startPrank(MANAGER);
        hook.tag(POOL, abi.encode(e, a, pa));
        hook.tag(POOL, abi.encode(e, b, pb));
        vm.stopPrank();
        AgentRewardsConsumer r =
            _rewards(latestMode ? AgentRewardsConsumer.DedupeMode.LatestPerChannel : AgentRewardsConsumer.DedupeMode.PerLeafSum);
        if (reverseOrder) {
            r.claim(e, b, pb);
            if (latestMode) vm.expectRevert(AgentRewardsConsumer.StaleLeaf.selector);
            try r.claim(e, a, pa) {} catch {}
        } else {
            r.claim(e, a, pa);
            r.claim(e, b, pb);
        }
        vm.expectRevert(AgentRewardsConsumer.LeafSpent.selector);
        r.claim(e, b, pb);
        uint256 want = latestMode ? p2 : uint256(p1) + p2;
        assertEq(r.totalCredited(), want);
        assertEq(r.channelEpochTotal(a.channelId, e), want);
    }

    function test_jobBelongsToTheFirstPool() public {
        bytes32[] memory models = new bytes32[](1);
        models[0] = MODEL;
        ReceiptJobHook.PoolConfig[] memory pools = new ReceiptJobHook.PoolConfig[](2);
        pools[0] = ReceiptJobHook.PoolConfig(POOL, models);
        pools[1] = ReceiptJobHook.PoolConfig(keccak256("unit/pool-2"), models);
        ReceiptJobHook h2 = new ReceiptJobHook(roots, block.chainid, MANAGER, pools);
        FlopReceiptRoot.Settlement memory a = _settle(1, 5, 0, 1, 1);
        (uint64 e, bytes32[] memory pa,) = _epoch(10, a, a, false);
        vm.startPrank(MANAGER);
        assertEq(h2.tag(pools[1].poolId, abi.encode(e, a, pa)), h2.jobIdOf(a));
        vm.expectRevert(ReceiptJobHook.JobBoundElsewhere.selector);
        h2.tag(POOL, abi.encode(e, a, pa));
        vm.stopPrank();
        AgentRewardsConsumer r =
            new AgentRewardsConsumer(roots, h2, block.chainid, POOL, AgentRewardsConsumer.DedupeMode.PerLeafSum, AgentRewardsConsumer.RewardMetric.MinerPaid, 10);
        vm.expectRevert(AgentRewardsConsumer.NotBoundToPool.selector);
        r.claim(e, a, pa);
    }

    function test_rewardsRefuseAHookOnAnotherChain() public {
        vm.expectRevert(AgentRewardsConsumer.BadConfig.selector);
        new AgentRewardsConsumer(roots, hook, block.chainid + 1, POOL, AgentRewardsConsumer.DedupeMode.PerLeafSum, AgentRewardsConsumer.RewardMetric.MinerPaid, 1);
    }
}
