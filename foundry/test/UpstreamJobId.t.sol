// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {FlopReceiptRoot} from "flop-receipt-root/FlopReceiptRoot.sol";
import {ReceiptJobHook} from "../src/ReceiptJobHook.sol";

/// @dev Replays the six published flop-receipt-root jobId vectors against
///      FlopReceiptRoot.jobIdOf, ReceiptJobHook.jobIdOf, and the ABI encoding
///      itself. Dummy leaf fields (hash, keys, amounts) are unused by the
///      event-key encoding.
contract UpstreamJobIdTest is Test {
    FlopReceiptRoot internal roots;
    ReceiptJobHook internal hook;

    function setUp() public {
        address[] memory attesters = new address[](1);
        attesters[0] = address(this);
        roots = new FlopReceiptRoot(bytes32(uint256(1)), 1, attesters, 1);
        bytes32 poolId = bytes32(uint256(2));
        bytes32[] memory models = new bytes32[](1);
        models[0] = bytes32(uint256(3));
        ReceiptJobHook.PoolConfig[] memory pools = new ReceiptJobHook.PoolConfig[](1);
        pools[0] = ReceiptJobHook.PoolConfig(poolId, models);
        hook = new ReceiptJobHook(roots, block.chainid, address(this), pools);
    }

    function test_publishedJobIdVectors() public view {
        string memory raw = vm.readFile(
            string.concat(vm.projectRoot(), "/../vendor/flop-receipt-root/test/fixtures/jobid_vectors.json")
        );
        assertEq(hook.JOB_ID_TAG(), roots.JOB_ID_TAG());
        assertEq(hook.JOB_ID_TAG(), vm.parseJsonBytes32(raw, ".tag"));
        assertEq(hook.JOB_ID_TAG(), bytes32(0x748fa4722b652359047a16941d7e978a83dcfab3a169bea48a5a663e7d31bd14));
        assertEq(vm.parseJsonString(raw, ".tagString"), "FlopReceiptRoot.jobId.v1");

        uint256 n = vm.parseJsonUint(raw, ".count");
        assertEq(n, 6);
        for (uint256 i; i < n; ++i) {
            string memory p = string.concat(".cases[", vm.toString(i), "]");
            FlopReceiptRoot.Settlement memory s;
            s.genesis = vm.parseJsonBytes32(raw, string.concat(p, ".genesis"));
            s.channelId = vm.parseJsonBytes32(raw, string.concat(p, ".channelId"));
            s.settledBlock = uint64(vm.parseJsonUint(raw, string.concat(p, ".settledBlock")));
            s.eventIndex = uint32(vm.parseJsonUint(raw, string.concat(p, ".eventIndex")));
            bytes32 want = vm.parseJsonBytes32(raw, string.concat(p, ".jobId"));
            string memory name = vm.parseJsonString(raw, string.concat(p, ".name"));
            bytes32 encoded = keccak256(
                abi.encode(roots.JOB_ID_TAG(), s.genesis, s.channelId, s.settledBlock, s.eventIndex)
            );
            assertEq(encoded, want, name);
            assertEq(roots.jobIdOf(s), want, name);
            assertEq(hook.jobIdOf(s), want, name);
        }
    }
}
