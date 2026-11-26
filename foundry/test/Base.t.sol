// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {FlopReceiptRoot} from "flop-receipt-root/FlopReceiptRoot.sol";

/// Shared helpers: vector readers, the real FlopReceiptRoot at the vectors' address, and quorum signing
/// with attester keys derived at runtime from a public label (test-only, never funded).
abstract contract Base is Test {
    string internal json;
    FlopReceiptRoot internal roots;
    uint256[3] internal keys;
    address[] internal attesters;

    function _load() internal {
        json = vm.readFile("../vectors/if-d8-v2.json");
        for (uint256 i; i < 3; ++i) {
            keys[i] = uint256(keccak256(bytes(string.concat("inferencefi-receipt-root test attester ", vm.toString(i)))));
        }
        // FlopReceiptRoot wants signers in ascending address order.
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
        delete attesters;
        for (uint256 i; i < 3; ++i) attesters.push(vm.addr(keys[i]));
        vm.chainId(_u(".scenario.params.evmChainId"));
    }

    function _deployRoots(uint64 startBlock) internal {
        address at = vm.parseJsonAddress(json, ".scenario.params.rootsAddress");
        deployCodeTo(
            "FlopReceiptRoot.sol:FlopReceiptRoot",
            abi.encode(vm.parseJsonBytes32(json, ".scenario.params.genesis"), startBlock, attesters, uint256(2)),
            at
        );
        roots = FlopReceiptRoot(at);
    }

    // ---------------------------------------------------------------- readers

    function _u(string memory k) internal view returns (uint256) {
        return vm.parseUint(vm.parseJsonString(json, k));
    }

    function _b(string memory k) internal view returns (bytes32) {
        return vm.parseJsonBytes32(json, k);
    }

    function _s(string memory k) internal view returns (string memory) {
        return vm.parseJsonString(json, k);
    }

    function _has(string memory k) internal view returns (bool) {
        return vm.keyExistsJson(json, k);
    }

    function _at(string memory k, uint256 i) internal pure returns (string memory) {
        return string.concat(k, "[", vm.toString(i), "]");
    }

    function _eq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    function _settlement(string memory p) internal view returns (FlopReceiptRoot.Settlement memory s) {
        s.genesis = _b(string.concat(p, ".genesis"));
        s.channelId = _b(string.concat(p, ".channelId"));
        s.settledBlock = uint64(_u(string.concat(p, ".settledBlock")));
        s.settledBlockHash = _b(string.concat(p, ".settledBlockHash"));
        s.eventIndex = uint32(_u(string.concat(p, ".eventIndex")));
        s.agent = _b(string.concat(p, ".agent"));
        s.miner = _b(string.concat(p, ".miner"));
        s.modelHash = _b(string.concat(p, ".modelHash"));
        s.aggregateGn = uint128(_u(string.concat(p, ".aggregateGn")));
        s.minerPaid = uint128(_u(string.concat(p, ".minerPaid")));
        s.burned = uint128(_u(string.concat(p, ".burned")));
        s.escrow = uint128(_u(string.concat(p, ".escrow")));
    }

    function _msg(string memory p) internal view returns (FlopReceiptRoot.RootMsg memory m) {
        m.genesis = _b(string.concat(p, ".genesis"));
        m.epoch = uint64(_u(string.concat(p, ".epoch")));
        m.fromBlock = uint64(_u(string.concat(p, ".fromBlock")));
        m.toBlock = uint64(_u(string.concat(p, ".toBlock")));
        m.toBlockHash = _b(string.concat(p, ".toBlockHash"));
        m.count = uint32(_u(string.concat(p, ".count")));
        m.root = _b(string.concat(p, ".root"));
    }

    function _proof(string memory p) internal view returns (bytes32[] memory) {
        return vm.parseJsonBytes32Array(json, p);
    }

    // ---------------------------------------------------------------- signing and calls

    /// The first `n` attesters sign `m` (ascending addresses).
    function _sign(FlopReceiptRoot.RootMsg memory m, uint256 n) internal view returns (bytes[] memory sigs) {
        bytes32 d = roots.digest(m);
        sigs = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], d);
            sigs[i] = abi.encodePacked(r, s, v);
        }
    }

    function _submit(FlopReceiptRoot.RootMsg memory m) internal {
        roots.submit(m, _sign(m, 2));
    }

    /// Call `target` and hold the outcome to `selector` (zero means success). Returns the return data.
    function _expect(address target, address caller, bytes memory data, bytes4 selector, string memory what)
        internal
        returns (bytes memory ret)
    {
        bool ok;
        vm.prank(caller);
        (ok, ret) = target.call(data);
        if (selector == bytes4(0)) {
            if (!ok) {
                emit log_named_bytes("unexpected revert", ret);
                fail();
            }
            assertTrue(ok, what);
        } else {
            assertFalse(ok, what);
            assertGe(ret.length, 4, what);
            assertEq(bytes4(ret), selector, what);
        }
    }

    /// OpenZeppelin-style sorted-pair proof processing, written from the published rule.
    function _process(bytes32 leaf, bytes32[] memory proof) internal pure returns (bytes32 h) {
        h = leaf;
        for (uint256 i; i < proof.length; ++i) {
            bytes32 p = proof[i];
            h = h <= p ? keccak256(abi.encodePacked(h, p)) : keccak256(abi.encodePacked(p, h));
        }
    }
}
