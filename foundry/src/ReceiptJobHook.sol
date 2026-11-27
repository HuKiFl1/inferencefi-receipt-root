// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {FlopReceiptRoot} from "flop-receipt-root/FlopReceiptRoot.sol";

/// @title ReceiptJobHook (reference, IF-D8)
/// @notice The jobId mapping of an Inference Finance swap hook on top of FlopReceiptRoot 19042c3.
///         A swap's hookData is `abi.encode(uint64 epoch, Settlement s, bytes32[] proof)`.
///         The jobId is the event key `keccak256(abi.encode(TAG, genesis, channelId, settledBlock, eventIndex))`
///         with `TAG = keccak256("FlopReceiptRoot.jobId.v1")` (same constant as FlopReceiptRoot.JOB_ID_TAG)
///         and the field widths (bytes32, bytes32, uint64, uint32). `FlopReceiptRoot.leafOf(s)` stays the proof input.
///         The leaf names no pool or EVM chain, so the binding lives here: the first pool to tag
///         a jobId owns it on this chain.
/// @dev `tag` is the body a real v4 `beforeSwap` would run; the PoolManager plumbing is left out.
///      Reference only: not audited, not deployed.
contract ReceiptJobHook {
    struct PoolConfig {
        bytes32 poolId;
        bytes32[] modelHashes;
    }

    /// @dev Same value as FlopReceiptRoot.JOB_ID_TAG: keccak256 of the UTF-8 bytes, not ABI-encoded.
    bytes32 public constant JOB_ID_TAG = keccak256("FlopReceiptRoot.jobId.v1");

    FlopReceiptRoot public immutable ROOTS;
    uint256 public immutable EVM_CHAIN_ID;
    address public immutable POOL_MANAGER;

    mapping(bytes32 poolId => bool) public isPool;
    mapping(bytes32 poolId => mapping(bytes32 modelHash => bool)) public poolServesModel;
    mapping(bytes32 jobId => bytes32 poolId) public poolOf;
    mapping(bytes32 jobId => uint64 epoch) public epochOf;

    event JobTagged(bytes32 indexed jobId, bytes32 indexed poolId, uint64 epoch);

    error BadConfig();
    error WrongChain();
    error NotPoolManager();
    error UnknownPool();
    error BadHookData();
    error ModelNotInPool();
    error ProofRejected();
    error JobBoundElsewhere();

    constructor(FlopReceiptRoot roots, uint256 evmChainId, address poolManager, PoolConfig[] memory pools) {
        if (address(roots) == address(0) || poolManager == address(0)) revert BadConfig();
        for (uint256 i; i < pools.length; ++i) {
            bytes32 p = pools[i].poolId;
            if (p == bytes32(0) || isPool[p] || pools[i].modelHashes.length == 0) revert BadConfig();
            isPool[p] = true;
            for (uint256 j; j < pools[i].modelHashes.length; ++j) {
                poolServesModel[p][pools[i].modelHashes[j]] = true;
            }
        }
        ROOTS = roots;
        EVM_CHAIN_ID = evmChainId;
        POOL_MANAGER = poolManager;
    }

    /// @notice Verify the receipt in `hookData`, bind its jobId to `poolId`, return the jobId.
    function tag(bytes32 poolId, bytes calldata hookData) external returns (bytes32 jobId) {
        if (block.chainid != EVM_CHAIN_ID) revert WrongChain();
        if (msg.sender != POOL_MANAGER) revert NotPoolManager();
        if (!isPool[poolId]) revert UnknownPool();
        (uint64 epoch, FlopReceiptRoot.Settlement memory s, bytes32[] memory proof) = decodeHookData(hookData);
        if (!poolServesModel[poolId][s.modelHash]) revert ModelNotInPool();
        if (!ROOTS.verify(epoch, s, proof)) revert ProofRejected();
        jobId = jobIdOf(s);
        bytes32 bound = poolOf[jobId];
        if (bound != bytes32(0) && bound != poolId) revert JobBoundElsewhere();
        poolOf[jobId] = poolId;
        epochOf[jobId] = epoch;
        emit JobTagged(jobId, poolId, epoch);
    }

    /// @notice Event-key jobId. `leafOf` is not used; the four fields are encoded as 32-byte ABI words.
    function jobIdOf(FlopReceiptRoot.Settlement memory s) public pure returns (bytes32) {
        return keccak256(abi.encode(JOB_ID_TAG, s.genesis, s.channelId, s.settledBlock, s.eventIndex));
    }

    /// @notice Canonical hookData only: `abi.decode` alone would accept trailing bytes and other
    ///         offsets, so one receipt could travel as many byte strings.
    function decodeHookData(bytes calldata hookData)
        public
        view
        returns (uint64 epoch, FlopReceiptRoot.Settlement memory s, bytes32[] memory proof)
    {
        try this.abiDecode(hookData) returns (uint64 e, FlopReceiptRoot.Settlement memory x, bytes32[] memory p) {
            (epoch, s, proof) = (e, x, p);
        } catch {
            revert BadHookData();
        }
        if (keccak256(abi.encode(epoch, s, proof)) != keccak256(hookData)) revert BadHookData();
    }

    /// @dev External so `decodeHookData` can turn its empty-data reverts into BadHookData.
    function abiDecode(bytes calldata hookData)
        external
        pure
        returns (uint64, FlopReceiptRoot.Settlement memory, bytes32[] memory)
    {
        return abi.decode(hookData, (uint64, FlopReceiptRoot.Settlement, bytes32[]));
    }
}
