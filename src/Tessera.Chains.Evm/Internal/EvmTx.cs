using System.Numerics;
using Nethereum.Hex.HexTypes;

namespace Tessera.Chains.Evm.Internal;

/// <summary>
/// Helpers for interpreting EVM transaction receipts.
/// </summary>
internal static class EvmTx
{
    /// <summary>
    /// Apply a safety margin to an <c>eth_estimateGas</c> result. The estimate is a lower bound;
    /// the real execution can cost marginally more (read-after-write replica lag on public RPCs,
    /// refund/warm-slot accounting), which otherwise surfaces as a status-0 out-of-gas revert.
    /// 1.5× is the common margin and is free on success — gas is billed on <c>gasUsed</c>, not the limit.
    /// </summary>
    public static BigInteger WithGasBuffer(BigInteger estimate) => estimate * 3 / 2;

    /// <summary>
    /// Assert that a mined transaction actually succeeded.
    /// </summary>
    /// <remarks>
    /// Nethereum's <c>SendRequestAndWaitForReceiptAsync</c> resolves as soon as the transaction is
    /// <em>mined</em>; for an ordinary (non-<c>...ThrowsOnRevert</c>) call it does NOT throw when the
    /// transaction reverted on-chain. A reverted transaction is mined with EIP-658 status <c>0</c>, so
    /// the only signal of failure is <see cref="Nethereum.RPC.Eth.DTOs.TransactionReceipt.Status"/>.
    /// We require status <c>1</c> and treat a missing/null status as a failure (pre-Byzantium receipts
    /// have no status, and we never want to report an unverifiable write as success).
    /// </remarks>
    /// <param name="status">The receipt's EIP-658 status (<c>1</c> = success, <c>0</c> = reverted, null = unknown).</param>
    /// <param name="transactionHash">Transaction hash, included in the failure message for diagnostics.</param>
    /// <exception cref="EvmTransactionFailedException">Thrown when the status is not exactly <c>1</c>.</exception>
    public static void EnsureReceiptSucceeded(HexBigInteger? status, string? transactionHash)
    {
        if (status?.Value == 1) return;

        var statusText = status is null ? "<none>" : status.Value.ToString();
        throw new EvmTransactionFailedException(
            $"Transaction {transactionHash ?? "<unknown>"} was mined but did not succeed (receipt status={statusText}; " +
            "expected 1). The call reverted on-chain or the status is unverifiable, so the operation did NOT take effect.",
            transactionHash,
            status?.Value);
    }
}
