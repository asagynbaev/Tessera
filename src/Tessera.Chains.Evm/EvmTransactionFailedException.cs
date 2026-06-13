using System.Numerics;

namespace Tessera.Chains.Evm;

/// <summary>
/// Thrown when an EVM write transaction is mined but does not succeed: the receipt carries an
/// EIP-658 status other than <c>1</c> (a revert is status <c>0</c>; a missing status is treated as
/// failure). Nethereum's ordinary wait-for-receipt does not raise on a mined-but-reverted
/// transaction, so the adapter raises this so a reverted write is never mistaken for success.
/// </summary>
public sealed class EvmTransactionFailedException : Exception
{
    /// <summary>The transaction hash, if known.</summary>
    public string? TransactionHash { get; }

    /// <summary>The receipt's EIP-658 status, if present (<c>0</c> = reverted; null = unknown/absent).</summary>
    public BigInteger? Status { get; }

    public EvmTransactionFailedException(string message, string? transactionHash, BigInteger? status)
        : base(message)
    {
        TransactionHash = transactionHash;
        Status = status;
    }
}
