using System.Numerics;
using Nethereum.Hex.HexTypes;
using Tessera.Chains.Evm;
using Tessera.Chains.Evm.Internal;

namespace Tessera.Chains.Evm.Tests;

/// <summary>
/// H8: Nethereum's wait-for-receipt does NOT throw on a mined-but-reverted transaction for ordinary
/// (non-ThrowsOnRevert) calls — it returns a receipt with EIP-658 status 0. Both
/// <c>EvmChainAnchor.SendAsync</c> and <c>EvmAllowlistGateway.SendAsync</c> route their receipt through
/// <see cref="EvmTx.EnsureReceiptSucceeded"/> before returning, so these tests pin the exact predicate:
/// status 1 succeeds; status 0 and a missing status are failures.
/// </summary>
public class EvmTxReceiptTests
{
    private const string TxHash = "0xabc123";

    [Fact]
    public void Status1_Succeeds()
    {
        var ex = Record.Exception(() => EvmTx.EnsureReceiptSucceeded(new HexBigInteger(1), TxHash));
        Assert.Null(ex);
    }

    [Fact]
    public void Status0_RevertedTx_IsTreatedAsFailure()
    {
        var ex = Assert.Throws<EvmTransactionFailedException>(
            () => EvmTx.EnsureReceiptSucceeded(new HexBigInteger(0), TxHash));

        Assert.Equal(TxHash, ex.TransactionHash);
        Assert.Equal(BigInteger.Zero, ex.Status);
        Assert.Contains(TxHash, ex.Message);
    }

    [Fact]
    public void NullStatus_IsTreatedAsFailure()
    {
        var ex = Assert.Throws<EvmTransactionFailedException>(
            () => EvmTx.EnsureReceiptSucceeded(null, TxHash));

        Assert.Null(ex.Status);
        Assert.Contains(TxHash, ex.Message);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(255)]
    public void AnyStatusOtherThanOne_IsTreatedAsFailure(int status)
        => Assert.Throws<EvmTransactionFailedException>(
            () => EvmTx.EnsureReceiptSucceeded(new HexBigInteger(status), TxHash));
}
