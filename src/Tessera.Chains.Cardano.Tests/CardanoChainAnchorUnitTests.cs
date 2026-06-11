using Tessera.Chains.Cardano;
using Tessera.Chains.Cardano.Providers;
using Tessera.Core;

namespace Tessera.Chains.Cardano.Tests;

public class CardanoChainAnchorUnitTests
{
    // A throwaway BIP-39 mnemonic — controls no funds; only exercises key parsing / construction.
    private const string TestMnemonic =
        "view harsh cherry fall arm stamp aerobic gospel royal excite mind lunar " +
        "burden castle edge urban alien vague adjust hedgehog slogan can fetch piano";

    private static CardanoAnchorOptions Options(AnchorMode mode = AnchorMode.Validator) => new()
    {
        Network = CardanoNetwork.Preprod,
        BlockfrostProjectId = "preprod_dummy",
        SigningKey = TestMnemonic,
        AnchorMode = mode,
    };

    [Fact]
    public void Ctor_EmptyProjectId_Throws() =>
        Assert.Throws<ArgumentException>(() => new CardanoChainAnchor(Options() with { BlockfrostProjectId = "" }));

    [Fact]
    public void Ctor_EmptySigningKey_Throws() =>
        Assert.Throws<ArgumentException>(() => new CardanoChainAnchor(Options() with { SigningKey = "  " }));

    [Fact]
    public void ChainId_ReflectsNetwork()
    {
        using var anchor = new CardanoChainAnchor(Options(), new FakeProvider());
        Assert.Equal("cardano:preprod", anchor.ChainId);
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(0)]
    public async Task AnchorRoot_WrongRootLength_Throws(int length)
    {
        using var anchor = new CardanoChainAnchor(Options(), new FakeProvider());
        await Assert.ThrowsAsync<ArgumentException>(() =>
            anchor.AnchorRootAsync(new DidId("did:tessera:alice"), new byte[length]));
    }

    [Fact]
    public async Task RegisterIssuer_WrongKeyLength_Throws()
    {
        using var anchor = new CardanoChainAnchor(Options(), new FakeProvider());
        await Assert.ThrowsAsync<ArgumentException>(() =>
            anchor.RegisterIssuerAsync(new DidId("did:tessera:issuer"), new byte[31], "https://schema"));
    }

    [Fact]
    public async Task GetAnchor_UnknownDid_Validator_ReturnsNull()
    {
        using var anchor = new CardanoChainAnchor(Options(AnchorMode.Validator), new FakeProvider());
        Assert.Null(await anchor.GetAnchorAsync(new DidId("did:tessera:nobody")));
    }

    [Fact]
    public async Task GetAnchor_UnknownDid_Metadata_ReturnsNull()
    {
        using var anchor = new CardanoChainAnchor(Options(AnchorMode.Metadata), new FakeProvider());
        Assert.Null(await anchor.GetAnchorAsync(new DidId("did:tessera:nobody")));
    }

    [Fact]
    public async Task IsRevokedSince_NoAnchor_ReturnsFalse()
    {
        using var anchor = new CardanoChainAnchor(Options(), new FakeProvider());
        Assert.False(await anchor.IsRevokedSinceAsync(new DidId("did:tessera:nobody"), 0));
    }

    /// <summary>Provider stub returning empty/benign data — the read paths must degrade to null, not throw.</summary>
    private sealed class FakeProvider : ICardanoProvider
    {
        public Task<ProtocolParameters> GetProtocolParametersAsync(CancellationToken ct)
            => Task.FromResult(new ProtocolParameters(44, 155381, 4310, 16384, 0.0577, 7.21e-05, 16_500_000, 10_000_000_000, 150, 3, new long[] { 1, 2, 3 }));

        public Task<IReadOnlyList<CardanoUtxo>> GetUtxosAsync(string address, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<CardanoUtxo>>(Array.Empty<CardanoUtxo>());

        public Task<IReadOnlyList<CardanoUtxo>> GetAssetUtxosAsync(string address, string unit, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<CardanoUtxo>>(Array.Empty<CardanoUtxo>());

        public Task<ChainTip> GetTipAsync(CancellationToken ct) => Task.FromResult(new ChainTip(0, 0));

        public Task<IReadOnlyList<RedeemerEvaluation>> EvaluateAsync(byte[] txCbor, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<RedeemerEvaluation>>(Array.Empty<RedeemerEvaluation>());

        public Task<string> SubmitAsync(byte[] txCbor, CancellationToken ct) => Task.FromResult("00");

        public Task<TxConfirmation?> GetTxAsync(string txHash, CancellationToken ct)
            => Task.FromResult<TxConfirmation?>(new TxConfirmation(1, 1_700_000_000));

        public Task<IReadOnlyList<MetadataTx>> GetMetadataTxsAsync(ulong label, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<MetadataTx>>(Array.Empty<MetadataTx>());
    }
}
