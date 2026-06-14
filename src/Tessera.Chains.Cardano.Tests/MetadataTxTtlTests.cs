using System.Formats.Cbor;
using Tessera.Chains.Cardano;
using Tessera.Chains.Cardano.Providers;
using Tessera.Core;

namespace Tessera.Chains.Cardano.Tests;

/// <summary>
/// Regression for the Metadata-mode TTL bug: the builder computed <c>ttl = tip.Slot + 7200</c> but
/// the inner <c>Build(...)</c> hardcoded <c>ttl: 0</c>, so every submitted tx carried
/// <c>invalidHereafter = 0</c> and the node rejected it with <c>OutsideValidityIntervalUTxO</c>.
/// This decodes the actually-submitted transaction body and asserts its TTL tracks the chain tip.
/// </summary>
public class MetadataTxTtlTests
{
    private const string TestMnemonic =
        "view harsh cherry fall arm stamp aerobic gospel royal excite mind lunar " +
        "burden castle edge urban alien vague adjust hedgehog slogan can fetch piano";

    private const ulong TipSlot = 50_000_000;
    private const ulong TtlWindow = 7200; // must match MetadataTxBuilder

    [Fact]
    public async Task MetadataTx_Ttl_TracksChainTip_NotZero()
    {
        var provider = new CapturingProvider();
        using var anchor = new CardanoChainAnchor(new CardanoAnchorOptions
        {
            Network = CardanoNetwork.Preprod,
            BlockfrostProjectId = "preprod_dummy",
            SigningKey = TestMnemonic,
            AnchorMode = AnchorMode.Metadata,
        }, provider);

        await anchor.AnchorRootAsync(new DidId("did:tessera:alice"), new byte[32]);

        Assert.NotNull(provider.SubmittedCbor);
        var ttl = ReadBodyTtl(provider.SubmittedCbor!);
        Assert.NotEqual(0UL, ttl);                 // the bug: was always 0
        Assert.Equal(TipSlot + TtlWindow, ttl);    // tip.Slot + window
    }

    /// <summary>Decode the tx (array) → body (map) → key 3 (ttl / invalidHereafter).</summary>
    private static ulong ReadBodyTtl(byte[] txCbor)
    {
        var reader = new CborReader(txCbor);
        reader.ReadStartArray();          // [body, witness_set, is_valid?, auxiliary_data]
        var n = reader.ReadStartMap();    // transaction_body map
        ulong? ttl = null;
        for (int i = 0; i < n; i++)
        {
            var key = reader.ReadInt32();
            if (key == 3) ttl = reader.ReadUInt64();
            else reader.SkipValue();
        }
        Assert.True(ttl.HasValue, "transaction body has no TTL (key 3)");
        return ttl!.Value;
    }

    /// <summary>Funded provider with a non-zero tip that captures the submitted tx bytes.</summary>
    private sealed class CapturingProvider : ICardanoProvider
    {
        public byte[]? SubmittedCbor { get; private set; }

        public Task<ProtocolParameters> GetProtocolParametersAsync(CancellationToken ct)
            => Task.FromResult(new ProtocolParameters(44, 155381, 4310, 16384, 0.0577, 7.21e-05, 16_500_000, 10_000_000_000, 150, 3, new long[] { 1, 2, 3 }));

        public Task<IReadOnlyList<CardanoUtxo>> GetUtxosAsync(string address, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<CardanoUtxo>>(new[]
            {
                new CardanoUtxo(
                    TxHash: new string('a', 64),
                    OutputIndex: 0,
                    Address: address,
                    Amount: new[] { new CardanoAsset("lovelace", 10_000_000) },
                    InlineDatumCbor: null,
                    HasReferenceScript: false),
            });

        public Task<IReadOnlyList<CardanoUtxo>> GetAssetUtxosAsync(string address, string unit, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<CardanoUtxo>>(Array.Empty<CardanoUtxo>());

        public Task<ChainTip> GetTipAsync(CancellationToken ct) => Task.FromResult(new ChainTip(TipSlot, 0));

        public Task<IReadOnlyList<RedeemerEvaluation>> EvaluateAsync(byte[] txCbor, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<RedeemerEvaluation>>(Array.Empty<RedeemerEvaluation>());

        public Task<string> SubmitAsync(byte[] txCbor, CancellationToken ct)
        {
            SubmittedCbor = txCbor;
            return Task.FromResult("00");
        }

        public Task<TxConfirmation?> GetTxAsync(string txHash, CancellationToken ct)
            => Task.FromResult<TxConfirmation?>(new TxConfirmation(1, 1_700_000_000));

        public Task<IReadOnlyList<MetadataTx>> GetMetadataTxsAsync(ulong label, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<MetadataTx>>(Array.Empty<MetadataTx>());
    }
}
