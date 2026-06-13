using System.Text.Json;
using Tessera.Chains;
using Tessera.Chains.Cardano;
using Tessera.Chains.Cardano.Internal;
using Tessera.Chains.Cardano.Providers;
using Tessera.Core;

namespace Tessera.Chains.Cardano.Tests;

/// <summary>
/// Security regression tests for Metadata-mode reads (findings H9 + M7). The transaction-metadata
/// label is a shared, permissionless namespace, so a read must (a) reject any metadata tx that did
/// not originate from the controller's address, and (b) verify a controller signature over the
/// payload. These tests build authentic + forged metadata feeds and assert the read outcome.
/// </summary>
public class CardanoMetadataAuthTests
{
    // The same throwaway mnemonic the unit tests use — controls no funds.
    private const string TestMnemonic =
        "view harsh cherry fall arm stamp aerobic gospel royal excite mind lunar " +
        "burden castle edge urban alien vague adjust hedgehog slogan can fetch piano";

    private const ulong Label = 5446;
    private static readonly DidId Did = new("did:tessera:alice");

    private static CardanoAnchorOptions MetadataOptions() => new()
    {
        Network = CardanoNetwork.Preprod,
        BlockfrostProjectId = "preprod_dummy",
        SigningKey = TestMnemonic,
        AnchorMode = AnchorMode.Metadata,
        Retry = CardanoRetryPolicy.None,
    };

    [Fact]
    public async Task ReadMetadata_AuthenticControllerTx_IsReturned()
    {
        var key = KeyLoader.Load(TestMnemonic, CardanoNetwork.Preprod);
        var root = Bytes(0x11, 32);
        var tx = SignedTx(key, Did, root, epoch: 0, fromAddress: key.Address);

        using var anchor = new CardanoChainAnchor(MetadataOptions(), new MetadataProvider(tx));
        var state = await anchor.GetAnchorAsync(Did);

        Assert.NotNull(state);
        Assert.Equal(root, state!.AttestationRoot);
        Assert.Equal(0UL, state.RevocationEpoch);
    }

    [Fact]
    public async Task ReadMetadata_ForeignSubmitterTx_IsRejected()
    {
        var key = KeyLoader.Load(TestMnemonic, CardanoNetwork.Preprod);
        // Same did + a valid controller signature, but submitted from an attacker address.
        var tx = SignedTx(key, Did, Bytes(0xAB, 32), epoch: 7,
            fromAddress: "addr_test1qqattackerattackerattackerattackerattackerattackerattacker");

        using var anchor = new CardanoChainAnchor(MetadataOptions(), new MetadataProvider(tx));
        var state = await anchor.GetAnchorAsync(Did);

        Assert.Null(state);
    }

    [Fact]
    public async Task ReadMetadata_MissingSignature_IsRejected()
    {
        var key = KeyLoader.Load(TestMnemonic, CardanoNetwork.Preprod);
        // Originates from the controller address, but carries no controller signature/pk.
        var unsigned = UnsignedTx(Did, Bytes(0x22, 32), epoch: 3, fromAddress: key.Address);

        using var anchor = new CardanoChainAnchor(MetadataOptions(), new MetadataProvider(unsigned));
        Assert.Null(await anchor.GetAnchorAsync(Did));
    }

    [Fact]
    public async Task ReadMetadata_ForgedSignatureFromOtherKey_IsRejected()
    {
        // An attacker signs with their own key but submits from the controller's address
        // (e.g. a shared/compromised wallet). The pk-hash != controller key-hash check rejects it.
        var attacker = KeyLoader.Load(OtherMnemonic, CardanoNetwork.Preprod);
        var controller = KeyLoader.Load(TestMnemonic, CardanoNetwork.Preprod);
        var tx = SignedTx(attacker, Did, Bytes(0xCD, 32), epoch: 9, fromAddress: controller.Address);

        using var anchor = new CardanoChainAnchor(MetadataOptions(), new MetadataProvider(tx));
        Assert.Null(await anchor.GetAnchorAsync(Did));
    }

    [Fact]
    public async Task ReadMetadata_AttackerTxThenControllerTx_ReturnsController()
    {
        var key = KeyLoader.Load(TestMnemonic, CardanoNetwork.Preprod);
        var realRoot = Bytes(0x55, 32);
        // Newest-first feed: attacker forgery first (must be skipped), genuine controller tx second.
        var attackerTx = SignedTx(KeyLoader.Load(OtherMnemonic, CardanoNetwork.Preprod), Did, Bytes(0xEE, 32),
            epoch: 99, fromAddress: "addr_test1qqattacker");
        var controllerTx = SignedTx(key, Did, realRoot, epoch: 2, fromAddress: key.Address);

        using var anchor = new CardanoChainAnchor(MetadataOptions(), new MetadataProvider(attackerTx, controllerTx));
        var state = await anchor.GetAnchorAsync(Did);

        Assert.NotNull(state);
        Assert.Equal(realRoot, state!.AttestationRoot);
        Assert.Equal(2UL, state.RevocationEpoch);
    }

    // ── builders ───────────────────────────────────────────────────────────────

    // A distinct, checksum-valid throwaway mnemonic standing in for an attacker key.
    private const string OtherMnemonic =
        "outer vintage click check fix foam because pride emerge stool illegal shrug " +
        "design praise fat rug floor liar mushroom olive uniform wood teach inherit";

    private static MetadataTx SignedTx(ControllerKey signer, DidId did, byte[] root, ulong epoch, string fromAddress)
    {
        var didHash = DidHash.Compute(did);
        var sig = MetadataAttestation.Sign(signer, didHash, root, epoch);
        var json = JsonBody(
            Convert.ToHexString(didHash).ToLowerInvariant(),
            Convert.ToHexString(root).ToLowerInvariant(),
            epoch,
            pkHex: Convert.ToHexString(signer.PublicKey.Key).ToLowerInvariant(),
            sigHex: Convert.ToHexString(sig).ToLowerInvariant());
        return new MetadataTx(RandomTxHash(), json, new[] { fromAddress });
    }

    private static MetadataTx UnsignedTx(DidId did, byte[] root, ulong epoch, string fromAddress)
    {
        var didHash = DidHash.Compute(did);
        var json = JsonBody(
            Convert.ToHexString(didHash).ToLowerInvariant(),
            Convert.ToHexString(root).ToLowerInvariant(),
            epoch, pkHex: null, sigHex: null);
        return new MetadataTx(RandomTxHash(), json, new[] { fromAddress });
    }

    private static JsonElement JsonBody(string didHex, string rootHex, ulong epoch, string? pkHex, string? sigHex)
    {
        var map = new Dictionary<string, object> { ["did"] = didHex, ["root"] = rootHex, ["epoch"] = epoch };
        if (pkHex is not null) map["pk"] = pkHex;
        if (sigHex is not null) map["sig"] = sigHex;
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(map));
        return doc.RootElement.Clone();
    }

    private static string RandomTxHash() => Convert.ToHexString(Guid.NewGuid().ToByteArray()).ToLowerInvariant();

    private static byte[] Bytes(byte fill, int n)
    {
        var b = new byte[n];
        Array.Fill(b, fill);
        return b;
    }

    /// <summary>Mock provider that serves a fixed, newest-first metadata feed and benign defaults.</summary>
    private sealed class MetadataProvider : ICardanoProvider
    {
        private readonly IReadOnlyList<MetadataTx> _txs;
        public MetadataProvider(params MetadataTx[] txs) => _txs = txs;

        public Task<IReadOnlyList<MetadataTx>> GetMetadataTxsAsync(ulong label, CancellationToken ct)
            => Task.FromResult(_txs);

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
    }
}
