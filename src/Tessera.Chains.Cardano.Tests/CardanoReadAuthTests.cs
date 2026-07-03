using Tessera.Chains;
using Tessera.Chains.Cardano;
using Tessera.Chains.Cardano.Internal;
using Tessera.Chains.Cardano.Providers;
using Tessera.Core;

namespace Tessera.Chains.Cardano.Tests;

/// <summary>
/// Read-side authentication for the Validator anchor mode (findings H-1 and H-2).
/// <list type="bullet">
///   <item>H-2: <see cref="AnchorState.Owner"/> is populated from the datum's controller.</item>
///   <item>H-1: when more than one UTxO carries the (policyId, did_hash) thread token, the read
///     never silently returns an arbitrary one — it selects the UTxO matching the expected
///     controller, or fails closed on ambiguity.</item>
/// </list>
/// </summary>
public class CardanoReadAuthTests
{
    // Same throwaway mnemonic used by the other Cardano unit tests — controls no funds.
    private const string TestMnemonic =
        "view harsh cherry fall arm stamp aerobic gospel royal excite mind lunar " +
        "burden castle edge urban alien vague adjust hedgehog slogan can fetch piano";

    private static CardanoAnchorOptions Options() => new()
    {
        Network = CardanoNetwork.Preprod,
        BlockfrostProjectId = "preprod_dummy",
        SigningKey = TestMnemonic,
        AnchorMode = AnchorMode.Validator,
    };

    /// <summary>The configured controller's on-chain key hash (the datum controller a legit anchor carries).</summary>
    private static byte[] AdapterControllerKeyHash()
        => KeyLoader.Load(TestMnemonic, CardanoNetwork.Preprod).KeyHash;

    private static CardanoUtxo AnchorUtxo(byte[] didHash, byte[] root, ulong epoch, byte[] controller, string txHash)
    {
        var datum = DatumCodec.EncodeAnchorDatum(new DidAnchorDatumValue(didHash, root, epoch, controller));
        return new CardanoUtxo(
            txHash, 0, "addr_test_script",
            new List<CardanoAsset> { new("lovelace", 2_000_000) },
            InlineDatumCbor: datum, HasReferenceScript: false);
    }

    [Fact]
    public async Task GetAnchor_SingleUtxo_PopulatesOwnerFromController()
    {
        var did = new DidId("did:tessera:alice");
        var didHash = DidHash.Compute(did);
        var root = Enumerable.Repeat((byte)0xAB, 32).ToArray();
        var controller = Enumerable.Range(0, 28).Select(i => (byte)(i + 1)).ToArray();

        using var anchor = new CardanoChainAnchor(Options(),
            new StubProvider(AnchorUtxo(didHash, root, 3, controller, "a1")));

        var state = await anchor.GetAnchorAsync(did);

        Assert.NotNull(state);
        Assert.Equal(root, state!.AttestationRoot);
        Assert.Equal(3UL, state.RevocationEpoch);
        Assert.Equal(Convert.ToHexString(controller).ToLowerInvariant(), state.Owner);
    }

    [Fact]
    public async Task GetAnchor_MultipleUtxos_NoneMatchController_FailsClosed()
    {
        var did = new DidId("did:tessera:alice");
        var didHash = DidHash.Compute(did);
        // Two conflicting anchors, neither authored by the adapter's controller (attacker squat).
        var attacker1 = Enumerable.Repeat((byte)0x11, 28).ToArray();
        var attacker2 = Enumerable.Repeat((byte)0x22, 28).ToArray();

        using var anchor = new CardanoChainAnchor(Options(), new StubProvider(
            AnchorUtxo(didHash, new byte[32], 0, attacker1, "a1"),
            AnchorUtxo(didHash, new byte[32], 0, attacker2, "a2")));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => anchor.GetAnchorAsync(did));
        Assert.Contains("Conflicting anchors", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetAnchor_MultipleUtxos_SelectsTheOneMatchingExpectedController()
    {
        var did = new DidId("did:tessera:alice");
        var didHash = DidHash.Compute(did);
        var mine = AdapterControllerKeyHash();
        var attacker = Enumerable.Repeat((byte)0x33, 28).ToArray();
        var legitRoot = Enumerable.Repeat((byte)0x5C, 32).ToArray();

        // Attacker's UTxO listed first; the authentic one (matching the controller) must still win.
        using var anchor = new CardanoChainAnchor(Options(), new StubProvider(
            AnchorUtxo(didHash, Enumerable.Repeat((byte)0xEE, 32).ToArray(), 9, attacker, "a1"),
            AnchorUtxo(didHash, legitRoot, 4, mine, "a2")));

        var state = await anchor.GetAnchorAsync(did);

        Assert.NotNull(state);
        Assert.Equal(legitRoot, state!.AttestationRoot);
        Assert.Equal(4UL, state.RevocationEpoch);
        Assert.Equal(Convert.ToHexString(mine).ToLowerInvariant(), state.Owner);
    }

    /// <summary>Provider stub returning a fixed set of anchor UTxOs for the asset query.</summary>
    private sealed class StubProvider : ICardanoProvider
    {
        private readonly IReadOnlyList<CardanoUtxo> _anchorUtxos;
        public StubProvider(params CardanoUtxo[] anchorUtxos) => _anchorUtxos = anchorUtxos;

        public Task<IReadOnlyList<CardanoUtxo>> GetAssetUtxosAsync(string address, string unit, CancellationToken ct)
            => Task.FromResult(_anchorUtxos);

        public Task<TxConfirmation?> GetTxAsync(string txHash, CancellationToken ct)
            => Task.FromResult<TxConfirmation?>(new TxConfirmation(1, 1_700_000_000));

        public Task<ProtocolParameters> GetProtocolParametersAsync(CancellationToken ct)
            => Task.FromResult(new ProtocolParameters(44, 155381, 4310, 16384, 0.0577, 7.21e-05, 16_500_000, 10_000_000_000, 150, 3, new long[] { 1, 2, 3 }));

        public Task<IReadOnlyList<CardanoUtxo>> GetUtxosAsync(string address, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<CardanoUtxo>>(Array.Empty<CardanoUtxo>());

        public Task<ChainTip> GetTipAsync(CancellationToken ct) => Task.FromResult(new ChainTip(0, 0));

        public Task<IReadOnlyList<RedeemerEvaluation>> EvaluateAsync(byte[] txCbor, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<RedeemerEvaluation>>(Array.Empty<RedeemerEvaluation>());

        public Task<string> SubmitAsync(byte[] txCbor, CancellationToken ct) => Task.FromResult("00");

        public Task<IReadOnlyList<MetadataTx>> GetMetadataTxsAsync(ulong label, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<MetadataTx>>(Array.Empty<MetadataTx>());
    }
}
