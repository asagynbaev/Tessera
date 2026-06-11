using System.Text;
using System.Text.Json;
using Tessera.Attestations;
using Tessera.Core;

namespace Tessera.Sources.Bitcoin.Tests;

public class BitcoinAttestationSourceTests
{
    private const long NowUnix = 1_700_000_000;
    private static readonly DidId Subject = new("did:tessera:privacy-subject");

    // Two real testnet addresses (their *strings* must never appear in a draft payload).
    private const string AddrA = "tb1qtp7fhly84qm6q4hhzmp0nh5frtdugmysqkxd0h";
    private const string AddrB = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    private const string TxId1 = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    private const string TxId2 = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
    private const string TxId3 = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";

    // Per-UTXO values (chosen 13-digit so they cannot collide with a base64 commitment by chance).
    private const long V1 = 1_000_000_000_000; // AddrA utxo1, 100 days old
    private const long V2 = 234_567_890_123;   // AddrA utxo2, 10 days old
    private const long V3 = 9_876_543_210_987;  // AddrB utxo3, 50 days old
    private const long ExpectedTotal = V1 + V2 + V3; // 11_111_111_101_110

    private sealed class FakeBitcoinProvider : IBitcoinProvider
    {
        private readonly Dictionary<string, (long Balance, BitcoinUtxo[] Utxos)> _data;
        public FakeBitcoinProvider(Dictionary<string, (long, BitcoinUtxo[])> data) => _data = data;

        public Task<BitcoinAddressSummary> GetAddressSummaryAsync(string address, CancellationToken ct = default)
            => Task.FromResult(new BitcoinAddressSummary { Address = address, ConfirmedSats = _data[address].Balance });

        public Task<IReadOnlyList<BitcoinUtxo>> GetUtxosAsync(string address, CancellationToken ct = default)
            => Task.FromResult((IReadOnlyList<BitcoinUtxo>)_data[address].Utxos);
    }

    private static BitcoinUtxo Utxo(string txid, long value, int ageDays) => new()
    {
        TxId = txid,
        Vout = 0,
        ValueSats = value,
        BlockHeight = 800_000,
        BlockTime = NowUnix - (long)ageDays * 86_400,
    };

    private static (BitcoinAttestationSource Source, IReadOnlyList<VerifiedBitcoinAddress> Verified) Build()
    {
        var data = new Dictionary<string, (long, BitcoinUtxo[])>
        {
            [AddrA] = (V1 + V2, new[] { Utxo(TxId1, V1, 100), Utxo(TxId2, V2, 10) }),
            [AddrB] = (V3, new[] { Utxo(TxId3, V3, 50) }),
        };
        var clock = new FakeClock(DateTimeOffset.FromUnixTimeSeconds(NowUnix));
        var source = new BitcoinAttestationSource(new FakeBitcoinProvider(data), clock: clock);
        var verified = new[]
        {
            new VerifiedBitcoinAddress { Address = AddrA, Type = BitcoinAddressType.P2wpkh, Network = BitcoinNetwork.Testnet },
            new VerifiedBitcoinAddress { Address = AddrB, Type = BitcoinAddressType.P2wpkh, Network = BitcoinNetwork.Testnet },
        };
        return (source, verified);
    }

    [Fact]
    public async Task Facts_AreComputed_ValueWeighted()
    {
        var (source, verified) = Build();
        var result = await source.ResolveForAsync(Subject, verified);

        Assert.Equal(ExpectedTotal, result.Facts.TotalSats);
        Assert.Equal(100, result.Facts.OldestUtxoAgeDays);
        Assert.Equal(2, result.Facts.AddressCount);
        // Σ(value·age)/total = 596_172_839_450_580 / 11_111_111_101_110 = 53 (floor).
        Assert.Equal(53, result.Facts.HodlAgeDays);
    }

    [Fact]
    public async Task EmitsThreeDrafts_WithExpectedShapes()
    {
        var (source, verified) = Build();
        var result = await source.ResolveForAsync(Subject, verified);

        Assert.Equal(3, result.Drafts.Count);

        var control = result.Drafts.Single(d => d.Type == BitcoinAttestationTypes.Control);
        Assert.Null(control.Payload.Commitment);
        Assert.NotNull(control.Payload.Claims);
        Assert.Equal(2, control.Payload.Claims![BitcoinAttestationTypes.AddressCountClaim]);
        Assert.Single(control.Payload.Claims); // ONLY the count

        var balance = result.Drafts.Single(d => d.Type == BitcoinAttestationTypes.Balance);
        Assert.NotNull(balance.Payload.Commitment);
        Assert.Null(balance.Payload.Claims);

        var age = result.Drafts.Single(d => d.Type == BitcoinAttestationTypes.HodlAge);
        Assert.NotNull(age.Payload.Commitment);
        Assert.Null(age.Payload.Claims);

        Assert.True(result.Openings.ContainsKey(BitcoinAttestationTypes.Balance));
        Assert.True(result.Openings.ContainsKey(BitcoinAttestationTypes.HodlAge));
    }

    [Fact]
    public async Task BalanceCommitment_BindsToTotal_AndProvesThreshold()
    {
        var (source, verified) = Build();
        var result = await source.ResolveForAsync(Subject, verified);

        var balance = result.Drafts.Single(d => d.Type == BitcoinAttestationTypes.Balance);
        var opening = result.Openings[BitcoinAttestationTypes.Balance];

        // The holder proves balance ≥ 1 BTC, bound to the committed total.
        const long oneBtc = 100_000_000;
        var cp = new CredentialProof();
        var bundle = cp.ProveBoundMinimum(result.Facts.TotalSats, oneBtc, opening, "btc_balance");
        Assert.True(cp.VerifyBound(balance.Payload.Commitment!, bundle));
    }

    [Fact]
    public async Task NoVerifiedAddresses_EmitsNothing()
    {
        var (source, _) = Build();
        var result = await source.ResolveForAsync(Subject, Array.Empty<VerifiedBitcoinAddress>());
        Assert.Empty(result.Drafts);
        Assert.Equal(0, result.Facts.TotalSats);
    }

    [Fact]
    public async Task PipelinePath_RequiresControlStore_AndExposesOpenings()
    {
        var (noStoreSource, _) = Build();
        var ctx = new SubjectContext { Subject = Subject };
        await Assert.ThrowsAsync<InvalidOperationException>(() => noStoreSource.ResolveAsync(ctx));

        // With a control store seeded by the verifier, the pipeline path returns drafts and stashes openings.
        var data = new Dictionary<string, (long, BitcoinUtxo[])>
        {
            [AddrA] = (V1 + V2, new[] { Utxo(TxId1, V1, 100), Utxo(TxId2, V2, 10) }),
            [AddrB] = (V3, new[] { Utxo(TxId3, V3, 50) }),
        };
        var clock = new FakeClock(DateTimeOffset.FromUnixTimeSeconds(NowUnix));
        var store = new InMemoryBitcoinControlStore();
        await store.RecordVerifiedAsync(Subject, new VerifiedBitcoinAddress { Address = AddrA, Type = BitcoinAddressType.P2wpkh, Network = BitcoinNetwork.Testnet });
        await store.RecordVerifiedAsync(Subject, new VerifiedBitcoinAddress { Address = AddrB, Type = BitcoinAddressType.P2wpkh, Network = BitcoinNetwork.Testnet });

        var source = new BitcoinAttestationSource(new FakeBitcoinProvider(data), store, clock: clock);
        var drafts = await source.ResolveAsync(ctx);
        Assert.Equal(3, drafts.Count);
        Assert.True(source.TryGetOpenings(Subject, out var openings));
        Assert.True(openings.ContainsKey(BitcoinAttestationTypes.Balance));
    }

    [Fact]
    public async Task SourceId_IsStableAndVendorScoped()
    {
        var (source, _) = Build();
        Assert.Equal("btc.control", source.SourceId);
        await Task.CompletedTask;
    }

    // ── The privacy invariant ────────────────────────────────────────────────

    [Fact]
    public async Task NoAddressTxidOrAmountLeaks_InAnySerializedDraft()
    {
        var (source, verified) = Build();
        var result = await source.ResolveForAsync(Subject, verified);

        long BlockTime(int ageDays) => NowUnix - (long)ageDays * 86_400;

        // Long, distinctive secrets (addresses, txids, amounts, 10-digit block times) — safe to scan
        // against the full wire surface including opaque base64 commitments (no chance collision).
        var longSecrets = new[]
        {
            AddrA, AddrB,
            TxId1, TxId2, TxId3,
            V1.ToString(), V2.ToString(), V3.ToString(), ExpectedTotal.ToString(),
            BlockTime(100).ToString(), BlockTime(10).ToString(), BlockTime(50).ToString(),
        };

        // Derived age quantities are small integers — scanned ONLY against the human-readable surface
        // (type/method/claims, no base64), so an accidental plaintext age claim is caught without
        // risking a base64 false positive. Combined with the structural "committed drafts carry no
        // claims" check above, this guards every plaintext leak path.
        var smallSecrets = new[]
        {
            result.Facts.HodlAgeDays.ToString(),
            result.Facts.OldestUtxoAgeDays.ToString(),
        };

        var full = new StringBuilder();
        var humanReadable = new StringBuilder();
        foreach (var draft in result.Drafts)
        {
            humanReadable.Append(draft.Type).Append('|').Append(draft.Payload.Method).Append('|')
                .Append(JsonSerializer.Serialize(draft.Payload.Claims)).Append('\n');

            // (1) JSON of the draft (Commitment renders as base64).
            full.Append(JsonSerializer.Serialize(new
            {
                draft.Type,
                draft.Payload.Method,
                Commitment = draft.Payload.Commitment is null ? null : Convert.ToBase64String(draft.Payload.Commitment),
                draft.Payload.Claims,
            }));

            // (2) The on-the-wire canonical signing bytes of a fully-built attestation.
            var attestation = new Attestation
            {
                Schema = BitcoinSchemas.SchemaNamespace,
                Type = draft.Type,
                Issuer = new DidId("did:tessera:btc-issuer"),
                Subject = Subject,
                IssuedAt = DateTimeOffset.FromUnixTimeSeconds(NowUnix),
                ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(NowUnix).Add(draft.Validity),
                Nonce = new byte[16],
                Payload = draft.Payload,
                Signature = new AttestationSignature { Algorithm = "ed25519", Value = new byte[64] },
            };
            full.Append(Convert.ToBase64String(AttestationCanonical.BuildSigningInput(attestation)));
        }

        var fullText = full.ToString();
        var humanText = humanReadable.ToString();
        foreach (var secret in longSecrets)
            Assert.DoesNotContain(secret, fullText, StringComparison.Ordinal);
        foreach (var secret in longSecrets.Concat(smallSecrets))
            Assert.DoesNotContain(secret, humanText, StringComparison.Ordinal);
    }
}
