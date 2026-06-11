using Tessera.Chains.Cardano.Internal;

namespace Tessera.Chains.Cardano.Tests;

/// <summary>
/// CBOR golden vectors + round-trips for the Plutus datums/redeemers and the Conway/V3 pieces
/// CardanoSharp cannot emit. Golden hexes were derived independently (not from the encoder).
/// Mirrors the Solana BorshTests.
/// </summary>
public class CardanoCborTests
{
    private static byte[] Filled(byte b, int n) => Enumerable.Repeat(b, n).ToArray();
    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    private static readonly byte[] Did = Filled(0xd1, 32);
    private static readonly byte[] Root = Filled(0x01, 32);
    private static readonly byte[] Controller = Filled(0xc0, 28);
    private static readonly byte[] NewRoot = Filled(0x02, 32);

    [Fact]
    public void EncodeAnchorDatum_MatchesGolden()
    {
        var datum = new DidAnchorDatumValue(Did, Root, 0, Controller);
        const string golden =
            "d879845820d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1" +
            "5820010101010101010101010101010101010101010101010101010101010101010100" +
            "581cc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
        Assert.Equal(golden, Hex(DatumCodec.EncodeAnchorDatum(datum)));
    }

    [Fact]
    public void RegisterDidRedeemer_IsEmptyConstr0() =>
        Assert.Equal("d87980", Hex(DatumCodec.RegisterDidRedeemer()));

    [Fact]
    public void UpdateRootRedeemer_MatchesGolden() =>
        Assert.Equal(
            "d8798158200202020202020202020202020202020202020202020202020202020202020202",
            Hex(DatumCodec.UpdateRootRedeemer(NewRoot)));

    [Fact]
    public void BumpRevocationRedeemer_IsConstr1WithReason() =>
        Assert.Equal("d87a8103", Hex(DatumCodec.BumpRevocationRedeemer(3)));

    [Fact]
    public void AnchorDatum_RoundTrips()
    {
        var datum = new DidAnchorDatumValue(Did, Root, 42, Controller);
        var decoded = DatumCodec.DecodeAnchorDatum(DatumCodec.EncodeAnchorDatum(datum));
        Assert.Equal(Did, decoded.DidHash);
        Assert.Equal(Root, decoded.AttestationRoot);
        Assert.Equal(42UL, decoded.RevocationEpoch);
        Assert.Equal(Controller, decoded.Controller);
    }

    [Theory]
    [InlineData(0UL)]
    [InlineData(1UL)]
    [InlineData(255UL)]
    [InlineData(65_536UL)]
    [InlineData(4_294_967_296UL)]
    public void AnchorDatum_EpochRoundTrips(ulong epoch)
    {
        var decoded = DatumCodec.DecodeAnchorDatum(
            DatumCodec.EncodeAnchorDatum(new DidAnchorDatumValue(Did, Root, epoch, Controller)));
        Assert.Equal(epoch, decoded.RevocationEpoch);
    }

    [Fact]
    public void LanguageViews_MatchesGolden() =>
        Assert.Equal("a10283010203", Hex(PlutusCbor.LanguageViews(new long[] { 1, 2, 3 })));

    [Fact]
    public void Redeemers_MintMapForm_MatchesGolden()
    {
        var redeemers = new[] { new RedeemerEntry(RedeemerEntry.MintTag, 0, DatumCodec.RegisterDidRedeemer(), 10, 20) };
        Assert.Equal("a182010082d87980820a14", Hex(PlutusCbor.Redeemers(redeemers)));
    }

    [Fact]
    public void ScriptDataHash_MatchesGolden()
    {
        var redeemers = PlutusCbor.Redeemers(new[] { new RedeemerEntry(RedeemerEntry.MintTag, 0, DatumCodec.RegisterDidRedeemer(), 10, 20) });
        var languageViews = PlutusCbor.LanguageViews(new long[] { 1, 2, 3 });
        Assert.Equal(
            "b73f58d89ac59860c6d5eaa217a6aabd130d3877a018b085a9ca8cf84f07b289",
            Hex(PlutusCbor.ScriptDataHash(redeemers, languageViews)));
    }

    [Fact]
    public void WitnessSet_CarriesV3ScriptUnderKey7()
    {
        // Map header 0xa3 (3 keys); key 7 (0x07) present for the Plutus V3 script.
        var witness = PlutusCbor.WitnessSet(
            Array.Empty<(byte[], byte[])>(),
            PlutusCbor.Redeemers(new[] { new RedeemerEntry(RedeemerEntry.MintTag, 0, DatumCodec.RegisterDidRedeemer(), 10, 20) }),
            Filled(0xab, 50));
        var hex = Hex(witness);
        Assert.StartsWith("a3", hex);     // 3-entry map
        Assert.Contains("07", hex);       // witness key 7 = plutus_v3_script
    }
}
