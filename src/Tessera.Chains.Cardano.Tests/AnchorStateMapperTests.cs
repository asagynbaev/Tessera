using Tessera.Chains.Cardano.Internal;
using Tessera.Core;

namespace Tessera.Chains.Cardano.Tests;

public class AnchorStateMapperTests
{
    [Theory]
    [InlineData(0UL, 0UL, false)]
    [InlineData(1UL, 0UL, true)]
    [InlineData(5UL, 5UL, false)]
    [InlineData(6UL, 5UL, true)]
    [InlineData(5UL, 6UL, false)]
    public void IsRevokedSince_TrueOnlyWhenChainEpochMovedPast(ulong current, ulong asOf, bool expected)
        => Assert.Equal(expected, AnchorStateMapper.IsRevokedSince(current, asOf));

    [Fact]
    public void ToAnchorState_FromDatum_MapsRootEpochAndTime()
    {
        var did = new DidId("did:tessera:alice");
        var root = Enumerable.Repeat((byte)0x07, 32).ToArray();
        var datum = new DidAnchorDatumValue(new byte[32], root, 9, new byte[28]);
        var when = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);

        var state = AnchorStateMapper.ToAnchorState(did, datum, when);

        Assert.Equal(did, state.Did);
        Assert.Equal(root, state.AttestationRoot);
        Assert.Equal(9UL, state.RevocationEpoch);
        Assert.Equal(when, state.UpdatedAt);
    }
}
