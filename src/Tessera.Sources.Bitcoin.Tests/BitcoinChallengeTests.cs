using System.Text;
using Tessera.Core;

namespace Tessera.Sources.Bitcoin.Tests;

public class BitcoinChallengeTests
{
    [Fact]
    public void CanonicalString_IsByteExact()
    {
        var challenge = BitcoinTestVectors.Challenge();
        Assert.Equal(BitcoinTestVectors.Message, challenge.ToCanonicalString());
    }

    [Fact]
    public void CanonicalString_HasDomainPrefix_AndLfSeparators_NoTrailingNewline()
    {
        var s = BitcoinTestVectors.Challenge().ToCanonicalString();
        Assert.StartsWith("tessera-btc-v1\n", s);
        Assert.DoesNotContain("\r", s);
        Assert.False(s.EndsWith("\n"));
        Assert.Equal(6, s.Split('\n').Length); // prefix + 5 fields
    }

    [Fact]
    public void CanonicalBytes_AreUtf8OfCanonicalString()
    {
        var challenge = BitcoinTestVectors.Challenge();
        Assert.Equal(Encoding.UTF8.GetBytes(challenge.ToCanonicalString()), challenge.ToCanonicalBytes());
    }

    [Fact]
    public void CanonicalString_RejectsLineBreakInFields()
    {
        // A subject DID or audience carrying a line break would make the line-joined canonical bytes
        // ambiguous — two different (sub, aud) interpretations could share one signature. Reject it.
        var evilAud = BitcoinChallenge.Create(new DidId("did:tessera:x"), "good", TimeSpan.FromMinutes(5))
            with { Audience = "good\naud=evil" };
        Assert.Throws<InvalidOperationException>(() => evilAud.ToCanonicalString());

        var evilSub = BitcoinChallenge.Create(new DidId("did:tessera:x"), "good", TimeSpan.FromMinutes(5))
            with { Subject = new DidId("did:tessera:x\naud=evil") };
        Assert.Throws<InvalidOperationException>(() => evilSub.ToCanonicalString());
    }

    [Fact]
    public void Create_ProducesFreshNonce_OfRequestedSize_AndWindow()
    {
        var clock = new FakeClock(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));
        var a = BitcoinChallenge.Create(new DidId("did:tessera:x"), "aud", TimeSpan.FromMinutes(10), clock, nonceBytes: 24);
        var b = BitcoinChallenge.Create(new DidId("did:tessera:x"), "aud", TimeSpan.FromMinutes(10), clock, nonceBytes: 24);

        Assert.Equal(24, a.Nonce.Length);
        Assert.NotEqual(Convert.ToHexString(a.Nonce), Convert.ToHexString(b.Nonce)); // random
        Assert.Equal(TimeSpan.FromMinutes(10), a.ExpiresAt - a.IssuedAt);
    }

    [Fact]
    public void Create_RejectsShortNonce()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            BitcoinChallenge.Create(new DidId("did:tessera:x"), "aud", TimeSpan.FromMinutes(10), nonceBytes: 8));
    }

    [Fact]
    public void Create_RejectsEmptyAudience_AndNonPositiveValidity()
    {
        Assert.Throws<ArgumentException>(() =>
            BitcoinChallenge.Create(new DidId("did:tessera:x"), "", TimeSpan.FromMinutes(10)));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            BitcoinChallenge.Create(new DidId("did:tessera:x"), "aud", TimeSpan.Zero));
    }

    [Fact]
    public void ToCanonicalString_RejectsUndersizedNonce()
    {
        var bad = new BitcoinChallenge
        {
            Subject = new DidId("did:tessera:x"),
            Audience = "aud",
            Nonce = new byte[8],
            IssuedAt = DateTimeOffset.UnixEpoch,
            ExpiresAt = DateTimeOffset.UnixEpoch.AddMinutes(10),
        };
        Assert.Throws<InvalidOperationException>(() => bad.ToCanonicalString());
    }
}
