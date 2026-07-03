namespace Tessera.Sources.Bitcoin.Tests;

public class BitcoinControlVerifierTests
{
    // Inside the fixture challenge's [iat, exp] window.
    private static FakeClock ClockInWindow() =>
        new(DateTimeOffset.FromUnixTimeSeconds(BitcoinTestVectors.IssuedAtUnix + 60));

    private static BitcoinControlVerifier Build(FakeClock clock, out InMemoryBitcoinControlStore store)
    {
        store = new InMemoryBitcoinControlStore();
        return new BitcoinControlVerifier(
            nonceStore: new InMemoryNonceStore(clock),
            controlStore: store,
            clock: clock);
    }

    [Fact]
    public void Ctor_RequiresExplicitNonceStore()
    {
        // M-1: there is no silent in-memory default on the production path — a durable store must be
        // passed deliberately (single-node/test callers pass new InMemoryNonceStore() on purpose).
        Assert.Throws<ArgumentNullException>(() => new BitcoinControlVerifier(nonceStore: null!));
    }

    [Fact]
    public async Task ValidProof_Succeeds_AndRecordsAddress()
    {
        var clock = ClockInWindow();
        var verifier = Build(clock, out var store);
        var v = BitcoinTestVectors.TestnetP2wpkh;

        var result = await verifier.VerifyAsync(
            BitcoinTestVectors.Challenge(), BitcoinTestVectors.Audience, v.Address, v.Signature, v.Network);

        Assert.True(result.IsValid, result.Reason);
        Assert.Equal(BitcoinAddressType.P2wpkh, result.AddressType);
        Assert.Equal(v.Address, result.Verified!.Address);

        var recorded = await store.GetVerifiedAsync(BitcoinTestVectors.Challenge().Subject);
        Assert.Single(recorded);
        Assert.Equal(v.Address, recorded[0].Address);
    }

    [Fact]
    public async Task Replay_SameAddressAndChallenge_Rejected()
    {
        var clock = ClockInWindow();
        var verifier = Build(clock, out _);
        var v = BitcoinTestVectors.TestnetP2pkh;

        Assert.True((await verifier.VerifyAsync(BitcoinTestVectors.Challenge(), BitcoinTestVectors.Audience, v.Address, v.Signature, v.Network)).IsValid);
        var replay = await verifier.VerifyAsync(BitcoinTestVectors.Challenge(), BitcoinTestVectors.Audience, v.Address, v.Signature, v.Network);
        Assert.False(replay.IsValid);
        Assert.Equal("nonce_replayed", replay.Reason);
    }

    [Fact]
    public async Task OneChallenge_SignedByMultipleAddresses_AllSucceed()
    {
        var clock = ClockInWindow();
        var verifier = Build(clock, out var store);
        var challenge = BitcoinTestVectors.Challenge();

        foreach (var v in new[] { BitcoinTestVectors.TestnetP2pkh, BitcoinTestVectors.TestnetP2shP2wpkh, BitcoinTestVectors.TestnetP2wpkh })
        {
            var r = await verifier.VerifyAsync(challenge, BitcoinTestVectors.Audience, v.Address, v.Signature, v.Network);
            Assert.True(r.IsValid, $"{v.Type}: {r.Reason}");
        }

        var recorded = await store.GetVerifiedAsync(challenge.Subject);
        Assert.Equal(3, recorded.Count);
    }

    [Fact]
    public async Task WrongAudience_Rejected()
    {
        var clock = ClockInWindow();
        var verifier = Build(clock, out _);
        var v = BitcoinTestVectors.TestnetP2wpkh;

        var result = await verifier.VerifyAsync(BitcoinTestVectors.Challenge(), "someone-else", v.Address, v.Signature, v.Network);
        Assert.False(result.IsValid);
        Assert.Equal("audience_mismatch", result.Reason);
    }

    [Fact]
    public async Task ExpiredChallenge_Rejected()
    {
        var clock = new FakeClock(DateTimeOffset.FromUnixTimeSeconds(BitcoinTestVectors.ExpiresAtUnix + 600));
        var verifier = Build(clock, out _);
        var v = BitcoinTestVectors.TestnetP2wpkh;

        var result = await verifier.VerifyAsync(BitcoinTestVectors.Challenge(), BitcoinTestVectors.Audience, v.Address, v.Signature, v.Network);
        Assert.False(result.IsValid);
        Assert.Equal("challenge_expired", result.Reason);
    }

    [Fact]
    public async Task ChallengeFromFuture_Rejected()
    {
        var clock = new FakeClock(DateTimeOffset.FromUnixTimeSeconds(BitcoinTestVectors.IssuedAtUnix - 600));
        var verifier = Build(clock, out _);
        var v = BitcoinTestVectors.TestnetP2wpkh;

        var result = await verifier.VerifyAsync(BitcoinTestVectors.Challenge(), BitcoinTestVectors.Audience, v.Address, v.Signature, v.Network);
        Assert.False(result.IsValid);
        Assert.Equal("challenge_not_yet_valid", result.Reason);
    }

    [Fact]
    public async Task InvalidSignature_DoesNotBurnNonce()
    {
        var clock = ClockInWindow();
        var verifier = Build(clock, out _);
        var v = BitcoinTestVectors.TestnetP2pkh;

        // Tamper r/s so recovery yields a different key → address_mismatch (signature invalid).
        var bytes = Convert.FromBase64String(v.Signature);
        bytes[5] ^= 0xFF;
        var badSig = Convert.ToBase64String(bytes);

        var bad = await verifier.VerifyAsync(BitcoinTestVectors.Challenge(), BitcoinTestVectors.Audience, v.Address, badSig, v.Network);
        Assert.False(bad.IsValid);

        // The good signature for the same (challenge, address) still succeeds — the nonce was not consumed.
        var good = await verifier.VerifyAsync(BitcoinTestVectors.Challenge(), BitcoinTestVectors.Audience, v.Address, v.Signature, v.Network);
        Assert.True(good.IsValid, good.Reason);
    }

    [Fact]
    public async Task Replay_InPostExpiryClockSkewWindow_Rejected()
    {
        // A challenge is still accepted up to clockSkew (2 min) after ExpiresAt. A captured signature
        // verified before expiry must NOT verify again inside that post-expiry skew window — the
        // replay token must outlive the acceptance window, not be evicted at ExpiresAt.
        var clock = new FakeClock(DateTimeOffset.FromUnixTimeSeconds(BitcoinTestVectors.ExpiresAtUnix - 60));
        var verifier = Build(clock, out _);
        var v = BitcoinTestVectors.TestnetP2wpkh;

        var first = await verifier.VerifyAsync(BitcoinTestVectors.Challenge(), BitcoinTestVectors.Audience, v.Address, v.Signature, v.Network);
        Assert.True(first.IsValid, first.Reason);

        clock.Set(DateTimeOffset.FromUnixTimeSeconds(BitcoinTestVectors.ExpiresAtUnix + 60)); // past expiry, within 2-min skew
        var replay = await verifier.VerifyAsync(BitcoinTestVectors.Challenge(), BitcoinTestVectors.Audience, v.Address, v.Signature, v.Network);
        Assert.False(replay.IsValid);
        Assert.Equal("nonce_replayed", replay.Reason);
    }

    [Fact]
    public async Task DegenerateWindow_ExpiresAtEqualsIssuedAt_Rejected()
    {
        var clock = new FakeClock(DateTimeOffset.FromUnixTimeSeconds(BitcoinTestVectors.IssuedAtUnix));
        var verifier = Build(clock, out _);
        var v = BitcoinTestVectors.TestnetP2wpkh;
        var challenge = BitcoinTestVectors.Challenge() with { ExpiresAt = BitcoinTestVectors.Challenge().IssuedAt };

        var result = await verifier.VerifyAsync(challenge, BitcoinTestVectors.Audience, v.Address, v.Signature, v.Network);
        Assert.False(result.IsValid);
        Assert.Equal("challenge_window_invalid", result.Reason);
    }

    [Fact]
    public async Task Taproot_Rejected_AsUnsupported()
    {
        var clock = ClockInWindow();
        var verifier = Build(clock, out _);

        var result = await verifier.VerifyAsync(
            BitcoinTestVectors.Challenge(), BitcoinTestVectors.Audience,
            BitcoinTestVectors.TestnetTaproot, BitcoinTestVectors.TestnetP2wpkh.Signature, BitcoinNetwork.Testnet);

        Assert.False(result.IsValid);
        Assert.Equal("taproot_bip322_unsupported", result.Reason);
    }
}
