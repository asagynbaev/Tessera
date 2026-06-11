using System.Security.Cryptography;
using System.Text;
using Tessera.Core;

namespace Tessera.Sources.Bitcoin;

/// <summary>Outcome of a single control-verification attempt for one address.</summary>
public sealed record BitcoinControlResult(bool IsValid, VerifiedBitcoinAddress? Verified, BitcoinAddressType AddressType, string? Reason)
{
    /// <summary>A successful verification carrying the verified address.</summary>
    public static BitcoinControlResult Success(VerifiedBitcoinAddress verified) =>
        new(true, verified, verified.Type, null);

    /// <summary>A failed verification carrying the address type (if known) and a reason code.</summary>
    public static BitcoinControlResult Failure(BitcoinAddressType type, string reason) =>
        new(false, null, type, reason);
}

/// <summary>
/// Validates a holder's proof of control over a Bitcoin address: the challenge's audience and
/// expiry, the <c>signmessage</c> signature (via <see cref="BitcoinMessageSignatureVerifier"/>),
/// and nonce freshness (via <see cref="INonceStore"/>). On success the address is control-verified
/// and — when a <see cref="IBitcoinControlStore"/> is supplied — recorded for the subject so the
/// attestation source can compute facts over it.
/// </summary>
/// <remarks>
/// One challenge may be signed by several of the holder's addresses (the session). The nonce-replay
/// guard is therefore keyed per <c>(subject, nonce, address)</c>: a captured <c>(address, signature)</c>
/// tuple cannot be replayed, while the holder may still prove multiple addresses against one
/// challenge. The nonce is consumed only after the signature checks out, so an invalid attempt does
/// not burn the holder's nonce.
/// </remarks>
public sealed class BitcoinControlVerifier
{
    private readonly BitcoinMessageSignatureVerifier _signatures;
    private readonly INonceStore _nonceStore;
    private readonly IBitcoinControlStore? _controlStore;
    private readonly TimeProvider _clock;
    private readonly TimeSpan _clockSkew;

    /// <summary>
    /// All dependencies are optional: an <see cref="InMemoryNonceStore"/>, no control store, a fresh
    /// signature verifier, the system clock, and a 2-minute clock skew are used by default.
    /// </summary>
    public BitcoinControlVerifier(
        INonceStore? nonceStore = null,
        IBitcoinControlStore? controlStore = null,
        BitcoinMessageSignatureVerifier? signatures = null,
        TimeProvider? clock = null,
        TimeSpan? clockSkew = null)
    {
        _clock = clock ?? TimeProvider.System;
        _nonceStore = nonceStore ?? new InMemoryNonceStore(_clock);
        _controlStore = controlStore;
        _signatures = signatures ?? new BitcoinMessageSignatureVerifier();
        _clockSkew = clockSkew ?? TimeSpan.FromMinutes(2);
        if (_clockSkew < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(clockSkew), _clockSkew, "Clock skew must not be negative.");
    }

    /// <summary>
    /// Verify that <paramref name="signatureBase64"/> is a valid <c>signmessage</c> over
    /// <paramref name="challenge"/>'s canonical string for <paramref name="address"/>, that the
    /// challenge targets <paramref name="expectedAudience"/> and is unexpired, and that the
    /// (subject, nonce, address) tuple has not been used. Never throws.
    /// </summary>
    public async Task<BitcoinControlResult> VerifyAsync(
        BitcoinChallenge challenge,
        string expectedAudience,
        string address,
        string signatureBase64,
        BitcoinNetwork network,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedAudience);

        if (!string.Equals(challenge.Audience, expectedAudience, StringComparison.Ordinal))
            return BitcoinControlResult.Failure(BitcoinAddressType.Unknown, "audience_mismatch");

        var now = _clock.GetUtcNow();
        if (now > challenge.ExpiresAt + _clockSkew)
            return BitcoinControlResult.Failure(BitcoinAddressType.Unknown, "challenge_expired");
        if (now + _clockSkew < challenge.IssuedAt)
            return BitcoinControlResult.Failure(BitcoinAddressType.Unknown, "challenge_not_yet_valid");
        if (challenge.ExpiresAt <= challenge.IssuedAt)
            return BitcoinControlResult.Failure(BitcoinAddressType.Unknown, "challenge_window_invalid");

        var sig = _signatures.Verify(address, challenge.ToCanonicalString(), signatureBase64, network);
        if (!sig.IsValid)
            return BitcoinControlResult.Failure(sig.AddressType, sig.Reason ?? "signature_invalid");

        // Consume the per-address replay token only once the signature is valid, so a bad attempt
        // can't burn the holder's nonce. The token binds the address so one challenge can be signed
        // by several addresses while each (address, signature) stays single-use. The token's TTL is
        // the FULL acceptance window (ExpiresAt + skew), not just ExpiresAt — otherwise a store that
        // evicts at ExpiresAt would drop the record while the challenge is still accepted, letting a
        // captured signature replay during the post-expiry skew window.
        var replayToken = ReplayToken(challenge.Nonce, address.Trim());
        var fresh = await _nonceStore.TryConsumeAsync(challenge.Subject, replayToken, challenge.ExpiresAt + _clockSkew, ct).ConfigureAwait(false);
        if (!fresh)
            return BitcoinControlResult.Failure(sig.AddressType, "nonce_replayed");

        var verified = new VerifiedBitcoinAddress
        {
            Address = address.Trim(),
            Type = sig.AddressType,
            Network = network,
        };
        if (_controlStore is not null)
            await _controlStore.RecordVerifiedAsync(challenge.Subject, verified, ct).ConfigureAwait(false);

        return BitcoinControlResult.Success(verified);
    }

    private static byte[] ReplayToken(byte[] nonce, string address)
    {
        var addr = Encoding.UTF8.GetBytes(address);
        var buf = new byte[nonce.Length + 1 + addr.Length];
        Buffer.BlockCopy(nonce, 0, buf, 0, nonce.Length);
        buf[nonce.Length] = 0x00; // domain separator between nonce and address
        Buffer.BlockCopy(addr, 0, buf, nonce.Length + 1, addr.Length);
        return SHA256.HashData(buf);
    }
}
