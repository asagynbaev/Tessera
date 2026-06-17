using System.Security.Cryptography;
using System.Text;
using Tessera.Core;

namespace Tessera.Sources.Bitcoin;

/// <summary>
/// An anti-replay challenge a holder signs with each Bitcoin address to prove control. The
/// holder runs the canonical string (<see cref="ToCanonicalString"/>) through their wallet's
/// <c>signmessage</c> and returns the signature per address; the verifier rebuilds the same
/// canonical string and checks the signature, the audience, the expiry, and nonce freshness.
/// </summary>
/// <remarks>
/// <para><b>Canonical string — byte-exact.</b> UTF-8, six lines joined by a single LF
/// (<c>0x0A</c>), no trailing newline, fixed field order, with a domain-separation prefix on the
/// first line so a Tessera challenge can never collide with another protocol's signed message:</para>
/// <code>
/// tessera-btc-v1\n
/// sub=&lt;subject DID&gt;\n
/// aud=&lt;audience&gt;\n
/// nonce=&lt;lowercase hex of the nonce bytes&gt;\n
/// iat=&lt;issued-at, Unix seconds&gt;\n
/// exp=&lt;expires-at, Unix seconds&gt;
/// </code>
/// <para>e.g. <c>tessera-btc-v1\nsub=did:tessera:abc\naud=aureus\nnonce=8f3c...\niat=1700000000\nexp=1700000600</c>.</para>
/// </remarks>
public sealed record BitcoinChallenge
{
    /// <summary>Domain-separation prefix, the first line of every canonical challenge string.</summary>
    public const string DomainPrefix = "tessera-btc-v1";

    /// <summary>The DID the proven addresses will be attested to.</summary>
    public required DidId Subject { get; init; }

    /// <summary>Random nonce, at least 16 bytes. Single-use (enforced via <see cref="INonceStore"/>).</summary>
    public required byte[] Nonce { get; init; }

    /// <summary>When the challenge was issued.</summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>When the challenge expires. Signatures presented after this are rejected.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Intended audience (the relying party / issuer id). Binds the proof to one verifier.</summary>
    public required string Audience { get; init; }

    /// <summary>
    /// Create a fresh challenge with a random nonce. <paramref name="nonceBytes"/> must be ≥ 16.
    /// </summary>
    public static BitcoinChallenge Create(
        DidId subject,
        string audience,
        TimeSpan validity,
        TimeProvider? clock = null,
        int nonceBytes = 32)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        if (nonceBytes < 16)
            throw new ArgumentOutOfRangeException(nameof(nonceBytes), nonceBytes, "Nonce must be at least 16 bytes.");
        if (validity <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(validity), validity, "Validity must be positive.");

        var now = (clock ?? TimeProvider.System).GetUtcNow();
        return new BitcoinChallenge
        {
            Subject = subject,
            Audience = audience,
            Nonce = RandomNumberGenerator.GetBytes(nonceBytes),
            IssuedAt = now,
            ExpiresAt = now + validity,
        };
    }

    /// <summary>
    /// The exact UTF-8 string the holder signs with their wallet. See the type remarks for the
    /// byte-exact layout. Deterministic: the same challenge always yields the same bytes.
    /// </summary>
    public string ToCanonicalString()
    {
        if (Nonce is null || Nonce.Length < 16)
            throw new InvalidOperationException("Challenge nonce must be at least 16 bytes.");
        // The canonical string is line-joined, so a field containing a line separator would make the
        // signed bytes ambiguous (two different (sub, aud) interpretations could share one signature).
        if (HasLineBreak(Subject.Value) || HasLineBreak(Audience))
            throw new InvalidOperationException("Challenge subject/audience must not contain line breaks.");

        var nonceHex = Convert.ToHexString(Nonce).ToLowerInvariant();
        var sb = new StringBuilder();
        sb.Append(DomainPrefix).Append('\n');
        sb.Append("sub=").Append(Subject.Value).Append('\n');
        sb.Append("aud=").Append(Audience).Append('\n');
        sb.Append("nonce=").Append(nonceHex).Append('\n');
        sb.Append("iat=").Append(IssuedAt.ToUnixTimeSeconds()).Append('\n');
        sb.Append("exp=").Append(ExpiresAt.ToUnixTimeSeconds());
        return sb.ToString();
    }

    /// <summary>The canonical string encoded as UTF-8 bytes.</summary>
    public byte[] ToCanonicalBytes() => Encoding.UTF8.GetBytes(ToCanonicalString());

    private static bool HasLineBreak(string s) => s.Contains('\n') || s.Contains('\r');
}
