namespace Tessera.Attestations;

using System.Globalization;
using System.Text;
using Tessera.Core;

/// <summary>
/// Canonical byte representation of an attestation, used as the message that the
/// issuer signs and as the leaf hash input for Merkle bundling. The format is
/// deliberately field-ordered and length-prefixed so that two implementations
/// in any language produce the same bytes for the same logical attestation.
/// </summary>
public static class AttestationCanonical
{
    /// <summary>Domain separator. Bump on breaking format changes.</summary>
    public const string DomainSeparator = "Tessera/v1/attestation";

    /// <summary>
    /// Build the canonical byte sequence for an attestation envelope's signing input.
    /// Excludes <see cref="Attestation.Signature"/> (the signature signs everything else).
    /// </summary>
    public static byte[] BuildSigningInput(Attestation a)
    {
        ArgumentNullException.ThrowIfNull(a);
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);

        w.Write(DomainSeparator);
        w.Write(a.Schema);
        w.Write(a.Type);
        w.Write(a.Issuer.Value);
        w.Write(a.Subject.Value);
        w.Write(a.IssuedAt.ToUnixTimeMilliseconds());
        w.Write(a.ExpiresAt?.ToUnixTimeMilliseconds() ?? 0L);

        w.Write(a.Nonce.Length);
        w.Write(a.Nonce);

        w.Write(a.Payload.Method);
        var commitment = a.Payload.Commitment ?? Array.Empty<byte>();
        w.Write(commitment.Length);
        w.Write(commitment);

        // Claims are serialized as a sorted key/value sequence so that map ordering
        // does not change the canonical bytes.
        var claims = a.Payload.Claims;
        if (claims is null)
        {
            w.Write(0);
        }
        else
        {
            var ordered = claims.OrderBy(kv => kv.Key, StringComparer.Ordinal).ToArray();
            w.Write(ordered.Length);
            foreach (var kv in ordered)
            {
                w.Write(kv.Key);
                w.Write(FormatClaimValueInvariant(kv.Value));
            }
        }
        return ms.ToArray();
    }

    /// <summary>
    /// Culture-INVARIANT string form of a claim value. Numbers, decimals and dates are formatted with
    /// <see cref="CultureInfo.InvariantCulture"/> so an issuer and a verifier in different locales
    /// compute the SAME signing bytes — closing the cross-locale verification-DoS where, e.g., a
    /// <c>double</c> renders as <c>1234.5</c> in one culture and <c>1234,5</c> in another. Plain
    /// <see cref="string"/> and <see cref="bool"/> already round-trip culture-independently, so their
    /// bytes are unchanged (the canonical form stays backward-compatible for string-valued claims —
    /// the only kind Tessera's own sources emit).
    /// </summary>
    /// <remarks>
    /// NOTE (hardening follow-up): this format still does not tag the value's CLR type, so an integer
    /// <c>123</c> and the string <c>"123"</c> canonicalize identically. Issuers should use
    /// string-valued claims for cross-implementation determinism; a future major version may switch to
    /// a type-tagged, length-framed claim encoding (a breaking wire change).
    /// </remarks>
    private static string FormatClaimValueInvariant(object? value) => value switch
    {
        null => "",
        string s => s,
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString() ?? "",
    };
}
