using System.Security.Cryptography;

namespace Tessera.Agents.HttpMessageSignatures;

/// <summary>
/// RFC 9530 <c>Content-Digest</c> over a request/response body. Only <c>sha-256</c> is produced;
/// verification also accepts <c>sha-512</c> if a peer used it. The digest is a structured-field
/// byte sequence: <c>sha-256=:BASE64:</c>.
/// </summary>
internal static class ContentDigest
{
    public const string HeaderName = "content-digest";

    /// <summary>Format the <c>Content-Digest</c> header value for <paramref name="body"/> using SHA-256.</summary>
    public static string ForBody(ReadOnlySpan<byte> body)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(body, hash);
        return $"sha-256=:{Convert.ToBase64String(hash)}:";
    }

    /// <summary>
    /// Verify that <paramref name="headerValue"/> (an RFC 9530 <c>Content-Digest</c>) matches
    /// <paramref name="body"/>. Checks every algorithm entry present that we understand; an entry
    /// with an unknown algorithm is ignored, but at least one understood entry must match.
    /// </summary>
    public static bool Matches(string headerValue, ReadOnlySpan<byte> body)
    {
        var understood = 0;
        foreach (var entry in headerValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = entry.IndexOf('=');
            if (eq <= 0) continue;
            var alg = entry[..eq].Trim();
            var value = entry[(eq + 1)..].Trim();
            if (value.Length < 2 || value[0] != ':' || value[^1] != ':') continue;
            var b64 = value[1..^1];

            byte[] expected;
            switch (alg)
            {
                case "sha-256": expected = SHA256.HashData(body.ToArray()); break;
                case "sha-512": expected = SHA512.HashData(body.ToArray()); break;
                default: continue; // unknown algorithm — skip
            }

            understood++;
            byte[] got;
            try { got = Convert.FromBase64String(b64); }
            catch (FormatException) { return false; }
            if (!CryptographicOperations.FixedTimeEquals(got, expected)) return false;
        }

        return understood > 0;
    }
}
