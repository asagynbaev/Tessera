using System.Text;
using Tessera.Core;
using Tessera.Signing;

namespace Tessera.Agents.HttpMessageSignatures;

/// <summary>Options for verifying an incoming signed HTTP request (RFC 9421, <c>did:tessera</c> profile).</summary>
public sealed class HttpSignatureVerificationOptions
{
    /// <summary>
    /// The signer's 32-byte Ed25519 public key, when known ahead of time (single-key case). Takes
    /// precedence over <see cref="ResolvePublicKey"/>.
    /// </summary>
    public byte[]? PublicKey { get; init; }

    /// <summary>
    /// Resolve the signer's Ed25519 public key from the signature <c>keyid</c>. In the
    /// <c>did:tessera</c> profile the caller supplies the agent's controller key (e.g. from the
    /// agent's <c>agent_identity</c> presentation, or a key directory).
    /// </summary>
    public Func<string, byte[]?>? ResolvePublicKey { get; init; }

    /// <summary>
    /// Require the <c>keyid</c> to be a <c>did:tessera</c> DID that re-derives from the resolved public
    /// key (<c>DidId.FromControllerKey(pubkey) == keyid</c>) — the DID authenticates the key with no
    /// registry lookup. Default true. Set false for non-DID keyids (e.g. Web Bot Auth key directories).
    /// </summary>
    public bool RequireDidKeyIdMatch { get; init; } = true;

    /// <summary>
    /// Reject a signature older than this, based on its <c>created</c> parameter. Bounds the replay
    /// window — a captured request can be replayed until it ages out. Defaults to 5 minutes; set to
    /// <c>null</c> to disable the age check (not recommended without a nonce/replay store).
    /// </summary>
    public TimeSpan? MaxAge { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Allowed clock skew for <c>created</c> / <c>expires</c> checks. Default 1 minute.</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>When set, require the signature's <c>tag</c> parameter to equal this value.</summary>
    public string? ExpectedTag { get; init; }

    /// <summary>Recompute and check the <c>Content-Digest</c> when it is a covered component. Default true.</summary>
    public bool VerifyContentDigest { get; init; } = true;

    /// <summary>
    /// Components the signature MUST cover, else it is rejected (<c>missing_required_component</c>) —
    /// the defense against a signature-scope downgrade, where an otherwise-valid signature covers too
    /// little to trust the parts a relying party cares about. When null, a safe default is enforced:
    /// <c>@method</c>, <c>@authority</c>, <c>@path</c>, plus <c>content-digest</c> when the request has
    /// a body (so the body is always authenticated). Pass an explicit list to widen or narrow it, or an
    /// empty list to disable the check.
    /// </summary>
    public IReadOnlyList<string>? RequiredComponents { get; init; }

    /// <summary>Structured-field label to verify. Default <c>sig1</c>.</summary>
    public string Label { get; init; } = "sig1";

    /// <summary>Clock for freshness checks. Defaults to the system clock.</summary>
    public TimeProvider? Clock { get; init; }
}

/// <summary>Outcome of verifying an HTTP message signature.</summary>
public sealed record HttpSignatureVerificationResult
{
    public required bool Valid { get; init; }

    /// <summary>Machine-readable failure reason, or null when valid.</summary>
    public string? Reason { get; init; }

    /// <summary>The signature <c>keyid</c>, when one was present.</summary>
    public string? KeyId { get; init; }

    /// <summary>
    /// The signer's DID, populated ONLY when the <c>keyid</c> was a well-formed <c>did:tessera</c> AND
    /// the DID was verified to re-derive from the signing key (i.e. <c>RequireDidKeyIdMatch</c> was
    /// true). Null otherwise — do not treat the <c>keyid</c> as an authenticated identity when this is null.
    /// </summary>
    public DidId? SignerDid { get; init; }

    /// <summary>Covered components that were verified, in order.</summary>
    public IReadOnlyList<string> CoveredComponents { get; init; } = Array.Empty<string>();

    internal static HttpSignatureVerificationResult Fail(string reason, string? keyId = null) =>
        new() { Valid = false, Reason = reason, KeyId = keyId };
}

/// <summary>
/// Verifies an RFC 9421 HTTP Message Signature on an incoming request against an agent's
/// <c>did:tessera</c> Ed25519 controller key. Confirms the signature over the reconstructed base, that
/// the <c>keyid</c> DID re-derives from the key, freshness (<c>created</c>/<c>expires</c>), an optional
/// tag, and the <c>Content-Digest</c> of the body.
/// </summary>
public static class HttpMessageVerifier
{
    public static async Task<HttpSignatureVerificationResult> VerifyAsync(
        HttpRequestMessage request,
        HttpSignatureVerificationOptions options,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(options);

        var inputHeader = GetHeader(request, "Signature-Input");
        var signatureHeader = GetHeader(request, "Signature");
        if (inputHeader is null || signatureHeader is null)
            return HttpSignatureVerificationResult.Fail("missing_signature_headers");

        var input = SignatureHeaders.ParseInput(inputHeader, options.Label);
        if (input is null)
            return HttpSignatureVerificationResult.Fail("malformed_signature_input");

        var signature = SignatureHeaders.ParseSignature(signatureHeader, options.Label);
        if (signature is null)
            return HttpSignatureVerificationResult.Fail("malformed_signature");

        var missing = MissingRequiredComponent(request, options, input.Components);
        if (missing is not null)
            return HttpSignatureVerificationResult.Fail($"missing_required_component:{missing}");

        var keyId = input.Parameters.KeyId;
        if (string.IsNullOrEmpty(keyId))
            return HttpSignatureVerificationResult.Fail("missing_keyid");

        if (input.Parameters.Alg is { } alg && !string.Equals(alg, "ed25519", StringComparison.OrdinalIgnoreCase))
            return HttpSignatureVerificationResult.Fail("unsupported_alg", keyId);

        var publicKey = options.PublicKey ?? options.ResolvePublicKey?.Invoke(keyId);
        if (publicKey is not { Length: Ed25519.PublicKeySize })
            return HttpSignatureVerificationResult.Fail("unknown_key", keyId);

        DidId? signerDid = null;
        if (options.RequireDidKeyIdMatch)
        {
            var keyIdDid = new DidId(keyId);
            if (!keyIdDid.IsWellFormed)
                return HttpSignatureVerificationResult.Fail("keyid_not_did", keyId);
            if (DidId.FromControllerKey(publicKey) != keyIdDid)
                return HttpSignatureVerificationResult.Fail("keyid_did_mismatch", keyId);
            signerDid = keyIdDid; // verified: the DID re-derives from the signing key
        }

        // Rebuild the base from the covered components plus the verbatim signature-params value.
        string baseString;
        try
        {
            baseString = SignatureBase.Build(request, input.Components, input.RawValue);
        }
        catch (SignatureComponentException ex)
        {
            return HttpSignatureVerificationResult.Fail($"unresolved_component:{ex.Component}", keyId);
        }

        if (!Ed25519.Verify(publicKey, Encoding.UTF8.GetBytes(baseString), signature))
            return HttpSignatureVerificationResult.Fail("bad_signature", keyId);

        var freshness = CheckFreshness(input.Parameters, options);
        if (freshness is not null)
            return HttpSignatureVerificationResult.Fail(freshness, keyId);

        if (options.ExpectedTag is { } expectedTag && input.Parameters.Tag != expectedTag)
            return HttpSignatureVerificationResult.Fail("tag_mismatch", keyId);

        if (options.VerifyContentDigest && input.Components.Contains(ContentDigest.HeaderName))
        {
            var digestHeader = GetHeader(request, "Content-Digest");
            var body = request.Content is null
                ? Array.Empty<byte>()
                : await request.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            if (digestHeader is null || !ContentDigest.Matches(digestHeader, body))
                return HttpSignatureVerificationResult.Fail("content_digest_mismatch", keyId);
        }

        return new HttpSignatureVerificationResult
        {
            Valid = true,
            KeyId = keyId,
            SignerDid = signerDid,
            CoveredComponents = input.Components,
        };
    }

    private static string? MissingRequiredComponent(
        HttpRequestMessage request,
        HttpSignatureVerificationOptions options,
        IReadOnlyList<string> covered)
    {
        IReadOnlyList<string> required;
        if (options.RequiredComponents is not null)
        {
            required = options.RequiredComponents;
        }
        else
        {
            // Safe default: bind the request line (incl. the query when present), and — when there is a
            // body — the body via its digest, so none of those can be swapped under a valid signature.
            var defaults = new List<string> { "@method", "@authority", "@path" };
            if (!string.IsNullOrEmpty(request.RequestUri?.Query))
                defaults.Add("@query");
            if (request.Content is not null)
                defaults.Add(ContentDigest.HeaderName);
            required = defaults;
        }

        foreach (var component in required)
            if (!covered.Contains(component))
                return component;
        return null;
    }

    // Bounds of DateTimeOffset in Unix seconds. A valid-but-out-of-range long would otherwise make
    // FromUnixTimeSeconds throw — and this runs outside the try/catch — so bounds-check and fail closed.
    private const long MinUnixSeconds = -62135596800;
    private const long MaxUnixSeconds = 253402300799;

    private static string? CheckFreshness(SignatureParameters p, HttpSignatureVerificationOptions options)
    {
        var now = (options.Clock ?? TimeProvider.System).GetUtcNow();
        var skew = options.ClockSkew;

        if (p.Created is not { } created)
            return "missing_created"; // no timestamp = no freshness bound
        if (!TryUnixSeconds(created, out var createdAt))
            return "created_out_of_range";
        if (createdAt - now > skew) return "created_in_future";
        if (options.MaxAge is { } maxAge && now - createdAt > maxAge + skew) return "signature_stale";

        if (p.Expires is { } expires)
        {
            if (!TryUnixSeconds(expires, out var expiresAt))
                return "expires_out_of_range";
            if (now - expiresAt > skew) return "signature_expired";
        }

        return null;
    }

    private static bool TryUnixSeconds(long seconds, out DateTimeOffset value)
    {
        if (seconds < MinUnixSeconds || seconds > MaxUnixSeconds)
        {
            value = default;
            return false;
        }
        value = DateTimeOffset.FromUnixTimeSeconds(seconds);
        return true;
    }

    private static string? GetHeader(HttpRequestMessage request, string name)
    {
        if (request.Headers.TryGetValues(name, out var values))
            return string.Join(", ", values);
        if (request.Content is not null && request.Content.Headers.TryGetValues(name, out var contentValues))
            return string.Join(", ", contentValues);
        return null;
    }
}
