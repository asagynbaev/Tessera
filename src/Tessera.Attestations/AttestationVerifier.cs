namespace Tessera.Attestations;

/// <summary>
/// Result of verifying a presentation or a single attestation.
/// </summary>
public sealed record VerificationResult
{
    public required bool Valid { get; init; }
    public string? Reason { get; init; }

    public static VerificationResult Ok() => new() { Valid = true };
    public static VerificationResult Fail(string reason) => new() { Valid = false, Reason = reason };
}

/// <summary>
/// Verifies that an attestation envelope is well-formed, unexpired, and signed by
/// a known active issuer.
/// </summary>
/// <remarks>
/// Signature verification is plugged in via <see cref="ISignatureVerifier"/> — the
/// same indirection pattern used by <c>DidService</c>. Callers can wire up Solnet,
/// NSec, BouncyCastle, etc. without making this package depend on a specific stack.
/// </remarks>
public sealed class AttestationVerifier
{
    private readonly IIssuerRegistry _issuers;
    private readonly ISignatureVerifier _verifier;
    private readonly TimeProvider _clock;
    private readonly TimeSpan? _maxAge;
    private readonly bool _requireExpiry;

    /// <param name="maxAttestationAge">
    /// When set, an attestation is rejected (<c>too_old</c>) once <c>now − IssuedAt</c> exceeds it.
    /// Caps the lifetime of credentials whose issuer set no <c>ExpiresAt</c>. Null = no age cap.
    /// </param>
    /// <param name="requireExpiry">
    /// When true, an attestation without an <c>ExpiresAt</c> is rejected (<c>missing_expiry</c>) so a
    /// sensitive credential cannot be valid forever. Default false (backward-compatible).
    /// </param>
    public AttestationVerifier(
        IIssuerRegistry issuers,
        ISignatureVerifier verifier,
        TimeProvider? clock = null,
        TimeSpan? maxAttestationAge = null,
        bool requireExpiry = false)
    {
        _issuers = issuers ?? throw new ArgumentNullException(nameof(issuers));
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        _clock = clock ?? TimeProvider.System;
        if (maxAttestationAge is { } age && age <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(maxAttestationAge), "Max attestation age must be positive.");
        _maxAge = maxAttestationAge;
        _requireExpiry = requireExpiry;
    }

    public async Task<VerificationResult> VerifyAsync(Attestation a, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(a);

        if (string.IsNullOrEmpty(a.Type)) return VerificationResult.Fail("missing_type");
        if (string.IsNullOrEmpty(a.Schema)) return VerificationResult.Fail("missing_schema");
        if (a.Signature is null || a.Signature.Value.Length == 0)
            return VerificationResult.Fail("missing_signature");

        var now = _clock.GetUtcNow();
        if (_requireExpiry && a.ExpiresAt is null)
            return VerificationResult.Fail("missing_expiry");
        if (a.ExpiresAt is { } exp && exp < now)
            return VerificationResult.Fail("expired");
        if (_maxAge is { } maxAge && now - a.IssuedAt > maxAge)
            return VerificationResult.Fail("too_old");

        if (a.IssuedAt > now.AddMinutes(5))
            return VerificationResult.Fail("issued_in_future");

        var issuer = await _issuers.ResolveAsync(a.Issuer, ct).ConfigureAwait(false);
        if (issuer is null) return VerificationResult.Fail("unknown_issuer");
        if (!issuer.Active) return VerificationResult.Fail("issuer_inactive");
        if (!string.Equals(issuer.Algorithm, a.Signature.Algorithm, StringComparison.Ordinal))
            return VerificationResult.Fail("algorithm_mismatch");

        var input = AttestationCanonical.BuildSigningInput(a);
        if (!_verifier.Verify(issuer.PublicKey, input, a.Signature.Value))
            return VerificationResult.Fail("bad_signature");

        return VerificationResult.Ok();
    }
}

/// <summary>
/// Plug-in signature verifier. Mirrors <c>Tessera.Did.ISignatureVerifier</c> but redeclared
/// here so that the Attestations package does not depend on the Did package.
/// </summary>
public interface ISignatureVerifier
{
    bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature);
}
