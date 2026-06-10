namespace Tessera.Attestations;

using Tessera.Core;

/// <summary>
/// A pluggable source of attestation content. Implementations turn an external proof
/// (a KYC provider's result, a government-registry lookup, ...) into one or more
/// <see cref="AttestationDraft"/>s for a subject. The source never signs — signing is the
/// issuer's job in the issuance pipeline — and it carries no provider specifics into the core:
/// concrete sources live in their own satellite packages.
/// </summary>
public interface IAttestationSource
{
    /// <summary>Stable identifier of this source (e.g. <c>"kyc.acme"</c>, <c>"registry.xroad"</c>). For diagnostics/audit.</summary>
    string SourceId { get; }

    /// <summary>
    /// Resolve the attestation drafts this source can produce for the subject. May call out to
    /// an external service. Returns an empty list when the source has nothing to attest.
    /// </summary>
    Task<IReadOnlyList<AttestationDraft>> ResolveAsync(SubjectContext subject, CancellationToken ct = default);
}

/// <summary>
/// An unsigned attestation the issuer will sign. The <see cref="Validity"/> is a lifetime;
/// <see cref="TimeSpan.Zero"/> (or negative) means "no expiry".
/// </summary>
public sealed record AttestationDraft(string Type, AttestationPayload Payload, TimeSpan Validity = default)
{
    /// <summary>Lifetime as a nullable suitable for the issuer (null = no expiry).</summary>
    public TimeSpan? ValidityOrNull => Validity > TimeSpan.Zero ? Validity : null;
}

/// <summary>
/// Inputs a source needs to resolve drafts for a subject. <see cref="Subject"/> is the DID the
/// attestations are about; <see cref="Parameters"/> carries source-specific lookup keys
/// (an applicant id, a national-id reference, ...) without the core knowing their meaning.
/// </summary>
public sealed record SubjectContext
{
    public required DidId Subject { get; init; }

    public IReadOnlyDictionary<string, string> Parameters { get; init; } =
        new Dictionary<string, string>();

    /// <summary>Convenience lookup; returns null when the key is absent.</summary>
    public string? Get(string key) => Parameters.TryGetValue(key, out var v) ? v : null;
}
