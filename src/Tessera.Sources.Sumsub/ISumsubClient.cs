namespace Tessera.Sources.Sumsub;

/// <summary>
/// Abstraction over the Sumsub applicant API. The plugin depends on this, not on a concrete
/// HTTP client, so the provider is swappable and unit tests inject a fake. The production
/// implementation is <see cref="SumsubHttpClient"/>.
/// </summary>
public interface ISumsubClient
{
    /// <summary>Fetch an applicant's current review, or null if the applicant is unknown.</summary>
    Task<SumsubApplicantReview?> GetApplicantReviewAsync(string applicantId, CancellationToken ct = default);
}

/// <summary>The verification outcome the plugin needs, distilled from Sumsub's applicant payload.</summary>
public sealed record SumsubApplicantReview
{
    public required string ApplicantId { get; init; }

    /// <summary>True when the review completed with a positive answer (<c>reviewAnswer == "GREEN"</c>).</summary>
    public required bool Approved { get; init; }

    /// <summary>Raw review answer (<c>GREEN</c> / <c>RED</c>), for diagnostics.</summary>
    public string? ReviewAnswer { get; init; }

    /// <summary>
    /// The <c>externalUserId</c> Sumsub recorded for this applicant at creation time. Integrators
    /// MUST set this to the subject DID so the attestation source can prove the applicant belongs
    /// to the DID it is signing claims onto. Null/absent when the integrator never bound one, in
    /// which case the source refuses to emit drafts.
    /// </summary>
    public string? ExternalUserId { get; init; }

    /// <summary>The Sumsub level name the applicant cleared (mapped to the kyc <c>level</c> claim).</summary>
    public string? LevelName { get; init; }

    /// <summary>Verified country (as reported by Sumsub). Mapped to the jurisdiction <c>country</c> claim.</summary>
    public string? Country { get; init; }
}
