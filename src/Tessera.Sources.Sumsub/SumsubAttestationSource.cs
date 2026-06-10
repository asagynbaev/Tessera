using Tessera.Attestations;

namespace Tessera.Sources.Sumsub;

/// <summary>
/// Layer-2 attestation source backed by Sumsub KYC. Resolves an approved applicant into
/// <c>kyc_verified</c> (with an optional <c>level</c> claim) and, when a country is known,
/// <c>jurisdiction</c> drafts. Returns nothing for unknown or not-yet-approved applicants.
/// </summary>
/// <remarks>
/// Swapping this provider out for another KYC vendor means writing another
/// <see cref="IAttestationSource"/> — no core or pipeline change. This package depends only on
/// <c>Tessera.Attestations</c> + <c>Tessera.Core</c>.
/// </remarks>
public sealed class SumsubAttestationSource : IAttestationSource
{
    /// <summary>SubjectContext parameter key carrying the Sumsub applicant id.</summary>
    public const string ApplicantIdKey = "sumsub_applicant_id";

    private readonly ISumsubClient _client;
    private readonly SumsubSourceOptions _options;

    public SumsubAttestationSource(ISumsubClient client, SumsubSourceOptions? options = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _options = options ?? new SumsubSourceOptions();
    }

    public string SourceId => "kyc.sumsub";

    public async Task<IReadOnlyList<AttestationDraft>> ResolveAsync(SubjectContext subject, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(subject);

        var applicantId = subject.Get(ApplicantIdKey) ?? subject.Get("applicant_id");
        if (string.IsNullOrWhiteSpace(applicantId))
            return Array.Empty<AttestationDraft>();

        var review = await _client.GetApplicantReviewAsync(applicantId, ct).ConfigureAwait(false);
        if (review is null || !review.Approved)
            return Array.Empty<AttestationDraft>();

        var drafts = new List<AttestationDraft>
        {
            new(
                AttestationTypes.KycVerified,
                new AttestationPayload
                {
                    Method = "sumsub",
                    Claims = review.LevelName is { Length: > 0 } level
                        ? new Dictionary<string, object> { ["level"] = level }
                        : null,
                },
                _options.KycValidity),
        };

        if (!string.IsNullOrWhiteSpace(review.Country))
        {
            drafts.Add(new AttestationDraft(
                AttestationTypes.Jurisdiction,
                new AttestationPayload
                {
                    Method = "sumsub",
                    Claims = new Dictionary<string, object> { ["country"] = review.Country! },
                },
                _options.JurisdictionValidity));
        }

        return drafts;
    }
}

/// <summary>Validity windows for the drafts this source emits.</summary>
public sealed record SumsubSourceOptions
{
    public TimeSpan KycValidity { get; init; } = TimeSpan.FromDays(365);
    public TimeSpan JurisdictionValidity { get; init; } = TimeSpan.FromDays(365);
}
