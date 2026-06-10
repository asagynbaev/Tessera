using Tessera.Attestations;

namespace Tessera.Sources.XRoad;

/// <summary>Domain attestation types this registry source emits beyond the standard ones.</summary>
public static class XRoadAttestationTypes
{
    public const string PropertyRight = "property_right";
    public const string Encumbrance = "encumbrance";
}

/// <summary>
/// Layer-2 attestation source backed by a government registry reached over X-Road. Distills a
/// registry lookup into <c>jurisdiction</c> (residency), <c>property_right</c>, and
/// <c>encumbrance</c> drafts. Returns nothing when the subject is not found.
/// </summary>
/// <remarks>Depends only on <c>Tessera.Attestations</c> + <c>Tessera.Core</c>; swappable without core changes.</remarks>
public sealed class XRoadAttestationSource : IAttestationSource
{
    /// <summary>SubjectContext key carrying the subject's national id.</summary>
    public const string NationalIdKey = "national_id";

    /// <summary>SubjectContext key carrying a parcel id to confirm ownership/encumbrance for.</summary>
    public const string ParcelIdKey = "parcel_id";

    private readonly IXRoadClient _client;
    private readonly XRoadSourceOptions _options;

    public XRoadAttestationSource(IXRoadClient client, XRoadSourceOptions? options = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _options = options ?? new XRoadSourceOptions();
    }

    public string SourceId => "registry.xroad";

    public async Task<IReadOnlyList<AttestationDraft>> ResolveAsync(SubjectContext subject, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(subject);

        var nationalId = subject.Get(NationalIdKey);
        if (string.IsNullOrWhiteSpace(nationalId))
            return Array.Empty<AttestationDraft>();

        var record = await _client.LookupAsync(
            new XRoadQuery { NationalId = nationalId, ParcelId = subject.Get(ParcelIdKey) }, ct).ConfigureAwait(false);
        if (record is null || !record.PersonFound)
            return Array.Empty<AttestationDraft>();

        var drafts = new List<AttestationDraft>();

        if (!string.IsNullOrWhiteSpace(record.ResidencyCountry))
        {
            drafts.Add(new AttestationDraft(
                AttestationTypes.Jurisdiction,
                new AttestationPayload { Method = "xroad", Claims = new Dictionary<string, object> { ["country"] = record.ResidencyCountry! } },
                _options.ResidencyValidity));
        }

        if (record.PropertyOwnershipConfirmed && !string.IsNullOrWhiteSpace(record.ParcelId))
        {
            drafts.Add(new AttestationDraft(
                XRoadAttestationTypes.PropertyRight,
                new AttestationPayload { Method = "xroad", Claims = new Dictionary<string, object> { ["parcel_id"] = record.ParcelId! } },
                _options.PropertyValidity));
        }

        if (!string.IsNullOrWhiteSpace(record.EncumbranceStatus) && !string.IsNullOrWhiteSpace(record.ParcelId))
        {
            drafts.Add(new AttestationDraft(
                XRoadAttestationTypes.Encumbrance,
                new AttestationPayload
                {
                    Method = "xroad",
                    Claims = new Dictionary<string, object> { ["parcel_id"] = record.ParcelId!, ["status"] = record.EncumbranceStatus! },
                },
                _options.EncumbranceValidity));
        }

        return drafts;
    }
}

/// <summary>Validity windows for the drafts this source emits.</summary>
public sealed record XRoadSourceOptions
{
    public TimeSpan ResidencyValidity { get; init; } = TimeSpan.FromDays(180);
    public TimeSpan PropertyValidity { get; init; } = TimeSpan.FromDays(90);
    public TimeSpan EncumbranceValidity { get; init; } = TimeSpan.FromDays(30);
}
