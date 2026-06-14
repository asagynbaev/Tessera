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
/// <remarks>
/// <para>Depends only on <c>Tessera.Attestations</c> + <c>Tessera.Core</c>; swappable without core changes.</para>
/// <para>
/// SECURITY — identity binding and residual trust. The <c>national_id</c>/<c>parcel_id</c> lookup
/// keys arrive in <see cref="SubjectContext.Parameters"/> while the DID arrives independently in
/// <see cref="SubjectContext.Subject"/>. This source does NOT itself prove that the queried
/// <c>national_id</c> belongs to the DID — that binding MUST be established out-of-band by the
/// caller before invoking the issuance pipeline (e.g. an authenticated session in which the holder
/// proved control of both the DID and the national id, such as eID login). The caller is
/// responsible for that proof; passing an arbitrary national id for an arbitrary DID is a misuse.
/// </para>
/// <para>
/// Within that contract this source still defends two things itself: (1) it confirms the registry
/// RESPONSE is about the requested subject — when the response carries a server-asserted national
/// id (<see cref="XRoadRegistryRecord.AssertedNationalId"/>) it must equal the requested one, else
/// no drafts are emitted; and (2) the <c>parcel_id</c> stamped onto property/encumbrance claims is
/// the SERVER-asserted value, never the caller's raw query parameter. When the service contract
/// returns no server-asserted national id, the response-vs-request check is skipped and the
/// national_id↔DID trust assumption above is the only safeguard — see the TODO in
/// <see cref="XRoadHttpClient.MapRecord"/>.
/// </para>
/// </remarks>
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

        // Response-vs-request guard: if the registry asserted a national id in its response, it must
        // be the one we queried. This rejects a service that returns a record for a different person
        // than was requested. When the response carries no asserted id this check is skipped and the
        // documented national_id↔DID out-of-band trust assumption is the only safeguard.
        if (!string.IsNullOrWhiteSpace(record.AssertedNationalId) &&
            !string.Equals(record.AssertedNationalId, nationalId, StringComparison.Ordinal))
        {
            return Array.Empty<AttestationDraft>();
        }

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
