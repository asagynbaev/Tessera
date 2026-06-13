namespace Tessera.Sources.XRoad;

/// <summary>
/// Abstraction over an X-Road government-registry query. The plugin depends on this rather than a
/// concrete transport, so the registry/service is swappable and unit tests inject a fake. The
/// production implementation is <see cref="XRoadHttpClient"/>.
/// </summary>
public interface IXRoadClient
{
    /// <summary>Look up a subject (and optional parcel) in the registry; null if nothing was found.</summary>
    Task<XRoadRegistryRecord?> LookupAsync(XRoadQuery query, CancellationToken ct = default);
}

/// <summary>What to look up. At least a national id is required for a person lookup.</summary>
public sealed record XRoadQuery
{
    public string? NationalId { get; init; }
    public string? ParcelId { get; init; }
}

/// <summary>The registry facts the plugin distills into attestations. Contains no raw PII.</summary>
public sealed record XRoadRegistryRecord
{
    /// <summary>True if the person was found in the population registry.</summary>
    public required bool PersonFound { get; init; }

    /// <summary>
    /// The national id the registry SERVER asserted for the matched person, as carried in the
    /// response body (not echoed from the query). Used by the source to confirm the response is
    /// about the requested subject. Null when the service contract does not return one — see the
    /// residual-trust note on <see cref="XRoadAttestationSource"/>.
    /// </summary>
    public string? AssertedNationalId { get; init; }

    /// <summary>Residency country (ISO-3166 alpha-2), if registered.</summary>
    public string? ResidencyCountry { get; init; }

    /// <summary>True if the subject is the confirmed owner of the queried parcel.</summary>
    public bool PropertyOwnershipConfirmed { get; init; }

    /// <summary>
    /// The parcel id the SERVER asserted ownership for, taken from the response body. The source
    /// emits this server-asserted value into the <c>parcel_id</c> claim — never the caller's raw
    /// query parameter — so a caller cannot have a claim minted for a parcel the registry did not
    /// confirm. Null when the response omits it.
    /// </summary>
    public string? ParcelId { get; init; }

    /// <summary>Encumbrance status on the parcel (e.g. <c>"none"</c>, <c>"mortgage"</c>, <c>"arrest"</c>).</summary>
    public string? EncumbranceStatus { get; init; }
}
