using System.Text.Json;

namespace Tessera.Sources.XRoad;

/// <summary>
/// Production <see cref="IXRoadClient"/> over an X-Road security server (REST message protocol)
/// using an injected <see cref="HttpClient"/>. Each request carries the mandatory
/// <c>X-Road-Client</c> header identifying the consumer subsystem; the registry service is
/// addressed by its X-Road service id in the request path.
/// </summary>
/// <remarks>
/// X-Road service semantics vary per member registry. The JSON mapping here targets a generic
/// person/property response; adapt <see cref="MapRecord"/> to your specific service contract.
/// Credentials/endpoints are configuration. Unit tests cover request construction and mapping.
/// </remarks>
public sealed class XRoadHttpClient : IXRoadClient
{
    private readonly HttpClient _http;
    private readonly XRoadHttpClientOptions _options;

    public XRoadHttpClient(HttpClient http, XRoadHttpClientOptions options)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        ArgumentException.ThrowIfNullOrEmpty(options.SecurityServerUrl);
        ArgumentException.ThrowIfNullOrEmpty(options.ClientId);
        ArgumentException.ThrowIfNullOrEmpty(options.ServiceId);
    }

    public async Task<XRoadRegistryRecord?> LookupAsync(XRoadQuery query, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (string.IsNullOrWhiteSpace(query.NationalId))
            return null;

        using var request = BuildRequest(query);
        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            return null;
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
        return MapRecord(query.ParcelId, doc.RootElement);
    }

    internal HttpRequestMessage BuildRequest(XRoadQuery query)
    {
        // X-Road REST address: {securityServer}/r1/{serviceId}/persons/{nationalId}?parcel={parcelId}
        var path = $"/r1/{_options.ServiceId}/persons/{Uri.EscapeDataString(query.NationalId!)}";
        if (!string.IsNullOrWhiteSpace(query.ParcelId))
            path += $"?parcel={Uri.EscapeDataString(query.ParcelId!)}";

        var request = new HttpRequestMessage(HttpMethod.Get, new Uri(new Uri(_options.SecurityServerUrl), path));
        request.Headers.Add("X-Road-Client", _options.ClientId);
        request.Headers.Accept.ParseAdd("application/json");
        return request;
    }

    internal static XRoadRegistryRecord MapRecord(string? parcelId, JsonElement root)
    {
        var personFound = root.TryGetProperty("personFound", out var pf) && pf.ValueKind == JsonValueKind.True;
        string? residency = root.TryGetProperty("residencyCountry", out var rc) ? rc.GetString() : null;

        var ownershipConfirmed = root.TryGetProperty("property", out var prop)
            && prop.TryGetProperty("ownershipConfirmed", out var oc) && oc.ValueKind == JsonValueKind.True;
        string? encumbrance = root.TryGetProperty("property", out var prop2) && prop2.TryGetProperty("encumbrance", out var enc)
            ? enc.GetString()
            : null;

        return new XRoadRegistryRecord
        {
            PersonFound = personFound,
            ResidencyCountry = residency,
            PropertyOwnershipConfirmed = ownershipConfirmed,
            ParcelId = parcelId,
            EncumbranceStatus = encumbrance,
        };
    }
}

/// <summary>Configuration for <see cref="XRoadHttpClient"/>.</summary>
public sealed record XRoadHttpClientOptions
{
    /// <summary>Base URL of the X-Road security server proxy.</summary>
    public required string SecurityServerUrl { get; init; }

    /// <summary>Consumer subsystem id sent in <c>X-Road-Client</c> (e.g. <c>"KZ/GOV/1234/tessera"</c>).</summary>
    public required string ClientId { get; init; }

    /// <summary>The registry service id segment used to address the producer service.</summary>
    public required string ServiceId { get; init; }
}
