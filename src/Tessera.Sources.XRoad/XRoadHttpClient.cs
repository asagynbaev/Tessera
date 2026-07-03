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

        // X-Road carries registry PII and relies on mutually-authenticated TLS between security
        // servers; refuse to talk to a security server over cleartext. The injected HttpClient is
        // expected to be configured with the consumer's mTLS client certificate and to pin/verify
        // the security server's certificate.
        if (!Uri.TryCreate(options.SecurityServerUrl, UriKind.Absolute, out var serverUri))
            throw new ArgumentException(
                $"SecurityServerUrl must be an absolute URL: '{options.SecurityServerUrl}'.", nameof(options));
        if (!string.Equals(serverUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException(
                $"SecurityServerUrl must use https (mTLS-configured HttpClient + cert pinning required): '{options.SecurityServerUrl}'.",
                nameof(options));
        if (string.IsNullOrWhiteSpace(serverUri.Host))
            throw new ArgumentException(
                $"SecurityServerUrl must have a non-empty host: '{options.SecurityServerUrl}'.", nameof(options));
    }

    /// <summary>
    /// An <see cref="HttpClientHandler"/> hardened for this client: <see cref="HttpClientHandler.AllowAutoRedirect"/>
    /// is <c>false</c>. An X-Road security server is a single hop and never legitimately returns a
    /// redirect, so following one would only replay the <c>X-Road-Client</c> subsystem header to an
    /// attacker-chosen target. The injected <see cref="HttpClient"/> MUST be built on a handler
    /// configured this way (in addition to the consumer's mTLS client certificate) — use
    /// <see cref="CreateHardenedHandler"/> as the base, or apply the same setting to your own handler.
    /// </summary>
    public static HttpClientHandler CreateHardenedHandler() => new() { AllowAutoRedirect = false };

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
        return MapRecord(query, doc.RootElement);
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

    internal static XRoadRegistryRecord MapRecord(XRoadQuery query, JsonElement root)
    {
        var personFound = root.TryGetProperty("personFound", out var pf) && pf.ValueKind == JsonValueKind.True;
        string? residency = root.TryGetProperty("residencyCountry", out var rc) ? rc.GetString() : null;

        // Prefer the SERVER-asserted national id from the response body. The source uses this to
        // confirm the response is about the requested subject; we never let the caller's query
        // parameter silently become the asserted identity. TODO: confirm the exact response field
        // ("nationalId") against your member registry's service contract.
        string? assertedNationalId = root.TryGetProperty("nationalId", out var nid) ? nid.GetString() : null;

        var ownershipConfirmed = root.TryGetProperty("property", out var prop)
            && prop.TryGetProperty("ownershipConfirmed", out var oc) && oc.ValueKind == JsonValueKind.True;
        string? encumbrance = root.TryGetProperty("property", out var prop2) && prop2.TryGetProperty("encumbrance", out var enc)
            ? enc.GetString()
            : null;

        // The parcel id stamped onto property/encumbrance claims is the SERVER-asserted one from
        // the response, NOT the caller's query parameter. Fall back to the query parcel id only
        // when the response omits it; in that case the residual trust assumption (documented on
        // XRoadAttestationSource) applies. TODO: confirm the response parcel field shape.
        string? assertedParcelId = null;
        if (root.TryGetProperty("property", out var prop3) && prop3.TryGetProperty("parcelId", out var pid))
            assertedParcelId = pid.GetString();
        assertedParcelId ??= query.ParcelId;

        return new XRoadRegistryRecord
        {
            PersonFound = personFound,
            AssertedNationalId = assertedNationalId,
            ResidencyCountry = residency,
            PropertyOwnershipConfirmed = ownershipConfirmed,
            ParcelId = assertedParcelId,
            EncumbranceStatus = encumbrance,
        };
    }
}

/// <summary>Configuration for <see cref="XRoadHttpClient"/>.</summary>
public sealed record XRoadHttpClientOptions
{
    /// <summary>
    /// Base URL of the X-Road security server proxy. MUST be an absolute <c>https</c> URL with a
    /// non-empty host (the constructor rejects anything else). The injected <see cref="HttpClient"/>
    /// is expected to be configured with the consumer subsystem's mTLS client certificate and to
    /// pin/verify the security server's TLS certificate.
    /// </summary>
    public required string SecurityServerUrl { get; init; }

    /// <summary>Consumer subsystem id sent in <c>X-Road-Client</c> (e.g. <c>"KZ/GOV/1234/tessera"</c>).</summary>
    public required string ClientId { get; init; }

    /// <summary>The registry service id segment used to address the producer service.</summary>
    public required string ServiceId { get; init; }
}
