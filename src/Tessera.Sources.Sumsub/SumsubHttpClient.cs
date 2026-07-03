using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Tessera.Sources.Sumsub;

/// <summary>
/// Production <see cref="ISumsubClient"/> over the Sumsub REST API using an injected
/// <see cref="HttpClient"/>. Requests are signed per Sumsub's app-token scheme
/// (X-App-Token + HMAC-SHA256 over <c>ts + METHOD + path + body</c>).
/// </summary>
/// <remarks>
/// Credentials are configuration, never hardcoded. The JSON mapping targets the documented
/// <c>/resources/applicants/{id}/one</c> shape; validate field paths against your Sumsub level
/// before production use. Unit tests cover the deterministic request signer; the source mapping
/// is tested via a fake <see cref="ISumsubClient"/>.
/// </remarks>
public sealed class SumsubHttpClient : ISumsubClient
{
    private readonly HttpClient _http;
    private readonly SumsubHttpClientOptions _options;
    private readonly TimeProvider _clock;

    public SumsubHttpClient(HttpClient http, SumsubHttpClientOptions options, TimeProvider? clock = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        ArgumentException.ThrowIfNullOrEmpty(options.AppToken);
        ArgumentException.ThrowIfNullOrEmpty(options.SecretKey);
        ArgumentException.ThrowIfNullOrEmpty(options.BaseUrl);

        // The X-App-Token is a long-lived credential carried on every request; refuse to ever send
        // it over a cleartext channel. Require an absolute https URL with a real host.
        if (!Uri.TryCreate(options.BaseUrl, UriKind.Absolute, out var baseUri))
            throw new ArgumentException($"BaseUrl must be an absolute URL: '{options.BaseUrl}'.", nameof(options));
        if (!string.Equals(baseUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException(
                $"BaseUrl must use https so the X-App-Token is never sent in cleartext: '{options.BaseUrl}'.", nameof(options));
        if (string.IsNullOrWhiteSpace(baseUri.Host))
            throw new ArgumentException($"BaseUrl must have a non-empty host: '{options.BaseUrl}'.", nameof(options));

        _clock = clock ?? TimeProvider.System;
    }

    /// <summary>
    /// An <see cref="HttpClientHandler"/> hardened for this client: <see cref="HttpClientHandler.AllowAutoRedirect"/>
    /// is <c>false</c>. Sumsub is a single-hop REST API and never legitimately returns a redirect, so
    /// following one would only replay the long-lived <c>X-App-Token</c> (and the request signature)
    /// to an attacker-chosen target. The injected <see cref="HttpClient"/> MUST be built on a handler
    /// configured this way — use <see cref="CreateHardenedHttpClient"/>, or apply the same setting to
    /// your own handler / <c>IHttpClientFactory</c> registration.
    /// </summary>
    public static HttpClientHandler CreateHardenedHandler() => new() { AllowAutoRedirect = false };

    /// <summary>
    /// Convenience: a new <see cref="HttpClient"/> built on <see cref="CreateHardenedHandler"/> (auto-redirect
    /// disabled). Pass it to the constructor. The caller owns the returned client's lifetime.
    /// </summary>
    public static HttpClient CreateHardenedHttpClient() => new(CreateHardenedHandler());

    public async Task<SumsubApplicantReview?> GetApplicantReviewAsync(string applicantId, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(applicantId);

        var path = $"/resources/applicants/{Uri.EscapeDataString(applicantId)}/one";
        using var request = BuildSignedRequest(HttpMethod.Get, path, body: "");

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            return null;
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
        return MapApplicant(applicantId, doc.RootElement);
    }

    internal HttpRequestMessage BuildSignedRequest(HttpMethod method, string pathAndQuery, string body)
    {
        var ts = _clock.GetUtcNow().ToUnixTimeSeconds();
        var sig = SumsubRequestSigner.Sign(_options.SecretKey, ts, method.Method, pathAndQuery, body);

        var request = new HttpRequestMessage(method, new Uri(new Uri(_options.BaseUrl), pathAndQuery));
        if (!string.IsNullOrEmpty(body))
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        request.Headers.Add("X-App-Token", _options.AppToken);
        request.Headers.Add("X-App-Access-Ts", ts.ToString());
        request.Headers.Add("X-App-Access-Sig", sig);
        return request;
    }

    /// <summary>Best-effort mapping of Sumsub's applicant JSON to the distilled review.</summary>
    internal static SumsubApplicantReview MapApplicant(string applicantId, JsonElement root)
    {
        string? reviewAnswer = null;
        var completed = false;
        if (root.TryGetProperty("review", out var review))
        {
            if (review.TryGetProperty("reviewStatus", out var status))
                completed = string.Equals(status.GetString(), "completed", StringComparison.OrdinalIgnoreCase);
            if (review.TryGetProperty("reviewResult", out var result) &&
                result.TryGetProperty("reviewAnswer", out var answer))
                reviewAnswer = answer.GetString();
        }

        string? level = root.TryGetProperty("levelName", out var lvl) ? lvl.GetString() : null;

        string? country = null;
        if (root.TryGetProperty("info", out var info) && info.TryGetProperty("country", out var c))
            country = c.GetString();
        else if (root.TryGetProperty("fixedInfo", out var fixedInfo) && fixedInfo.TryGetProperty("country", out var fc))
            country = fc.GetString();

        // externalUserId is the integrator-supplied binding between the Sumsub applicant and the
        // subject (the DID). The attestation source uses it to reject "identity transplants".
        string? externalUserId =
            root.TryGetProperty("externalUserId", out var ext) ? ext.GetString() : null;

        return new SumsubApplicantReview
        {
            ApplicantId = applicantId,
            Approved = completed && string.Equals(reviewAnswer, "GREEN", StringComparison.OrdinalIgnoreCase),
            ReviewAnswer = reviewAnswer,
            ExternalUserId = externalUserId,
            LevelName = level,
            Country = country,
        };
    }
}

/// <summary>Configuration for <see cref="SumsubHttpClient"/>.</summary>
public sealed record SumsubHttpClientOptions
{
    /// <summary>
    /// Sumsub API base URL. MUST be an absolute <c>https</c> URL with a non-empty host: the
    /// constructor rejects anything else so the long-lived <c>X-App-Token</c> is never transmitted
    /// in cleartext. Defaults to the public Sumsub endpoint.
    /// </summary>
    public string BaseUrl { get; init; } = "https://api.sumsub.com";
    public required string AppToken { get; init; }
    public required string SecretKey { get; init; }
}

/// <summary>Deterministic Sumsub request signer (HMAC-SHA256 over ts + METHOD + path + body).</summary>
internal static class SumsubRequestSigner
{
    public static string Sign(string secretKey, long ts, string method, string pathAndQuery, string body)
    {
        var payload = ts.ToString() + method.ToUpperInvariant() + pathAndQuery + (body ?? string.Empty);
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
