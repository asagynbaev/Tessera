using System.Net;
using System.Text.Json;

namespace Tessera.Sources.Bitcoin;

/// <summary>
/// <see cref="IBitcoinProvider"/> over the Esplora REST API as exposed by mempool.space and
/// blockstream.info (and any self-hosted Esplora). Thin and dependency-free beyond NBitcoin
/// (HttpClient + System.Text.Json). Reads retry on transient faults (HTTP 5xx / 429 / network);
/// this provider never writes.
/// </summary>
/// <remarks>
/// Endpoints used:
/// <list type="bullet">
///   <item><c>GET {base}/address/:addr</c> → <c>chain_stats.funded_txo_sum − chain_stats.spent_txo_sum</c> = confirmed sats.</item>
///   <item><c>GET {base}/address/:addr/utxo</c> → confirmed UTXOs (value + funding-block height/time).</item>
/// </list>
/// </remarks>
public sealed class EsploraBitcoinProvider : IBitcoinProvider, IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly BitcoinRetryPolicy _retry;

    /// <summary>
    /// Create the provider. Pass an <see cref="HttpClient"/> to reuse one (e.g. from
    /// <c>IHttpClientFactory</c>); when null, the provider owns and disposes its own.
    /// </summary>
    public EsploraBitcoinProvider(EsploraBitcoinProviderOptions options, HttpClient? http = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var baseUrl = string.IsNullOrWhiteSpace(options.BaseUrl)
            ? BitcoinNetworkInfo.DefaultEsploraBaseUrl(options.Network)
            : options.BaseUrl!.TrimEnd('/');

        _ownsHttp = http is null;
        _http = http ?? new HttpClient();
        _http.BaseAddress = new Uri(baseUrl + "/");
        _retry = options.Retry ?? BitcoinRetryPolicy.Default;
    }

    /// <inheritdoc/>
    public Task<BitcoinAddressSummary> GetAddressSummaryAsync(string address, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        return BitcoinRetry.RunAsync(_retry, async () =>
        {
            using var doc = await GetJsonAsync($"address/{Uri.EscapeDataString(address)}", ct, allowNotFound: true).ConfigureAwait(false);
            if (doc is null)
                return new BitcoinAddressSummary { Address = address, ConfirmedSats = 0 };

            var stats = doc.RootElement.GetProperty("chain_stats");
            var funded = stats.GetProperty("funded_txo_sum").GetInt64();
            var spent = stats.GetProperty("spent_txo_sum").GetInt64();
            return new BitcoinAddressSummary { Address = address, ConfirmedSats = funded - spent };
        }, ct);
    }

    /// <inheritdoc/>
    public Task<IReadOnlyList<BitcoinUtxo>> GetUtxosAsync(string address, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        return BitcoinRetry.RunAsync(_retry, async () =>
        {
            using var doc = await GetJsonAsync($"address/{Uri.EscapeDataString(address)}/utxo", ct, allowNotFound: true).ConfigureAwait(false);
            if (doc is null) return (IReadOnlyList<BitcoinUtxo>)Array.Empty<BitcoinUtxo>();

            var result = new List<BitcoinUtxo>();
            foreach (var u in doc.RootElement.EnumerateArray())
            {
                var status = u.GetProperty("status");
                // Only confirmed UTXOs carry a block height/time; unconfirmed ones are excluded.
                if (!status.TryGetProperty("confirmed", out var c) || !c.GetBoolean())
                    continue;
                result.Add(new BitcoinUtxo
                {
                    TxId = u.GetProperty("txid").GetString()!,
                    Vout = u.GetProperty("vout").GetInt32(),
                    ValueSats = u.GetProperty("value").GetInt64(),
                    BlockHeight = status.GetProperty("block_height").GetInt64(),
                    BlockTime = status.GetProperty("block_time").GetInt64(),
                });
            }
            return result;
        }, ct);
    }

    // ── HTTP helpers (mirror BlockfrostCardanoProvider) ──────────────────────────

    private async Task<JsonDocument?> GetJsonAsync(string path, CancellationToken ct, bool allowNotFound = false)
    {
        using var resp = await _http.GetAsync(path, ct).ConfigureAwait(false);
        if (allowNotFound && resp.StatusCode == HttpStatusCode.NotFound) return null;
        var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode) throw ToException(resp.StatusCode, path, body);
        return JsonDocument.Parse(body);
    }

    /// <summary>Maps an Esplora error to the source taxonomy. 5xx/429 are transient (retryable).</summary>
    private static Exception ToException(HttpStatusCode status, string path, string body)
    {
        var snippet = body.Length > 300 ? body[..300] : body;
        var message = $"Esplora {(int)status} on '{path}': {snippet}";
        return status == HttpStatusCode.TooManyRequests || (int)status >= 500
            ? new TransientBitcoinProviderException(message)
            : new InvalidOperationException(message);
    }

    /// <summary>Disposes the owned <see cref="HttpClient"/> (no-op when one was supplied).</summary>
    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }
}

/// <summary>Options for <see cref="EsploraBitcoinProvider"/>.</summary>
public sealed record EsploraBitcoinProviderOptions
{
    /// <summary>Network the provider reads from. Selects the default base URL.</summary>
    public BitcoinNetwork Network { get; init; } = BitcoinNetwork.Mainnet;

    /// <summary>
    /// Esplora API base URL, no trailing <c>/</c> (e.g. <c>https://blockstream.info/testnet/api</c>).
    /// When null/empty, derived from <see cref="Network"/> (mempool.space).
    /// </summary>
    public string? BaseUrl { get; init; }

    /// <summary>Retry policy for transient read failures.</summary>
    public BitcoinRetryPolicy Retry { get; init; } = BitcoinRetryPolicy.Default;
}
