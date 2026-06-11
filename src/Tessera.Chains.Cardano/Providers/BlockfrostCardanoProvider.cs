using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Tessera.Chains.Cardano.Internal;

namespace Tessera.Chains.Cardano.Providers;

/// <summary>
/// <see cref="ICardanoProvider"/> over the Blockfrost REST API. Thin and dependency-free
/// (HttpClient + System.Text.Json). The project id is sent as the <c>project_id</c> header and
/// never appears in exception messages or logs.
/// </summary>
internal sealed class BlockfrostCardanoProvider : ICardanoProvider, IDisposable
{
    private const string CborMediaType = "application/cbor";
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;

    public BlockfrostCardanoProvider(CardanoNetwork network, string projectId, HttpClient? http = null)
    {
        if (string.IsNullOrWhiteSpace(projectId))
            throw new ArgumentException("BlockfrostProjectId required.", nameof(projectId));

        _ownsHttp = http is null;
        _http = http ?? new HttpClient();
        _http.BaseAddress = new Uri(CardanoNetworkInfo.BlockfrostBaseUrl(network) + "/");
        _http.DefaultRequestHeaders.Remove("project_id");
        _http.DefaultRequestHeaders.Add("project_id", projectId);
    }

    public async Task<ProtocolParameters> GetProtocolParametersAsync(CancellationToken ct)
    {
        using var doc = await GetJsonAsync("epochs/latest/parameters", ct).ConfigureAwait(false);
        var r = doc!.RootElement;
        var v3 = r.GetProperty("cost_models_raw").GetProperty("PlutusV3");
        var costModel = v3.EnumerateArray().Select(e => e.GetInt64()).ToArray();
        return new ProtocolParameters(
            MinFeeA: r.GetProperty("min_fee_a").GetUInt64(),
            MinFeeB: r.GetProperty("min_fee_b").GetUInt64(),
            CoinsPerUtxoByte: ParseULong(r.GetProperty("coins_per_utxo_size")),
            MaxTxSize: r.GetProperty("max_tx_size").GetInt32(),
            PriceMem: r.GetProperty("price_mem").GetDouble(),
            PriceStep: r.GetProperty("price_step").GetDouble(),
            MaxTxExMem: ParseULong(r.GetProperty("max_tx_ex_mem")),
            MaxTxExSteps: ParseULong(r.GetProperty("max_tx_ex_steps")),
            CollateralPercent: r.GetProperty("collateral_percent").GetInt32(),
            MaxCollateralInputs: r.GetProperty("max_collateral_inputs").GetInt32(),
            PlutusV3CostModel: costModel);
    }

    public Task<IReadOnlyList<CardanoUtxo>> GetUtxosAsync(string address, CancellationToken ct)
        => GetUtxoPagesAsync($"addresses/{address}/utxos", ct);

    public Task<IReadOnlyList<CardanoUtxo>> GetAssetUtxosAsync(string address, string unit, CancellationToken ct)
        => GetUtxoPagesAsync($"addresses/{address}/utxos/{unit}", ct);

    private async Task<IReadOnlyList<CardanoUtxo>> GetUtxoPagesAsync(string basePath, CancellationToken ct)
    {
        var result = new List<CardanoUtxo>();
        for (var page = 1; page <= 20; page++)
        {
            using var doc = await GetJsonAsync($"{basePath}?count=100&page={page}&order=asc", ct, allowNotFound: true).ConfigureAwait(false);
            if (doc is null) break; // 404 = address never used
            var arr = doc.RootElement;
            if (arr.GetArrayLength() == 0) break;
            foreach (var u in arr.EnumerateArray())
                result.Add(ParseUtxo(u));
            if (arr.GetArrayLength() < 100) break;
        }
        return result;
    }

    private static CardanoUtxo ParseUtxo(JsonElement u)
    {
        var assets = u.GetProperty("amount").EnumerateArray()
            .Select(a => new CardanoAsset(a.GetProperty("unit").GetString()!, ParseULong(a.GetProperty("quantity"))))
            .ToList();
        byte[]? inlineDatum = null;
        if (u.TryGetProperty("inline_datum", out var d) && d.ValueKind == JsonValueKind.String)
            inlineDatum = Convert.FromHexString(d.GetString()!);
        var hasRefScript = u.TryGetProperty("reference_script_hash", out var rs) && rs.ValueKind == JsonValueKind.String;
        return new CardanoUtxo(
            TxHash: u.GetProperty("tx_hash").GetString()!,
            OutputIndex: u.GetProperty("output_index").GetInt32(),
            Address: u.TryGetProperty("address", out var ad) && ad.ValueKind == JsonValueKind.String ? ad.GetString()! : string.Empty,
            Amount: assets,
            InlineDatumCbor: inlineDatum,
            HasReferenceScript: hasRefScript);
    }

    public async Task<ChainTip> GetTipAsync(CancellationToken ct)
    {
        using var doc = await GetJsonAsync("blocks/latest", ct).ConfigureAwait(false);
        var r = doc!.RootElement;
        return new ChainTip(r.GetProperty("slot").GetUInt64(), r.GetProperty("height").GetUInt64());
    }

    public async Task<IReadOnlyList<RedeemerEvaluation>> EvaluateAsync(byte[] txCbor, CancellationToken ct)
    {
        using var doc = await PostCborAsync("utils/txs/evaluate", txCbor, ct).ConfigureAwait(false);
        return EvaluationParser.Parse(doc!.RootElement);
    }

    public async Task<string> SubmitAsync(byte[] txCbor, CancellationToken ct)
    {
        // Single-shot: never wrapped in CardanoRetry.
        using var content = new ByteArrayContent(txCbor);
        content.Headers.ContentType = new MediaTypeHeaderValue(CborMediaType);
        using var resp = await _http.PostAsync("tx/submit", content, ct).ConfigureAwait(false);
        var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            throw ToException(resp.StatusCode, "tx/submit", body);
        return body.Trim().Trim('"');
    }

    public async Task<TxConfirmation?> GetTxAsync(string txHash, CancellationToken ct)
    {
        using var doc = await GetJsonAsync($"txs/{txHash}", ct, allowNotFound: true).ConfigureAwait(false);
        if (doc is null) return null;
        var r = doc.RootElement;
        return new TxConfirmation(r.GetProperty("block_height").GetUInt64(), r.GetProperty("block_time").GetInt64());
    }

    public async Task<IReadOnlyList<MetadataTx>> GetMetadataTxsAsync(ulong label, CancellationToken ct)
    {
        var result = new List<MetadataTx>();
        for (var page = 1; page <= 20; page++)
        {
            using var doc = await GetJsonAsync($"metadata/txs/labels/{label}?count=100&page={page}&order=desc", ct, allowNotFound: true).ConfigureAwait(false);
            if (doc is null) break;
            var arr = doc.RootElement;
            if (arr.GetArrayLength() == 0) break;
            foreach (var e in arr.EnumerateArray())
                result.Add(new MetadataTx(e.GetProperty("tx_hash").GetString()!, e.GetProperty("json_metadata").Clone()));
            if (arr.GetArrayLength() < 100) break;
        }
        return result;
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    private async Task<JsonDocument?> GetJsonAsync(string path, CancellationToken ct, bool allowNotFound = false)
    {
        using var resp = await _http.GetAsync(path, ct).ConfigureAwait(false);
        if (allowNotFound && resp.StatusCode == HttpStatusCode.NotFound) return null;
        var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode) throw ToException(resp.StatusCode, path, body);
        return JsonDocument.Parse(body);
    }

    private async Task<JsonDocument?> PostCborAsync(string path, byte[] cbor, CancellationToken ct)
    {
        using var content = new ByteArrayContent(cbor);
        content.Headers.ContentType = new MediaTypeHeaderValue(CborMediaType);
        using var resp = await _http.PostAsync(path, content, ct).ConfigureAwait(false);
        var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode) throw ToException(resp.StatusCode, path, body);
        return JsonDocument.Parse(body);
    }

    /// <summary>Maps a Blockfrost error to the adapter taxonomy. 5xx/429 are transient (retryable).</summary>
    private static Exception ToException(HttpStatusCode status, string path, string body)
    {
        var snippet = body.Length > 300 ? body[..300] : body;
        var message = $"Blockfrost {(int)status} on '{path}': {snippet}";
        return status == HttpStatusCode.TooManyRequests || (int)status >= 500
            ? new TransientProviderException(message)
            : new InvalidOperationException(message);
    }

    private static ulong ParseULong(JsonElement e) => e.ValueKind == JsonValueKind.String
        ? ulong.Parse(e.GetString()!, CultureInfo.InvariantCulture)
        : e.GetUInt64();

    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }
}

/// <summary>Tolerant parser for the Blockfrost/Ogmios tx-evaluation response (v5 and v6 shapes).</summary>
internal static class EvaluationParser
{
    public static IReadOnlyList<RedeemerEvaluation> Parse(JsonElement root)
    {
        if (!root.TryGetProperty("result", out var result))
            return Array.Empty<RedeemerEvaluation>();

        var list = new List<RedeemerEvaluation>();

        // v6: result is an array of { validator: {index, purpose} | "spend:0", budget: {memory, cpu} }.
        if (result.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in result.EnumerateArray())
            {
                var (purpose, index) = ReadValidator(item.GetProperty("validator"));
                var budget = item.GetProperty("budget");
                list.Add(new RedeemerEvaluation(purpose, index,
                    ReadUnit(budget, "memory"), ReadUnit(budget, "cpu", "steps")));
            }
            return list;
        }

        // v5: result.EvaluationResult is a map of "purpose:index" -> {memory, steps}.
        if (result.ValueKind == JsonValueKind.Object && result.TryGetProperty("EvaluationResult", out var evalMap))
        {
            foreach (var entry in evalMap.EnumerateObject())
            {
                var (purpose, index) = SplitKey(entry.Name);
                list.Add(new RedeemerEvaluation(purpose, index,
                    ReadUnit(entry.Value, "memory"), ReadUnit(entry.Value, "steps", "cpu")));
            }
        }
        return list;
    }

    private static (string Purpose, uint Index) ReadValidator(JsonElement v) => v.ValueKind == JsonValueKind.String
        ? SplitKey(v.GetString()!)
        : (v.GetProperty("purpose").GetString() ?? "spend", v.GetProperty("index").GetUInt32());

    private static (string Purpose, uint Index) SplitKey(string key)
    {
        var parts = key.Split(':');
        return (parts[0], parts.Length > 1 ? uint.Parse(parts[1], CultureInfo.InvariantCulture) : 0u);
    }

    private static ulong ReadUnit(JsonElement budget, string name, string? alt = null)
    {
        if (budget.TryGetProperty(name, out var v)) return v.GetUInt64();
        if (alt is not null && budget.TryGetProperty(alt, out var w)) return w.GetUInt64();
        return 0;
    }
}
