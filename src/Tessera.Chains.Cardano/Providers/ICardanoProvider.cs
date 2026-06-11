using System.Text.Json;

namespace Tessera.Chains.Cardano.Providers;

/// <summary>
/// Chain-data + submission surface the adapter needs, abstracted so the Blockfrost provider
/// can be swapped (e.g. for a self-hosted node) and mocked in tests. All reads are retried by
/// the adapter; submission is single-shot.
/// </summary>
internal interface ICardanoProvider
{
    /// <summary>Current protocol parameters (fees, ex-unit prices/limits, PlutusV3 cost model).</summary>
    Task<ProtocolParameters> GetProtocolParametersAsync(CancellationToken ct);

    /// <summary>All UTxOs at an address (paged internally). Used for coin/collateral selection.</summary>
    Task<IReadOnlyList<CardanoUtxo>> GetUtxosAsync(string address, CancellationToken ct);

    /// <summary>UTxOs at an address holding a specific asset (<paramref name="unit"/> = policyId ‖ assetNameHex).</summary>
    Task<IReadOnlyList<CardanoUtxo>> GetAssetUtxosAsync(string address, string unit, CancellationToken ct);

    /// <summary>Current chain tip (slot for TTL, height).</summary>
    Task<ChainTip> GetTipAsync(CancellationToken ct);

    /// <summary>Evaluate a transaction's Plutus scripts, returning the execution units per redeemer.</summary>
    Task<IReadOnlyList<RedeemerEvaluation>> EvaluateAsync(byte[] txCbor, CancellationToken ct);

    /// <summary>Submit a signed transaction; returns its hash. Single-shot — never auto-retried.</summary>
    Task<string> SubmitAsync(byte[] txCbor, CancellationToken ct);

    /// <summary>Transaction details once on-chain (block height + time), or null if not yet confirmed.</summary>
    Task<TxConfirmation?> GetTxAsync(string txHash, CancellationToken ct);

    /// <summary>Transactions carrying metadata under a label (for <see cref="AnchorMode.Metadata"/> reads).</summary>
    Task<IReadOnlyList<MetadataTx>> GetMetadataTxsAsync(ulong label, CancellationToken ct);
}

/// <summary>Protocol parameters relevant to fee + script-data-hash computation.</summary>
internal sealed record ProtocolParameters(
    ulong MinFeeA,
    ulong MinFeeB,
    ulong CoinsPerUtxoByte,
    int MaxTxSize,
    double PriceMem,
    double PriceStep,
    ulong MaxTxExMem,
    ulong MaxTxExSteps,
    int CollateralPercent,
    int MaxCollateralInputs,
    long[] PlutusV3CostModel);

/// <summary>A single native asset in a UTxO value.</summary>
internal sealed record CardanoAsset(string Unit, ulong Quantity);

/// <summary>An unspent transaction output.</summary>
internal sealed record CardanoUtxo(
    string TxHash,
    int OutputIndex,
    string Address,
    IReadOnlyList<CardanoAsset> Amount,
    byte[]? InlineDatumCbor,
    bool HasReferenceScript)
{
    public ulong Lovelace => Amount.FirstOrDefault(a => a.Unit == "lovelace")?.Quantity ?? 0;

    /// <summary>True if the UTxO holds only ADA (eligible as Plutus collateral).</summary>
    public bool IsPureAda => Amount.Count == 1 && Amount[0].Unit == "lovelace";
}

internal sealed record ChainTip(ulong Slot, ulong Height);

internal sealed record TxConfirmation(ulong BlockHeight, long BlockTimeUnix);

internal sealed record RedeemerEvaluation(string Purpose, uint Index, ulong Mem, ulong Steps);

internal sealed record MetadataTx(string TxHash, JsonElement Json);
