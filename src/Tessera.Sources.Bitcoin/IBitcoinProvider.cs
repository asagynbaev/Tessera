namespace Tessera.Sources.Bitcoin;

/// <summary>
/// Abstraction over a Bitcoin chain-data provider. The source depends on this, not on a concrete
/// HTTP client, so the backend is swappable and unit tests inject a fake. The production
/// implementation is <see cref="EsploraBitcoinProvider"/> (mempool.space / blockstream.info).
/// </summary>
public interface IBitcoinProvider
{
    /// <summary>
    /// Confirmed on-chain summary for an address: the confirmed balance in satoshis (funded − spent
    /// over confirmed transactions). Returns a zeroed summary for an address that has never been used.
    /// </summary>
    Task<BitcoinAddressSummary> GetAddressSummaryAsync(string address, CancellationToken ct = default);

    /// <summary>
    /// The confirmed unspent outputs for an address, each carrying its value and the block it
    /// confirmed in (height + time). Unconfirmed UTXOs are excluded. Empty for an unused address.
    /// </summary>
    Task<IReadOnlyList<BitcoinUtxo>> GetUtxosAsync(string address, CancellationToken ct = default);
}

/// <summary>Confirmed balance summary for a single address, in satoshis.</summary>
public sealed record BitcoinAddressSummary
{
    /// <summary>The address this summary is for.</summary>
    public required string Address { get; init; }

    /// <summary>Confirmed balance in satoshis (<c>funded_txo_sum − spent_txo_sum</c> over confirmed txs).</summary>
    public required long ConfirmedSats { get; init; }
}

/// <summary>A confirmed unspent transaction output.</summary>
public sealed record BitcoinUtxo
{
    /// <summary>Funding transaction id (hex).</summary>
    public required string TxId { get; init; }

    /// <summary>Output index within the funding transaction.</summary>
    public required int Vout { get; init; }

    /// <summary>Output value in satoshis.</summary>
    public required long ValueSats { get; init; }

    /// <summary>Height of the block that confirmed the funding transaction.</summary>
    public required long BlockHeight { get; init; }

    /// <summary>Unix time (seconds) of the block that confirmed the funding transaction.</summary>
    public required long BlockTime { get; init; }
}
