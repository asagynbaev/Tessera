using System.Numerics;

namespace Tessera.Sources.Bitcoin;

/// <summary>
/// The numeric facts computed over a holder's control-verified addresses. These are the issuer's
/// internal inputs to the commitments — they are delivered to the holder, never written into an
/// attestation payload (only commitments and the address count are).
/// </summary>
public sealed record BitcoinFacts
{
    /// <summary>Total confirmed balance across all verified addresses, in satoshis.</summary>
    public required long TotalSats { get; init; }

    /// <summary>
    /// Value-weighted holding age in whole days: <c>Σ(utxo.value × utxo.age_days) / total_sats</c>,
    /// over confirmed UTXOs (age from the UTXO's confirming block time to now). 0 when there is no
    /// confirmed balance. A heuristic, not a guarantee — see the README on gameability.
    /// </summary>
    public required long HodlAgeDays { get; init; }

    /// <summary>Age in whole days of the oldest confirmed UTXO across all verified addresses.</summary>
    public required long OldestUtxoAgeDays { get; init; }

    /// <summary>Number of addresses whose control was proven (the boolean <c>btc_control</c> fact).</summary>
    public required int AddressCount { get; init; }

    /// <summary>Chain-tip block height at the moment these facts were observed (point-in-time binding).</summary>
    public required long SnapshotBlockHeight { get; init; }

    /// <summary>Chain-tip block hash (hex) at the moment these facts were observed.</summary>
    public required string SnapshotBlockHash { get; init; }

    /// <summary>Chain-tip block time at the moment these facts were observed.</summary>
    public required DateTimeOffset SnapshotTimeUtc { get; init; }
}

/// <summary>
/// Computes <see cref="BitcoinFacts"/> from a provider over a set of verified addresses. Confirmed
/// balance comes from the address summary; the value-weighted age uses confirmed UTXOs.
/// </summary>
internal static class BitcoinFactCalculator
{
    private const long SecondsPerDay = 86_400;

    public static async Task<BitcoinFacts> ComputeAsync(
        IBitcoinProvider provider,
        IReadOnlyList<VerifiedBitcoinAddress> verified,
        TimeProvider clock,
        CancellationToken ct)
    {
        var now = clock.GetUtcNow();

        // Capture the chain tip ONCE up front: every fact below is observed "as of" this snapshot,
        // so the emitted attestations bind to a single point in time rather than no moment at all.
        var tip = await provider.GetChainTipAsync(ct).ConfigureAwait(false);

        long totalSats = 0;
        long oldestAgeDays = 0;
        long weightedAgeDenominator = 0;                   // Σ confirmed UTXO value (same set as the numerator)
        BigInteger weightedAgeNumerator = BigInteger.Zero; // Σ value·ageDays (exact)

        foreach (var addr in verified)
        {
            ct.ThrowIfCancellationRequested();

            var summary = await provider.GetAddressSummaryAsync(addr.Address, ct).ConfigureAwait(false);
            totalSats = checked(totalSats + summary.ConfirmedSats);

            var utxos = await provider.GetUtxosAsync(addr.Address, ct).ConfigureAwait(false);
            foreach (var u in utxos)
            {
                var ageDays = AgeDays(u.BlockTime, now);
                weightedAgeNumerator += (BigInteger)u.ValueSats * ageDays;
                weightedAgeDenominator = checked(weightedAgeDenominator + u.ValueSats);
                if (ageDays > oldestAgeDays) oldestAgeDays = ageDays;
            }
        }

        // Value-weighted age = Σ(value·age) / Σ(value) over the SAME confirmed-UTXO set, so the
        // numerator and denominator are always one consistent snapshot (the UTXO sum equals the
        // summary's confirmed balance on a consistent read). 0 when there are no confirmed UTXOs.
        long hodlAgeDays = weightedAgeDenominator > 0
            ? (long)(weightedAgeNumerator / weightedAgeDenominator)
            : 0;

        return new BitcoinFacts
        {
            TotalSats = totalSats,
            HodlAgeDays = hodlAgeDays,
            OldestUtxoAgeDays = oldestAgeDays,
            AddressCount = verified.Count,
            SnapshotBlockHeight = tip.BlockHeight,
            SnapshotBlockHash = tip.BlockHash,
            SnapshotTimeUtc = tip.BlockTimeUtc,
        };
    }

    private static long AgeDays(long blockTimeUnixSeconds, DateTimeOffset now)
    {
        var ageSeconds = now.ToUnixTimeSeconds() - blockTimeUnixSeconds;
        if (ageSeconds <= 0) return 0; // guard clock skew / future-dated block times
        return ageSeconds / SecondsPerDay;
    }
}
