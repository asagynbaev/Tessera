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
/// Computes <see cref="BitcoinFacts"/> from a provider over a set of verified addresses. Both the
/// confirmed balance and the value-weighted age are computed over the SAME set of confirmed UTXOs
/// that are buried at least <c>minConfirmations</c> blocks deep relative to the pinned snapshot.
/// </summary>
internal static class BitcoinFactCalculator
{
    private const long SecondsPerDay = 86_400;

    /// <param name="minConfirmations">
    /// Minimum confirmation depth a UTXO must have (relative to the pinned snapshot height) to be
    /// counted. Values below 1 are treated as 1. Defends against flash-funding: an attacker who
    /// funds an address, takes a single confirmation, mints a <c>btc_balance</c> attestation and
    /// then moves the coins is defeated because the shallow, not-yet-final output is not counted.
    /// </param>
    public static async Task<BitcoinFacts> ComputeAsync(
        IBitcoinProvider provider,
        IReadOnlyList<VerifiedBitcoinAddress> verified,
        TimeProvider clock,
        int minConfirmations,
        CancellationToken ct)
    {
        var now = clock.GetUtcNow();

        // Capture the chain tip ONCE up front: every fact below is observed "as of" this snapshot,
        // so the emitted attestations bind to a single point in time rather than no moment at all.
        var tip = await provider.GetChainTipAsync(ct).ConfigureAwait(false);

        // A confirmed UTXO in the tip block has depth 1; require at least minConfirmations. Balance is
        // derived from this SAME depth-filtered UTXO set (NOT the address summary, which reports every
        // confirmed output including 1-conf ones and so cannot be depth-filtered), keeping balance and
        // age one consistent, flash-fund-resistant snapshot.
        //
        // NOTE (out of scope here): this trusts a single provider. A hostile or buggy provider can
        // still misreport heights/values and thus fabricate these facts; defending that needs
        // multi-provider quorum, which is not addressed by this filter.
        var minDepth = minConfirmations < 1 ? 1 : minConfirmations;

        long totalSats = 0;
        long oldestAgeDays = 0;
        BigInteger weightedAgeNumerator = BigInteger.Zero; // Σ value·ageDays (exact)

        foreach (var addr in verified)
        {
            ct.ThrowIfCancellationRequested();

            var utxos = await provider.GetUtxosAsync(addr.Address, ct).ConfigureAwait(false);
            foreach (var u in utxos)
            {
                // depth = snapshotHeight − fundingHeight + 1. A UTXO funded in a block newer than the
                // pinned tip (provider inconsistency) yields depth ≤ 0 and is excluded — the safe side.
                var depth = tip.BlockHeight - u.BlockHeight + 1;
                if (depth < minDepth) continue;

                totalSats = checked(totalSats + u.ValueSats);
                var ageDays = AgeDays(u.BlockTime, now);
                weightedAgeNumerator += (BigInteger)u.ValueSats * ageDays;
                if (ageDays > oldestAgeDays) oldestAgeDays = ageDays;
            }
        }

        // Value-weighted age = Σ(value·age) / Σ(value) over the SAME deep-confirmed-UTXO set (its value
        // sum IS totalSats), so numerator and denominator are always one consistent snapshot. 0 when
        // there is no deep-confirmed balance.
        long hodlAgeDays = totalSats > 0
            ? (long)(weightedAgeNumerator / totalSats)
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
