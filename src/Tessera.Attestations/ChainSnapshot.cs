using System.Text.Json;

namespace Tessera.Attestations;

/// <summary>
/// A point-in-time blockchain reference — the best block at the moment a fact was observed: height,
/// block hash, and time. Generic chain infrastructure (no vendor or use-case semantics): a source
/// writes it into an attestation payload's claims so a verifier can freshness-check <em>when</em> a
/// fact was true. It is public chain data and carries no subject-identifying information, so it does
/// not weaken any privacy invariant.
/// </summary>
/// <remarks>
/// Stored in <see cref="AttestationPayload.Claims"/> under the three <c>snapshot_*</c> keys below.
/// The time is persisted as Unix seconds (a long) rather than a formatted timestamp so the canonical
/// signing bytes are culture-invariant and identical across implementations.
/// </remarks>
public sealed record ChainSnapshot
{
    /// <summary>Height of the snapshot block.</summary>
    public required long BlockHeight { get; init; }

    /// <summary>Hash of the snapshot block (hex).</summary>
    public required string BlockHash { get; init; }

    /// <summary>Time of the snapshot block.</summary>
    public required DateTimeOffset TimeUtc { get; init; }

    /// <summary>Claim key carrying <see cref="BlockHeight"/>.</summary>
    public const string BlockHeightClaim = "snapshot_block_height";

    /// <summary>Claim key carrying <see cref="BlockHash"/>.</summary>
    public const string BlockHashClaim = "snapshot_block_hash";

    /// <summary>Claim key carrying <see cref="TimeUtc"/> as Unix seconds.</summary>
    public const string TimeClaim = "snapshot_time_unix_s";

    /// <summary>Merge this snapshot's three fields into a claims dictionary the caller is building.</summary>
    public void WriteClaims(IDictionary<string, object> claims)
    {
        ArgumentNullException.ThrowIfNull(claims);
        claims[BlockHeightClaim] = BlockHeight;
        claims[BlockHashClaim] = BlockHash;
        claims[TimeClaim] = TimeUtc.ToUnixTimeSeconds();
    }

    /// <summary>
    /// Read the snapshot from an attestation payload, or null when the payload carries no snapshot
    /// (or it is malformed). The public read path for verifiers and downstream callers.
    /// </summary>
    public static ChainSnapshot? TryFrom(AttestationPayload? payload)
        => payload is null ? null : TryFrom(payload.Claims);

    /// <summary>Read the snapshot from a claims dictionary, or null when absent/malformed.</summary>
    public static ChainSnapshot? TryFrom(IReadOnlyDictionary<string, object>? claims)
    {
        if (claims is null) return null;
        if (!claims.TryGetValue(BlockHeightClaim, out var heightObj)
            || !claims.TryGetValue(BlockHashClaim, out var hashObj)
            || !claims.TryGetValue(TimeClaim, out var timeObj))
            return null;

        if (!TryToLong(heightObj, out var height) || !TryToLong(timeObj, out var unixSeconds))
            return null;

        var hash = hashObj as string ?? hashObj?.ToString();
        if (string.IsNullOrEmpty(hash)) return null;

        return new ChainSnapshot
        {
            BlockHeight = height,
            BlockHash = hash,
            TimeUtc = DateTimeOffset.FromUnixTimeSeconds(unixSeconds),
        };
    }

    // Claims survive in memory as the boxed types a source wrote (long), but may arrive as a string
    // or JsonElement after a JSON round-trip — accept all so reads are robust to the transport.
    private static bool TryToLong(object? value, out long result)
    {
        switch (value)
        {
            case long l: result = l; return true;
            case int i: result = i; return true;
            case string s when long.TryParse(s, out var parsed): result = parsed; return true;
            case JsonElement je when je.ValueKind == JsonValueKind.Number && je.TryGetInt64(out var n):
                result = n; return true;
            case JsonElement je when je.ValueKind == JsonValueKind.String && long.TryParse(je.GetString(), out var ns):
                result = ns; return true;
            default: result = 0; return false;
        }
    }
}
