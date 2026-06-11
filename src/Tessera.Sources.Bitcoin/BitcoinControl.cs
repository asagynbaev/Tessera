using System.Collections.Concurrent;
using Tessera.Core;

namespace Tessera.Sources.Bitcoin;

/// <summary>
/// A Bitcoin address whose control has been proven for a subject via a signed challenge. Carries
/// only what the source needs downstream — the address (to query balances) and its type/network.
/// It is never written into an attestation payload (see the privacy invariant in the README).
/// </summary>
public sealed record VerifiedBitcoinAddress
{
    /// <summary>The proven address.</summary>
    public required string Address { get; init; }

    /// <summary>The address type the signature recovered to.</summary>
    public required BitcoinAddressType Type { get; init; }

    /// <summary>The network the address belongs to.</summary>
    public required BitcoinNetwork Network { get; init; }
}

/// <summary>
/// The set of control-verified addresses per subject — the "holder session" the attestation
/// source computes facts over. Populated by <see cref="BitcoinControlVerifier"/> as each address's
/// signature checks out, and read by <see cref="BitcoinAttestationSource"/> on the issuance-pipeline
/// path. The bundled <see cref="InMemoryBitcoinControlStore"/> is process-local; a hosted issuer
/// supplies a shared implementation.
/// </summary>
public interface IBitcoinControlStore
{
    /// <summary>Record an address as control-verified for the subject. Idempotent per address.</summary>
    Task RecordVerifiedAsync(DidId subject, VerifiedBitcoinAddress address, CancellationToken ct = default);

    /// <summary>The addresses verified for the subject so far (empty if none).</summary>
    Task<IReadOnlyList<VerifiedBitcoinAddress>> GetVerifiedAsync(DidId subject, CancellationToken ct = default);
}

/// <summary>Process-local <see cref="IBitcoinControlStore"/>; thread-safe, deduplicated by address.</summary>
public sealed class InMemoryBitcoinControlStore : IBitcoinControlStore
{
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, VerifiedBitcoinAddress>> _bySubject =
        new(StringComparer.Ordinal);

    /// <inheritdoc/>
    public Task RecordVerifiedAsync(DidId subject, VerifiedBitcoinAddress address, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(address);
        var set = _bySubject.GetOrAdd(subject.Value, _ => new ConcurrentDictionary<string, VerifiedBitcoinAddress>(StringComparer.Ordinal));
        set[address.Address] = address;
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<IReadOnlyList<VerifiedBitcoinAddress>> GetVerifiedAsync(DidId subject, CancellationToken ct = default)
    {
        IReadOnlyList<VerifiedBitcoinAddress> result = _bySubject.TryGetValue(subject.Value, out var set)
            ? set.Values.ToList()
            : Array.Empty<VerifiedBitcoinAddress>();
        return Task.FromResult(result);
    }
}
