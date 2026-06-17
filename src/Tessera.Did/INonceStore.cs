namespace Tessera.Did;

using System.Collections.Concurrent;
using Tessera.Core;

/// <summary>
/// Anti-replay guard for challenge nonces. The verifier consumes a (subject, nonce) pair exactly
/// once: the first consumption succeeds, any later attempt with the same pair is a replay and
/// fails. Storage durability is the caller's concern — a production deployment backs this with a
/// shared store (Redis, a database) so replay protection holds across processes and restarts.
/// The bundled <see cref="InMemoryNonceStore"/> is process-local, for tests and single-node use.
/// </summary>
/// <remarks>
/// Mirrors <c>Tessera.Sources.Bitcoin.INonceStore</c>. <see cref="DidService"/> accepts one
/// optionally; when supplied, wallet binding consumes the signed nonce atomically so a captured
/// binding challenge cannot be replayed.
/// </remarks>
public interface INonceStore
{
    /// <summary>
    /// Atomically record a (subject, nonce) pair as used. Returns <c>true</c> when the pair was
    /// newly recorded (fresh); <c>false</c> when it was already present (a replay).
    /// <paramref name="expiresAt"/> lets an implementation evict the entry after the challenge
    /// can no longer be presented.
    /// </summary>
    Task<bool> TryConsumeAsync(DidId subject, byte[] nonce, DateTimeOffset expiresAt, CancellationToken ct = default);
}

/// <summary>
/// Process-local <see cref="INonceStore"/>. Thread-safe; evicts expired entries opportunistically.
/// Not durable across restarts — use a shared store in production.
/// </summary>
public sealed class InMemoryNonceStore : INonceStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);
    private readonly TimeProvider _clock;

    /// <summary>Create the store, optionally with a custom clock for eviction.</summary>
    public InMemoryNonceStore(TimeProvider? clock = null) => _clock = clock ?? TimeProvider.System;

    /// <inheritdoc/>
    public Task<bool> TryConsumeAsync(DidId subject, byte[] nonce, DateTimeOffset expiresAt, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(nonce);
        EvictExpired();
        var key = subject.Value + ":" + Convert.ToHexString(nonce);
        var fresh = _seen.TryAdd(key, expiresAt);
        return Task.FromResult(fresh);
    }

    // Retain entries past their stored expiry so a replay arriving in a post-expiry clock-skew grace
    // window is still caught: eviction must not coincide with the still-presentable boundary.
    private static readonly TimeSpan EvictionMargin = TimeSpan.FromMinutes(5);

    private void EvictExpired()
    {
        var threshold = _clock.GetUtcNow() - EvictionMargin;
        foreach (var kvp in _seen)
        {
            if (kvp.Value <= threshold)
                _seen.TryRemove(kvp.Key, out _);
        }
    }
}
