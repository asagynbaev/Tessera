using Microsoft.EntityFrameworkCore;
using Tessera.Attestations;
using Tessera.Core;
using Tessera.EntityFrameworkCore.Internal;

namespace Tessera.EntityFrameworkCore;

/// <summary>
/// EF Core <see cref="IIssuerRegistry"/>. Resolves issuers against the <c>issuers</c> table
/// and offers management methods (<see cref="RegisterAsync"/>, <see cref="DeactivateAsync"/>)
/// beyond the read-only resolver interface — the registry is the authoritative source for
/// issuer onboarding.
/// </summary>
public sealed class EfCoreIssuerRegistry : IIssuerRegistry, IIssuerRegistrar
{
    /// <summary>How many times a write is retried after losing an optimistic-concurrency race.</summary>
    private const int MaxConcurrencyRetries = 3;

    private readonly TesseraDbContext _db;
    private readonly TimeProvider _clock;

    public EfCoreIssuerRegistry(TesseraDbContext db, TimeProvider? clock = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _clock = clock ?? TimeProvider.System;
    }

    /// <summary>Returns the issuer record only if found AND active.</summary>
    public async Task<IssuerRecord?> ResolveAsync(DidId issuer, CancellationToken ct = default)
    {
        var entity = await _db.Issuers
            .AsNoTracking()
            .FirstOrDefaultAsync(i => i.Did == issuer.Value && i.Active, ct)
            .ConfigureAwait(false);

        return entity is null ? null : DomainMappings.ToDomain(entity);
    }

    /// <summary>
    /// Insert a new issuer or update an existing one. Sets <c>Active=true</c> from the record;
    /// to deactivate, prefer <see cref="DeactivateAsync"/> for clarity.
    /// </summary>
    public async Task RegisterAsync(IssuerRecord record, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);

        await WithConcurrencyRetryAsync(async () =>
        {
            var existing = await _db.Issuers
                .FirstOrDefaultAsync(i => i.Did == record.Did.Value, ct)
                .ConfigureAwait(false);

            var now = _clock.GetUtcNow();
            if (existing is null)
            {
                _db.Issuers.Add(DomainMappings.ToEntity(record, now));
            }
            else
            {
                // The issuer registry is the trust root for attestation verification. Refuse to silently
                // overwrite an already-registered issuer's PUBLIC KEY via this upsert — that would
                // substitute the trust anchor and impersonate the issuer. Key rotation must be deliberate.
                if (!existing.PublicKey.AsSpan().SequenceEqual(record.PublicKey))
                    throw new InvalidOperationException(
                        $"Refusing to overwrite the public key of already-registered issuer '{record.Did.Value}' " +
                        "via RegisterAsync. Issuer key rotation must be an explicit, authorized operation.");
                DomainMappings.ToEntity(record, now, existing);
                existing.Version++; // advance the concurrency token so a racing writer is detected
            }

            await _db.SaveChangesAsync(ct).ConfigureAwait(false);
            return true;
        }, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Mark an issuer inactive. Future <see cref="ResolveAsync"/> calls return null;
    /// existing attestations remain in the system but verification fails for inactive issuers.
    /// </summary>
    public Task<bool> DeactivateAsync(DidId issuer, CancellationToken ct = default)
    {
        return WithConcurrencyRetryAsync(async () =>
        {
            var entity = await _db.Issuers
                .FirstOrDefaultAsync(i => i.Did == issuer.Value, ct)
                .ConfigureAwait(false);

            if (entity is null) return false;

            entity.Active = false;
            entity.UpdatedAt = _clock.GetUtcNow();
            entity.Version++; // advance the concurrency token so a racing writer is detected
            await _db.SaveChangesAsync(ct).ConfigureAwait(false);
            return true;
        }, ct);
    }

    /// <summary>
    /// Run a read-modify-save operation, retrying it (up to <see cref="MaxConcurrencyRetries"/> times)
    /// when a concurrent writer wins the optimistic-concurrency race. On conflict the stale tracked
    /// issuer graph is discarded so the retry re-reads the committed row and re-applies on top of it,
    /// turning a silent lost update into a deterministic last-writer-wins outcome. Non-concurrency
    /// failures (e.g. the public-key-overwrite guard) propagate immediately.
    /// </summary>
    private async Task<T> WithConcurrencyRetryAsync<T>(Func<Task<T>> operation, CancellationToken ct)
    {
        var attempt = 0;
        while (true)
        {
            try
            {
                return await operation().ConfigureAwait(false);
            }
            catch (DbUpdateConcurrencyException) when (attempt++ < MaxConcurrencyRetries)
            {
                ct.ThrowIfCancellationRequested();
                // Detach the stale tracked entities so the next attempt re-queries the DB fresh.
                foreach (var entry in _db.ChangeTracker.Entries<Entities.IssuerEntity>().ToList())
                    entry.State = EntityState.Detached;
            }
        }
    }
}
