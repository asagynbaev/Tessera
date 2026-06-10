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
            DomainMappings.ToEntity(record, now, existing);
        }

        await _db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Mark an issuer inactive. Future <see cref="ResolveAsync"/> calls return null;
    /// existing attestations remain in the system but verification fails for inactive issuers.
    /// </summary>
    public async Task<bool> DeactivateAsync(DidId issuer, CancellationToken ct = default)
    {
        var entity = await _db.Issuers
            .FirstOrDefaultAsync(i => i.Did == issuer.Value, ct)
            .ConfigureAwait(false);

        if (entity is null) return false;

        entity.Active = false;
        entity.UpdatedAt = _clock.GetUtcNow();
        await _db.SaveChangesAsync(ct).ConfigureAwait(false);
        return true;
    }
}
