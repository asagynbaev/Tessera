using Microsoft.EntityFrameworkCore;
using Tessera.Core;
using Tessera.Did;
using Tessera.EntityFrameworkCore.Entities;
using Tessera.EntityFrameworkCore.Internal;

namespace Tessera.EntityFrameworkCore;

/// <summary>
/// EF Core <see cref="IDidStore"/>. Persists <see cref="DidDocument"/> aggregates
/// into the normalized schema defined by <see cref="TesseraDbContext"/>.
/// </summary>
/// <remarks>
/// One <see cref="DbContext"/> per request — register both the <c>DbContext</c> and
/// this store as scoped services. The store does not call <c>SaveChangesAsync</c>
/// inside read paths; only <see cref="SaveAsync"/> persists.
/// </remarks>
public sealed class EfCoreDidStore : IDidStore
{
    private readonly TesseraDbContext _db;

    public EfCoreDidStore(TesseraDbContext db)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
    }

    public async Task<DidDocument?> GetAsync(DidId did, CancellationToken ct = default)
    {
        var entity = await LoadGraphAsync(did, ct).ConfigureAwait(false);
        return entity is null ? null : DomainMappings.ToDomain(entity);
    }

    /// <summary>
    /// Persist a mutated <see cref="DidDocument"/> using optimistic concurrency.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Callers obtain a document at version <c>N</c> via <see cref="GetAsync"/>, mutate it
    /// (which bumps it to <c>N+1</c> in <c>DidService</c>), then call this method. EF Core's
    /// concurrency token (<see cref="DidDocumentEntity.Version"/>, configured in
    /// <see cref="TesseraDbContext.OnModelCreating"/>) is set with its ORIGINAL value pinned to
    /// the pre-mutation version <c>N = document.Version - 1</c>. The resulting
    /// <c>UPDATE ... WHERE Id=@id AND Version=@N</c> affects zero rows — and throws
    /// <see cref="DbUpdateConcurrencyException"/> — if another writer already committed
    /// version <c>N+1</c> in the meantime. This prevents a lost update from, for example,
    /// resurrecting a DID that a concurrent <c>RevokeAsync</c> just revoked.
    /// </para>
    /// <para>
    /// The exception is intentionally NOT swallowed: callers (e.g. <c>RevokeAsync</c> /
    /// <c>BindWalletAsync</c>) should re-read the document and retry on the fresh snapshot.
    /// </para>
    /// </remarks>
    /// <exception cref="DbUpdateConcurrencyException">
    /// Another writer modified the document since the caller read it.
    /// </exception>
    public async Task SaveAsync(DidDocument document, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(document);

        var existing = await LoadGraphAsync(document.Id, ct).ConfigureAwait(false);
        if (existing is null)
        {
            var fresh = DomainMappings.ToEntity(document);
            _db.DidDocuments.Add(fresh);
        }
        else
        {
            DomainMappings.ToEntity(document, existing);

            // Pin the concurrency token's ORIGINAL value to the version the caller read
            // (pre-mutation = document.Version - 1) rather than the value freshly loaded from
            // the DB. Otherwise EF would compare against the current row and miss a concurrent
            // commit. The first write (which never came from a read) carries Version=1 and is
            // matched against an original of 0; any genuine update carries Version >= 2.
            var originalVersion = document.Version - 1;
            _db.Entry(existing).Property(e => e.Version).OriginalValue = originalVersion;
        }

        await _db.SaveChangesAsync(ct).ConfigureAwait(false);
    }

    public async Task<bool> ExistsAsync(DidId did, CancellationToken ct = default)
        => await _db.DidDocuments
            .AsNoTracking()
            .AnyAsync(d => d.Id == did.Value, ct)
            .ConfigureAwait(false);

    private Task<DidDocumentEntity?> LoadGraphAsync(DidId did, CancellationToken ct)
        => _db.DidDocuments
            .Include(d => d.VerificationMethods)
            .Include(d => d.Wallets)
            .Include(d => d.Bindings)
            .FirstOrDefaultAsync(d => d.Id == did.Value, ct);
}
