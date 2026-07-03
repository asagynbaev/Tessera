using Microsoft.EntityFrameworkCore;
using Tessera.EntityFrameworkCore.Entities;

namespace Tessera.EntityFrameworkCore;

/// <summary>
/// EF Core <see cref="DbContext"/> holding Tessera's normalized identity schema.
/// Provider-agnostic — consumers configure Postgres / SQL Server / SQLite at the
/// composition root by passing <see cref="DbContextOptions{TesseraDbContext}"/>.
/// </summary>
/// <remarks>
/// Schema:
/// <list type="bullet">
///   <item><c>did_documents</c> — one row per DID, PK = DID string</item>
///   <item><c>verification_methods</c> — N rows per DID</item>
///   <item><c>wallet_bindings</c> — N rows per DID, unique (did, chain, address)</item>
///   <item><c>channel_bindings</c> — N rows per DID</item>
///   <item><c>issuers</c> — one row per issuer DID, PK = issuer DID string</item>
/// </list>
/// Schema migrations are the consumer's responsibility — generate them once with
/// <c>dotnet ef migrations add</c> against the chosen provider.
/// </remarks>
public class TesseraDbContext : DbContext
{
    public TesseraDbContext(DbContextOptions<TesseraDbContext> options)
        : base(options) { }

    /// <summary>For testing or subclass scenarios that pass a typed-options.</summary>
    protected TesseraDbContext(DbContextOptions options) : base(options) { }

    public DbSet<DidDocumentEntity> DidDocuments => Set<DidDocumentEntity>();
    public DbSet<VerificationMethodEntity> VerificationMethods => Set<VerificationMethodEntity>();
    public DbSet<WalletBindingEntity> WalletBindings => Set<WalletBindingEntity>();
    public DbSet<ChannelBindingEntity> ChannelBindings => Set<ChannelBindingEntity>();
    public DbSet<IssuerEntity> Issuers => Set<IssuerEntity>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<DidDocumentEntity>(e =>
        {
            e.ToTable("did_documents");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasMaxLength(256).IsRequired();
            e.Property(x => x.Controller).HasMaxLength(256).IsRequired();
            e.Property(x => x.AttestationRoot).HasMaxLength(32);
            e.Property(x => x.Revoked).IsRequired();

            // Optimistic concurrency: Version is bumped by DidService on every mutation.
            // Marking it a concurrency token makes EF emit UPDATE ... WHERE Id=@id AND Version=@original,
            // so a stale write (whose original Version no longer matches the row) affects 0 rows
            // and throws DbUpdateConcurrencyException instead of silently clobbering a concurrent
            // commit (e.g. resurrecting a revoked DID). See EfCoreDidStore.SaveAsync.
            e.Property(x => x.Version).IsRequired().IsConcurrencyToken();
            e.Property(x => x.CreatedAt).IsRequired();
            e.Property(x => x.UpdatedAt).IsRequired();

            e.HasMany(x => x.VerificationMethods)
                .WithOne(x => x.Document!)
                .HasForeignKey(x => x.DidId)
                .OnDelete(DeleteBehavior.Cascade);

            e.HasMany(x => x.Wallets)
                .WithOne(x => x.Document!)
                .HasForeignKey(x => x.DidId)
                .OnDelete(DeleteBehavior.Cascade);

            e.HasMany(x => x.Bindings)
                .WithOne(x => x.Document!)
                .HasForeignKey(x => x.DidId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<VerificationMethodEntity>(e =>
        {
            e.ToTable("verification_methods");
            e.HasKey(x => x.DbId);
            e.Property(x => x.DidId).HasMaxLength(256).IsRequired();
            e.Property(x => x.Id).HasMaxLength(512).IsRequired();
            e.Property(x => x.Type).HasMaxLength(128).IsRequired();
            e.Property(x => x.PublicKeyMultibase).HasMaxLength(512).IsRequired();

            e.HasIndex(x => new { x.DidId, x.Id }).IsUnique();
        });

        b.Entity<WalletBindingEntity>(e =>
        {
            e.ToTable("wallet_bindings");
            e.HasKey(x => x.DbId);
            e.Property(x => x.DidId).HasMaxLength(256).IsRequired();
            e.Property(x => x.Chain).HasMaxLength(64).IsRequired();
            e.Property(x => x.Address).HasMaxLength(256).IsRequired();
            e.Property(x => x.ProofSignature).IsRequired();
            e.Property(x => x.BoundAt).IsRequired();

            // (DID, chain, address) is the natural identity of a binding —
            // re-binding the same wallet replaces rather than duplicates.
            e.HasIndex(x => new { x.DidId, x.Chain, x.Address }).IsUnique();
        });

        b.Entity<ChannelBindingEntity>(e =>
        {
            e.ToTable("channel_bindings");
            e.HasKey(x => x.DbId);
            e.Property(x => x.DidId).HasMaxLength(256).IsRequired();
            e.Property(x => x.Type).HasMaxLength(64).IsRequired();
            e.Property(x => x.Commitment).IsRequired();
            e.Property(x => x.Issuer).HasMaxLength(256).IsRequired();
            e.Property(x => x.IssuedAt).IsRequired();

            e.HasIndex(x => new { x.DidId, x.Type });
        });

        b.Entity<IssuerEntity>(e =>
        {
            e.ToTable("issuers");
            e.HasKey(x => x.Did);
            e.Property(x => x.Did).HasMaxLength(256).IsRequired();
            e.Property(x => x.PublicKey).IsRequired();
            e.Property(x => x.Algorithm).HasMaxLength(32).IsRequired();
            e.Property(x => x.SchemaUri).HasMaxLength(512).IsRequired();
            e.Property(x => x.Active).IsRequired();

            // Optimistic concurrency (mirrors did_documents): Version is bumped on every update by
            // EfCoreIssuerRegistry. Marking it a concurrency token makes EF emit
            // UPDATE ... WHERE Did=@did AND Version=@original, so a racing writer (e.g. a
            // RegisterAsync that read the row before a concurrent DeactivateAsync committed) affects
            // 0 rows and throws DbUpdateConcurrencyException instead of silently losing the update.
            e.Property(x => x.Version).IsRequired().IsConcurrencyToken();
            e.Property(x => x.CreatedAt).IsRequired();
            e.Property(x => x.UpdatedAt).IsRequired();

            e.HasIndex(x => x.Active);
        });
    }
}
