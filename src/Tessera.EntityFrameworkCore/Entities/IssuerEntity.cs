namespace Tessera.EntityFrameworkCore.Entities;

/// <summary>
/// Persistence-side projection of <see cref="Tessera.Attestations.IssuerRecord"/>.
/// </summary>
public sealed class IssuerEntity
{
    /// <summary>Issuer DID string. Primary key.</summary>
    public string Did { get; set; } = "";

    public byte[] PublicKey { get; set; } = Array.Empty<byte>();

    /// <summary>Algorithm identifier, e.g. <c>"ed25519"</c>.</summary>
    public string Algorithm { get; set; } = "";

    public string SchemaUri { get; set; } = "";

    /// <summary>False = revoked / deactivated; lookups must filter on this.</summary>
    public bool Active { get; set; }

    /// <summary>
    /// Optimistic-concurrency token, bumped on every update by <c>EfCoreIssuerRegistry</c> and
    /// configured as a concurrency token in <c>TesseraDbContext</c>. Prevents a racing
    /// <c>DeactivateAsync</c> and <c>RegisterAsync</c> from silently clobbering one another.
    /// </summary>
    public int Version { get; set; } = 1;

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
