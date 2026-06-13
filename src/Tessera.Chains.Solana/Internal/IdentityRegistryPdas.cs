using System.Text;
using Solnet.Wallet;
using Solnet.Wallet.Utilities;

namespace Tessera.Chains.Solana.Internal;

/// <summary>
/// PDA derivation matching the seeds declared by
/// <c>chains/solana/programs/identity-registry/src/lib.rs</c>.
/// </summary>
/// <remarks>
/// Seeds (must match Rust exactly):
/// <list type="bullet">
///   <item><c>[b"config"]</c> → <see cref="RegistryConfig"/> (singleton)</item>
///   <item><c>[b"did", did_hash]</c> → <see cref="DidAnchor"/></item>
///   <item><c>[b"issuer", issuer_did_hash]</c> → <see cref="Issuer"/></item>
/// </list>
/// </remarks>
internal static class IdentityRegistryPdas
{
    private static readonly byte[] DidSeed = Encoding.UTF8.GetBytes("did");
    private static readonly byte[] IssuerSeed = Encoding.UTF8.GetBytes("issuer");
    private static readonly byte[] ConfigSeed = Encoding.UTF8.GetBytes("config");

    /// <summary>Derive the singleton <c>RegistryConfig</c> PDA (<c>[b"config"]</c>).</summary>
    public static (PublicKey Pda, byte Bump) RegistryConfig(PublicKey programId)
    {
        var seeds = new List<byte[]> { ConfigSeed };
        if (!PublicKey.TryFindProgramAddress(seeds, programId, out var pda, out var bump))
            throw new InvalidOperationException("Failed to derive RegistryConfig PDA.");
        return (pda, bump);
    }

    public static (PublicKey Pda, byte Bump) DidAnchor(PublicKey programId, ReadOnlySpan<byte> didHash)
    {
        if (didHash.Length != 32)
            throw new ArgumentException("did_hash must be 32 bytes.", nameof(didHash));

        var seeds = new List<byte[]> { DidSeed, didHash.ToArray() };
        if (!PublicKey.TryFindProgramAddress(seeds, programId, out var pda, out var bump))
            throw new InvalidOperationException("Failed to derive DidAnchor PDA.");
        return (pda, bump);
    }

    public static (PublicKey Pda, byte Bump) Issuer(PublicKey programId, ReadOnlySpan<byte> issuerDidHash)
    {
        if (issuerDidHash.Length != 32)
            throw new ArgumentException("issuer_did_hash must be 32 bytes.", nameof(issuerDidHash));

        var seeds = new List<byte[]> { IssuerSeed, issuerDidHash.ToArray() };
        if (!PublicKey.TryFindProgramAddress(seeds, programId, out var pda, out var bump))
            throw new InvalidOperationException("Failed to derive Issuer PDA.");
        return (pda, bump);
    }
}
