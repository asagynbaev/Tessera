using Solnet.Programs;
using Solnet.Rpc.Models;
using Solnet.Wallet;
using Tessera.Chains.Solana.Internal;

namespace Tessera.Chains.Solana.Instructions;

/// <summary>
/// Builders for the four <c>identity-registry</c> Anchor instructions.
/// Account ordering MUST match the Rust <c>#[derive(Accounts)]</c> structs exactly —
/// breaking that contract sends bytes the program will reject.
/// </summary>
internal static class IdentityRegistryInstructions
{
    /// <summary>
    /// Build an <c>initialize</c> instruction that creates the singleton <c>RegistryConfig</c>
    /// PDA and records the registry <paramref name="admin"/>.
    /// Account order (from <c>Initialize&lt;'info&gt;</c>): registry_config (PDA, init), payer (signer), system_program.
    /// </summary>
    public static TransactionInstruction Initialize(
        PublicKey programId,
        PublicKey registryConfigPda,
        PublicKey payer,
        PublicKey admin)
    {
        var data = new AnchorBorshWriter()
            .WriteFixedBytes(IdentityRegistryDiscriminators.Initialize, 8)
            .WritePubkey(admin.KeyBytes)
            .ToArray();

        return new TransactionInstruction
        {
            ProgramId = programId.KeyBytes,
            Keys = new List<AccountMeta>
            {
                AccountMeta.Writable(registryConfigPda, isSigner: false),
                AccountMeta.Writable(payer, isSigner: true),
                AccountMeta.ReadOnly(SystemProgram.ProgramIdKey, isSigner: false),
            },
            Data = data,
        };
    }

    /// <summary>
    /// Build a <c>register_did</c> instruction.
    /// Account order (from <c>RegisterDid&lt;'info&gt;</c>): did_anchor (PDA, init), owner (signer, payer), system_program.
    /// </summary>
    public static TransactionInstruction RegisterDid(
        PublicKey programId,
        PublicKey didAnchorPda,
        PublicKey owner,
        ReadOnlySpan<byte> didHash,
        ReadOnlySpan<byte> attestationRoot)
    {
        if (didHash.Length != 32) throw new ArgumentException("did_hash must be 32 bytes.", nameof(didHash));
        if (attestationRoot.Length != 32) throw new ArgumentException("attestation_root must be 32 bytes.", nameof(attestationRoot));

        var data = new AnchorBorshWriter()
            .WriteFixedBytes(IdentityRegistryDiscriminators.RegisterDid, 8)
            .WriteFixedBytes(didHash, 32)
            .WriteFixedBytes(attestationRoot, 32)
            .ToArray();

        return new TransactionInstruction
        {
            ProgramId = programId.KeyBytes,
            Keys = new List<AccountMeta>
            {
                AccountMeta.Writable(didAnchorPda, isSigner: false),
                AccountMeta.Writable(owner, isSigner: true),
                AccountMeta.ReadOnly(SystemProgram.ProgramIdKey, isSigner: false),
            },
            Data = data,
        };
    }

    /// <summary>
    /// Build an <c>update_root</c> instruction.
    /// Account order (from <c>UpdateDid&lt;'info&gt;</c>): did_anchor (PDA, mut), owner (signer).
    /// </summary>
    public static TransactionInstruction UpdateRoot(
        PublicKey programId,
        PublicKey didAnchorPda,
        PublicKey owner,
        ReadOnlySpan<byte> newRoot)
    {
        if (newRoot.Length != 32) throw new ArgumentException("new_root must be 32 bytes.", nameof(newRoot));

        var data = new AnchorBorshWriter()
            .WriteFixedBytes(IdentityRegistryDiscriminators.UpdateRoot, 8)
            .WriteFixedBytes(newRoot, 32)
            .ToArray();

        return new TransactionInstruction
        {
            ProgramId = programId.KeyBytes,
            Keys = new List<AccountMeta>
            {
                AccountMeta.Writable(didAnchorPda, isSigner: false),
                AccountMeta.ReadOnly(owner, isSigner: true),
            },
            Data = data,
        };
    }

    /// <summary>
    /// Build a <c>bump_revocation</c> instruction.
    /// </summary>
    public static TransactionInstruction BumpRevocation(
        PublicKey programId,
        PublicKey didAnchorPda,
        PublicKey owner,
        byte reason)
    {
        var data = new AnchorBorshWriter()
            .WriteFixedBytes(IdentityRegistryDiscriminators.BumpRevocation, 8)
            .WriteU8(reason)
            .ToArray();

        return new TransactionInstruction
        {
            ProgramId = programId.KeyBytes,
            Keys = new List<AccountMeta>
            {
                AccountMeta.Writable(didAnchorPda, isSigner: false),
                AccountMeta.ReadOnly(owner, isSigner: true),
            },
            Data = data,
        };
    }

    /// <summary>
    /// Build a <c>register_issuer</c> instruction. ADMIN-GATED on-chain: <paramref name="admin"/>
    /// must sign and must equal <c>RegistryConfig.admin</c>.
    /// Account order (from <c>RegisterIssuer&lt;'info&gt;</c>): registry_config (PDA, readonly),
    /// issuer (PDA, init), signing_key (readonly), admin (signer, payer), system_program.
    /// </summary>
    public static TransactionInstruction RegisterIssuer(
        PublicKey programId,
        PublicKey registryConfigPda,
        PublicKey issuerPda,
        PublicKey signingKey,
        PublicKey admin,
        ReadOnlySpan<byte> issuerDidHash,
        string schemaUri)
    {
        if (issuerDidHash.Length != 32) throw new ArgumentException("issuer_did_hash must be 32 bytes.", nameof(issuerDidHash));
        if (schemaUri.Length > 200) throw new ArgumentException("schema_uri exceeds MAX_SCHEMA_URI_LEN (200).", nameof(schemaUri));

        var data = new AnchorBorshWriter()
            .WriteFixedBytes(IdentityRegistryDiscriminators.RegisterIssuer, 8)
            .WriteFixedBytes(issuerDidHash, 32)
            .WriteString(schemaUri)
            .ToArray();

        return new TransactionInstruction
        {
            ProgramId = programId.KeyBytes,
            Keys = new List<AccountMeta>
            {
                AccountMeta.ReadOnly(registryConfigPda, isSigner: false),
                AccountMeta.Writable(issuerPda, isSigner: false),
                AccountMeta.ReadOnly(signingKey, isSigner: false),
                AccountMeta.Writable(admin, isSigner: true),
                AccountMeta.ReadOnly(SystemProgram.ProgramIdKey, isSigner: false),
            },
            Data = data,
        };
    }

    /// <summary>
    /// Build a <c>deactivate_issuer</c> instruction. ADMIN-GATED on-chain: <paramref name="admin"/>
    /// must sign and must equal <c>RegistryConfig.admin</c>.
    /// Account order (from <c>DeactivateIssuer&lt;'info&gt;</c>): registry_config (PDA, readonly),
    /// issuer (PDA, mut), admin (signer).
    /// </summary>
    public static TransactionInstruction DeactivateIssuer(
        PublicKey programId,
        PublicKey registryConfigPda,
        PublicKey issuerPda,
        PublicKey admin)
    {
        var data = new AnchorBorshWriter()
            .WriteFixedBytes(IdentityRegistryDiscriminators.DeactivateIssuer, 8)
            .ToArray();

        return new TransactionInstruction
        {
            ProgramId = programId.KeyBytes,
            Keys = new List<AccountMeta>
            {
                AccountMeta.ReadOnly(registryConfigPda, isSigner: false),
                AccountMeta.Writable(issuerPda, isSigner: false),
                AccountMeta.ReadOnly(admin, isSigner: true),
            },
            Data = data,
        };
    }
}
