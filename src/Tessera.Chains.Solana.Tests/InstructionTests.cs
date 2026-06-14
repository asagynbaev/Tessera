using Solnet.Wallet;
using Tessera.Chains.Solana.Instructions;
using Tessera.Chains.Solana.Internal;

namespace Tessera.Chains.Solana.Tests;

public class InstructionTests
{
    // Real deployment will replace these with deployed program/account IDs.
    // We use valid base58 strings here so PublicKey ctor doesn't reject them at class-init.
    private static readonly PublicKey Program = new("11111111111111111111111111111114");
    private static readonly PublicKey PdaKey = new("11111111111111111111111111111112");
    private static readonly PublicKey Owner = new("11111111111111111111111111111113");
    private static readonly PublicKey ConfigKey = new("11111111111111111111111111111115");

    private static byte[] FilledHash(byte seed)
    {
        var b = new byte[32];
        for (int i = 0; i < 32; i++) b[i] = (byte)(seed + i);
        return b;
    }

    [Fact]
    public void RegisterDid_DataLayout()
    {
        var didHash = FilledHash(1);
        var root = FilledHash(2);

        var ix = IdentityRegistryInstructions.RegisterDid(Program, PdaKey, Owner, didHash, root);

        // 8 discriminator + 32 did_hash + 32 attestation_root
        Assert.Equal(8 + 32 + 32, ix.Data.Length);
        Assert.Equal(IdentityRegistryDiscriminators.RegisterDid, ix.Data[..8]);
        Assert.Equal(didHash, ix.Data[8..40]);
        Assert.Equal(root, ix.Data[40..72]);
    }

    [Fact]
    public void RegisterDid_AccountList_HasCorrectOrderAndSigners()
    {
        var ix = IdentityRegistryInstructions.RegisterDid(Program, PdaKey, Owner, FilledHash(0), FilledHash(1));

        Assert.Equal(3, ix.Keys.Count);

        // 0: did_anchor PDA — writable, NOT signer
        Assert.Equal(PdaKey.Key, ix.Keys[0].PublicKey);
        Assert.True(ix.Keys[0].IsWritable);
        Assert.False(ix.Keys[0].IsSigner);

        // 1: owner — writable (pays rent), signer
        Assert.Equal(Owner.Key, ix.Keys[1].PublicKey);
        Assert.True(ix.Keys[1].IsWritable);
        Assert.True(ix.Keys[1].IsSigner);

        // 2: system_program — readonly, not signer
        Assert.False(ix.Keys[2].IsWritable);
        Assert.False(ix.Keys[2].IsSigner);
    }

    [Fact]
    public void RegisterDid_RejectsWrongHashLength()
    {
        Assert.Throws<ArgumentException>(() =>
            IdentityRegistryInstructions.RegisterDid(Program, PdaKey, Owner, new byte[31], new byte[32]));
        Assert.Throws<ArgumentException>(() =>
            IdentityRegistryInstructions.RegisterDid(Program, PdaKey, Owner, new byte[32], new byte[31]));
    }

    [Fact]
    public void UpdateRoot_DataLayout()
    {
        var newRoot = FilledHash(5);
        var ix = IdentityRegistryInstructions.UpdateRoot(Program, PdaKey, Owner, newRoot);

        Assert.Equal(8 + 32, ix.Data.Length);
        Assert.Equal(IdentityRegistryDiscriminators.UpdateRoot, ix.Data[..8]);
        Assert.Equal(newRoot, ix.Data[8..40]);
    }

    [Fact]
    public void UpdateRoot_AccountList()
    {
        var ix = IdentityRegistryInstructions.UpdateRoot(Program, PdaKey, Owner, FilledHash(0));

        Assert.Equal(2, ix.Keys.Count);
        Assert.True(ix.Keys[0].IsWritable);   // PDA
        Assert.False(ix.Keys[0].IsSigner);
        Assert.False(ix.Keys[1].IsWritable);  // owner — read-only signer
        Assert.True(ix.Keys[1].IsSigner);
    }

    [Fact]
    public void BumpRevocation_DataLayout()
    {
        var ix = IdentityRegistryInstructions.BumpRevocation(Program, PdaKey, Owner, reason: 3);

        Assert.Equal(8 + 1, ix.Data.Length);
        Assert.Equal(IdentityRegistryDiscriminators.BumpRevocation, ix.Data[..8]);
        Assert.Equal((byte)3, ix.Data[8]);
    }

    [Fact]
    public void Initialize_DataLayout()
    {
        var admin = Owner;
        var ix = IdentityRegistryInstructions.Initialize(Program, ConfigKey, payer: Owner, admin: admin);

        // 8 discriminator + 32 admin pubkey
        Assert.Equal(8 + 32, ix.Data.Length);
        Assert.Equal(IdentityRegistryDiscriminators.Initialize, ix.Data[..8]);
        Assert.Equal(admin.KeyBytes, ix.Data[8..40]);
    }

    [Fact]
    public void Initialize_AccountList()
    {
        var ix = IdentityRegistryInstructions.Initialize(Program, ConfigKey, payer: Owner, admin: Owner);

        Assert.Equal(3, ix.Keys.Count);
        Assert.Equal(ConfigKey.Key, ix.Keys[0].PublicKey);  // registry_config PDA (init)
        Assert.True(ix.Keys[0].IsWritable);
        Assert.False(ix.Keys[0].IsSigner);
        Assert.True(ix.Keys[1].IsWritable);                  // payer
        Assert.True(ix.Keys[1].IsSigner);
        Assert.False(ix.Keys[2].IsWritable);                 // system_program
        Assert.False(ix.Keys[2].IsSigner);
    }

    [Fact]
    public void RegisterIssuer_DataLayout()
    {
        var issuerHash = FilledHash(7);
        var ix = IdentityRegistryInstructions.RegisterIssuer(
            Program,
            registryConfigPda: ConfigKey,
            issuerPda: PdaKey,
            signingKey: Owner,
            admin: Owner,
            issuerDidHash: issuerHash,
            schemaUri: "v1");

        // 8 discriminator + 32 hash + 4 string-length + 2 utf8 bytes
        Assert.Equal(8 + 32 + 4 + 2, ix.Data.Length);
        Assert.Equal(IdentityRegistryDiscriminators.RegisterIssuer, ix.Data[..8]);
        Assert.Equal(issuerHash, ix.Data[8..40]);
        Assert.Equal(new byte[] { 2, 0, 0, 0 }, ix.Data[40..44]);
        Assert.Equal((byte)'v', ix.Data[44]);
        Assert.Equal((byte)'1', ix.Data[45]);
    }

    [Fact]
    public void RegisterIssuer_AccountList()
    {
        var ix = IdentityRegistryInstructions.RegisterIssuer(
            Program, ConfigKey, PdaKey, Owner, Owner, FilledHash(0), "x");

        // Order must match Rust RegisterIssuer<'info>: registry_config, issuer, signing_key, admin, system_program.
        Assert.Equal(5, ix.Keys.Count);
        Assert.Equal(ConfigKey.Key, ix.Keys[0].PublicKey);  // registry_config — readonly, not signer
        Assert.False(ix.Keys[0].IsWritable);
        Assert.False(ix.Keys[0].IsSigner);
        Assert.Equal(PdaKey.Key, ix.Keys[1].PublicKey);     // issuer PDA (init) — writable
        Assert.True(ix.Keys[1].IsWritable);
        Assert.False(ix.Keys[1].IsSigner);
        Assert.False(ix.Keys[2].IsWritable);                 // signing_key — readonly
        Assert.False(ix.Keys[2].IsSigner);
        Assert.True(ix.Keys[3].IsWritable);                  // admin pays rent — writable signer
        Assert.True(ix.Keys[3].IsSigner);
        Assert.False(ix.Keys[4].IsWritable);                 // system_program
        Assert.False(ix.Keys[4].IsSigner);
    }

    [Fact]
    public void RegisterIssuer_RejectsOversizedSchema()
    {
        var hash = FilledHash(0);
        var tooLong = new string('a', 201);  // MAX_SCHEMA_URI_LEN = 200
        Assert.Throws<ArgumentException>(() =>
            IdentityRegistryInstructions.RegisterIssuer(Program, ConfigKey, PdaKey, Owner, Owner, hash, tooLong));
    }

    [Fact]
    public void DeactivateIssuer_DataLayout()
    {
        var ix = IdentityRegistryInstructions.DeactivateIssuer(Program, ConfigKey, PdaKey, admin: Owner);

        Assert.Equal(8, ix.Data.Length);
        Assert.Equal(IdentityRegistryDiscriminators.DeactivateIssuer, ix.Data[..8]);
    }

    [Fact]
    public void DeactivateIssuer_AccountList()
    {
        var ix = IdentityRegistryInstructions.DeactivateIssuer(Program, ConfigKey, PdaKey, admin: Owner);

        // Order must match Rust DeactivateIssuer<'info>: registry_config, issuer, admin.
        Assert.Equal(3, ix.Keys.Count);
        Assert.Equal(ConfigKey.Key, ix.Keys[0].PublicKey);  // registry_config — readonly
        Assert.False(ix.Keys[0].IsWritable);
        Assert.True(ix.Keys[1].IsWritable);                  // issuer PDA — mut
        Assert.False(ix.Keys[1].IsSigner);
        Assert.False(ix.Keys[2].IsWritable);                 // admin — readonly signer
        Assert.True(ix.Keys[2].IsSigner);
    }
}
