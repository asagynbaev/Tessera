using Tessera.Chains.Solana.Accounts;
using Tessera.Chains.Solana.Internal;

namespace Tessera.Chains.Solana.Tests;

public class AccountDecoderTests
{
    private static byte[] FilledBytes(byte seed, int len)
    {
        var b = new byte[len];
        for (int i = 0; i < len; i++) b[i] = (byte)(seed + i);
        return b;
    }

    [Fact]
    public void DidAnchor_DecodesAllFields()
    {
        var didHash = FilledBytes(10, 32);
        var owner = FilledBytes(50, 32);
        var root = FilledBytes(100, 32);

        var raw = Concat(
            IdentityRegistryDiscriminators.DidAnchorAccount,
            new AnchorBorshWriter()
                .WriteU8(1)
                .WriteFixedBytes(didHash, 32)
                .WriteFixedBytes(owner, 32)
                .WriteFixedBytes(root, 32)
                .WriteU64(42)
                .WriteI64(1_700_000_000)
                .WriteI64(1_700_000_500)
                .ToArray());

        var account = DidAnchorAccount.Decode(raw);

        Assert.Equal((byte)1, account.AccountVersion);
        Assert.Equal(didHash, account.DidHash);
        Assert.Equal(owner, account.Owner);
        Assert.Equal(root, account.AttestationRoot);
        Assert.Equal(42UL, account.RevocationEpoch);
        Assert.Equal(1_700_000_000L, account.CreatedAt);
        Assert.Equal(1_700_000_500L, account.UpdatedAt);
    }

    [Fact]
    public void DidAnchor_WrongDiscriminator_Throws()
    {
        var raw = new byte[129];
        // discriminator bytes left as zeros — won't match real DidAnchor disc.
        Assert.Throws<ArgumentException>(() => DidAnchorAccount.Decode(raw));
    }

    [Fact]
    public void DidAnchor_DataTooShort_Throws()
    {
        Assert.Throws<ArgumentException>(() => DidAnchorAccount.Decode(new byte[8]));
    }

    [Fact]
    public void Issuer_DecodesAllFields()
    {
        var didHash = FilledBytes(20, 32);
        var signingKey = FilledBytes(80, 32);
        var schemaUri = "https://schemas.tessera/attestation/v1";

        var raw = Concat(
            IdentityRegistryDiscriminators.IssuerAccount,
            new AnchorBorshWriter()
                .WriteU8(1)
                .WriteFixedBytes(didHash, 32)
                .WriteFixedBytes(signingKey, 32)
                .WriteString(schemaUri)
                .WriteBool(true)
                .WriteI64(1_700_000_000)
                .ToArray());

        var account = IssuerAccount.Decode(raw);

        Assert.Equal((byte)1, account.AccountVersion);
        Assert.Equal(didHash, account.IssuerDidHash);
        Assert.Equal(signingKey, account.SigningKey);
        Assert.Equal(schemaUri, account.SchemaUri);
        Assert.True(account.Active);
        Assert.Equal(1_700_000_000L, account.CreatedAt);
    }

    [Fact]
    public void Issuer_InactiveFlagDecodes()
    {
        var raw = Concat(
            IdentityRegistryDiscriminators.IssuerAccount,
            new AnchorBorshWriter()
                .WriteU8(1)
                .WriteFixedBytes(FilledBytes(0, 32), 32)
                .WriteFixedBytes(FilledBytes(0, 32), 32)
                .WriteString("")
                .WriteBool(false)
                .WriteI64(0)
                .ToArray());

        var account = IssuerAccount.Decode(raw);
        Assert.False(account.Active);
    }

    [Fact]
    public void Issuer_WrongDiscriminator_Throws()
    {
        var raw = Concat(
            IdentityRegistryDiscriminators.DidAnchorAccount, // wrong disc on purpose
            new AnchorBorshWriter()
                .WriteU8(1)
                .WriteFixedBytes(FilledBytes(0, 32), 32)
                .WriteFixedBytes(FilledBytes(0, 32), 32)
                .WriteString("")
                .WriteBool(true)
                .WriteI64(0)
                .ToArray());

        Assert.Throws<ArgumentException>(() => IssuerAccount.Decode(raw));
    }

    [Fact]
    public void RegistryConfig_DecodesAllFields()
    {
        var admin = FilledBytes(60, 32);

        var raw = Concat(
            IdentityRegistryDiscriminators.RegistryConfigAccount,
            new AnchorBorshWriter()
                .WriteU8(1)
                .WriteFixedBytes(admin, 32)
                .WriteU8(254) // bump
                .ToArray());

        var account = RegistryConfigAccount.Decode(raw);

        Assert.Equal((byte)1, account.AccountVersion);
        Assert.Equal(admin, account.Admin);
        Assert.Equal((byte)254, account.Bump);
    }

    [Fact]
    public void RegistryConfig_WrongDiscriminator_Throws()
    {
        var raw = Concat(
            IdentityRegistryDiscriminators.DidAnchorAccount, // wrong disc on purpose
            new AnchorBorshWriter()
                .WriteU8(1)
                .WriteFixedBytes(FilledBytes(0, 32), 32)
                .WriteU8(255)
                .ToArray());

        Assert.Throws<ArgumentException>(() => RegistryConfigAccount.Decode(raw));
    }

    [Fact]
    public void RegistryConfig_DataTooShort_Throws()
    {
        Assert.Throws<ArgumentException>(() => RegistryConfigAccount.Decode(new byte[8]));
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var c = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, c, 0, a.Length);
        Buffer.BlockCopy(b, 0, c, a.Length, b.Length);
        return c;
    }
}
