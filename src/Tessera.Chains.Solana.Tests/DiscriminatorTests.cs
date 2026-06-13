using System.Security.Cryptography;
using System.Text;
using Tessera.Chains.Solana.Internal;

namespace Tessera.Chains.Solana.Tests;

public class DiscriminatorTests
{
    [Fact]
    public void InstructionDiscriminators_AreEightBytes()
    {
        Assert.Equal(8, IdentityRegistryDiscriminators.Initialize.Length);
        Assert.Equal(8, IdentityRegistryDiscriminators.RegisterDid.Length);
        Assert.Equal(8, IdentityRegistryDiscriminators.UpdateRoot.Length);
        Assert.Equal(8, IdentityRegistryDiscriminators.BumpRevocation.Length);
        Assert.Equal(8, IdentityRegistryDiscriminators.RegisterIssuer.Length);
        Assert.Equal(8, IdentityRegistryDiscriminators.DeactivateIssuer.Length);
    }

    [Fact]
    public void AccountDiscriminators_AreEightBytes()
    {
        Assert.Equal(8, IdentityRegistryDiscriminators.RegistryConfigAccount.Length);
        Assert.Equal(8, IdentityRegistryDiscriminators.DidAnchorAccount.Length);
        Assert.Equal(8, IdentityRegistryDiscriminators.IssuerAccount.Length);
    }

    [Fact]
    public void InstructionDiscriminators_AreDistinct()
    {
        var all = new[]
        {
            IdentityRegistryDiscriminators.Initialize,
            IdentityRegistryDiscriminators.RegisterDid,
            IdentityRegistryDiscriminators.UpdateRoot,
            IdentityRegistryDiscriminators.BumpRevocation,
            IdentityRegistryDiscriminators.RegisterIssuer,
            IdentityRegistryDiscriminators.DeactivateIssuer,
        };

        for (int i = 0; i < all.Length; i++)
            for (int j = i + 1; j < all.Length; j++)
                Assert.False(all[i].SequenceEqual(all[j]), $"discriminator collision at {i},{j}");
    }

    [Fact]
    public void AccountDiscriminators_AreDistinct()
    {
        var all = new[]
        {
            IdentityRegistryDiscriminators.RegistryConfigAccount,
            IdentityRegistryDiscriminators.DidAnchorAccount,
            IdentityRegistryDiscriminators.IssuerAccount,
        };

        for (int i = 0; i < all.Length; i++)
            for (int j = i + 1; j < all.Length; j++)
                Assert.False(all[i].SequenceEqual(all[j]), $"account discriminator collision at {i},{j}");
    }

    [Fact]
    public void Discriminator_MatchesAnchorFormula_ForInstruction()
    {
        // Anchor's rule: first 8 bytes of sha256("global:<snake_case_name>").
        // Reproducing it independently here proves our internal helper is correct
        // — if Anchor's IDL ever ships, this hex is what an external verifier would expect.
        var expected = SHA256.HashData(Encoding.UTF8.GetBytes("global:register_did"))[..8];
        Assert.Equal(expected, IdentityRegistryDiscriminators.RegisterDid);
    }

    [Fact]
    public void Discriminator_MatchesAnchorFormula_ForAccount()
    {
        var expected = SHA256.HashData(Encoding.UTF8.GetBytes("account:DidAnchor"))[..8];
        Assert.Equal(expected, IdentityRegistryDiscriminators.DidAnchorAccount);
    }

    [Fact]
    public void Discriminator_IsDeterministic()
    {
        var a = AnchorDiscriminator.ForInstruction("register_did");
        var b = AnchorDiscriminator.ForInstruction("register_did");
        Assert.Equal(a, b);
    }
}
