using Tessera.Chains.Stellar;

namespace Tessera.Chains.Stellar.Tests;

/// <summary>
/// Offline guard-clause tests for <see cref="StellarChainAnchor"/> construction — these run with
/// no network and no secrets, so the project gives real coverage in CI even when the env-gated
/// testnet smoke tests skip.
/// </summary>
public class StellarAnchorOptionsTests
{
    private static StellarAnchorOptions Valid() => new()
    {
        SorobanRpcUrl = "https://soroban-testnet.stellar.org",
        ContractId = "CAAA",
        SigningKeySeed = "SAAA",
    };

    [Fact]
    public void Ctor_NullOptions_Throws()
        => Assert.Throws<ArgumentNullException>(() => new StellarChainAnchor(null!));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Ctor_BlankRpcUrl_Throws(string rpc)
        => Assert.Throws<ArgumentException>(() => new StellarChainAnchor(Valid() with { SorobanRpcUrl = rpc }));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Ctor_BlankContractId_Throws(string contract)
        => Assert.Throws<ArgumentException>(() => new StellarChainAnchor(Valid() with { ContractId = contract }));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Ctor_BlankSigningKey_Throws(string key)
        => Assert.Throws<ArgumentException>(() => new StellarChainAnchor(Valid() with { SigningKeySeed = key }));

    [Fact]
    public void Defaults_AreTestnet()
    {
        var opts = Valid();
        Assert.Equal("Test SDF Network ; September 2015", opts.NetworkPassphrase);
        Assert.Equal(TimeSpan.FromMinutes(2), opts.ConfirmationTimeout);
    }
}
