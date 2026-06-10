using System.Text;
using System.Text.Json;
using Nethereum.Util;

namespace Tessera.Chains.Evm.Tests;

public class EvmAllowlistGatewayUnitTests
{
    private const string DummyKey = "0x4646464646464646464646464646464646464646464646464646464646464646";
    private const string DummyContract = "0x0000000000000000000000000000000000000001";
    private const string SampleAddr = "0x000000000000000000000000000000000000dEaD";

    private static EvmAllowlistGatewayOptions Opts(AllowlistFunctionStyle style = AllowlistFunctionStyle.AddRemovePair, string? tag = null) => new()
    {
        RpcUrl = "http://localhost:8545",
        ChainId = 97,
        ContractAddress = DummyContract,
        PrivateKey = DummyKey,
        ChainTag = tag,
        Style = style,
    };

    private static string SelectorOf(string sig)
        => Convert.ToHexString(Sha3Keccack.Current.CalculateHash(Encoding.UTF8.GetBytes(sig)), 0, 4).ToLowerInvariant();

    [Fact]
    public void ChainId_DefaultsTo_EvmColonChainId()
        => Assert.Equal("evm:97", new EvmAllowlistGateway(Opts()).ChainId);

    [Fact]
    public void ChainTag_Override_Wins()
        => Assert.Equal("bsc", new EvmAllowlistGateway(Opts(tag: "bsc")).ChainId);

    [Theory]
    [InlineData("", DummyContract, DummyKey, 97)]
    [InlineData("http://x", "", DummyKey, 97)]
    [InlineData("http://x", DummyContract, "", 97)]
    [InlineData("http://x", DummyContract, DummyKey, 0)]
    public void Ctor_Validates_RequiredFields(string rpc, string contract, string key, long chainId)
    {
        var options = new EvmAllowlistGatewayOptions { RpcUrl = rpc, ChainId = chainId, ContractAddress = contract, PrivateKey = key };
        Assert.Throws<ArgumentException>(() => new EvmAllowlistGateway(options));
    }

    [Fact]
    public void AddRemovePair_Resolves_ToConfiguredFunctions()
    {
        var gw = new EvmAllowlistGateway(Opts(AllowlistFunctionStyle.AddRemovePair));

        var add = gw.ResolveAdd(SampleAddr);
        Assert.Equal("addToAllowlist", add.name);
        Assert.Equal(new object[] { SampleAddr }, add.args);

        var rev = gw.ResolveRevoke(SampleAddr);
        Assert.Equal("removeFromAllowlist", rev.name);
        Assert.Equal(new object[] { SampleAddr }, rev.args);
    }

    [Fact]
    public void SetBoolFlag_Resolves_ToSetWithBool()
    {
        var gw = new EvmAllowlistGateway(Opts(AllowlistFunctionStyle.SetBoolFlag));

        var add = gw.ResolveAdd(SampleAddr);
        Assert.Equal("setAllowed", add.name);
        Assert.Equal(new object[] { SampleAddr, true }, add.args);

        var rev = gw.ResolveRevoke(SampleAddr);
        Assert.Equal("setAllowed", rev.name);
        Assert.Equal(new object[] { SampleAddr, false }, rev.args);
    }

    [Fact]
    public async Task AddAsync_Rejects_InvalidAddress()
    {
        var gw = new EvmAllowlistGateway(Opts());
        await Assert.ThrowsAsync<ArgumentException>(() => gw.AddAsync("not-an-address"));
        await Assert.ThrowsAsync<ArgumentException>(() => gw.RevokeAsync("0x123"));
    }

    [Fact]
    public void BuildAbi_AddRemovePair_HasExpectedSelectors()
    {
        using var doc = JsonDocument.Parse(EvmAllowlistGateway.BuildAbi(Opts(AllowlistFunctionStyle.AddRemovePair)));
        var byName = doc.RootElement.EnumerateArray().ToDictionary(e => e.GetProperty("name").GetString()!);

        Assert.True(byName.ContainsKey("addToAllowlist"));
        Assert.True(byName.ContainsKey("removeFromAllowlist"));
        Assert.True(byName.ContainsKey("isAllowed"));

        Assert.Equal("address", byName["addToAllowlist"].GetProperty("inputs")[0].GetProperty("type").GetString());
        Assert.Equal(SelectorOf("addToAllowlist(address)"), SelectorOf(Canonical(byName["addToAllowlist"])));
        Assert.Equal(SelectorOf("removeFromAllowlist(address)"), SelectorOf(Canonical(byName["removeFromAllowlist"])));
    }

    [Fact]
    public void BuildAbi_SetBoolFlag_HasSetWithAddressBool()
    {
        using var doc = JsonDocument.Parse(EvmAllowlistGateway.BuildAbi(Opts(AllowlistFunctionStyle.SetBoolFlag)));
        var set = doc.RootElement.EnumerateArray().First(e => e.GetProperty("name").GetString() == "setAllowed");

        var inputs = set.GetProperty("inputs").EnumerateArray().Select(i => i.GetProperty("type").GetString()).ToArray();
        Assert.Equal(new[] { "address", "bool" }, inputs);
        Assert.Equal(SelectorOf("setAllowed(address,bool)"), SelectorOf(Canonical(set)));
    }

    private static string Canonical(JsonElement fn)
    {
        var name = fn.GetProperty("name").GetString();
        var inputs = fn.GetProperty("inputs").EnumerateArray().Select(i => i.GetProperty("type").GetString());
        return $"{name}({string.Join(",", inputs)})";
    }
}
