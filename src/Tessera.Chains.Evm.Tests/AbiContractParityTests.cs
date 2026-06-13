using System.Text;
using System.Text.Json;
using Nethereum.Contracts;
using Nethereum.Util;
using Tessera.Chains.Evm.Internal;

namespace Tessera.Chains.Evm.Tests;

/// <summary>
/// Deterministic, node-free parity checks: the C# Nethereum bindings must produce exactly
/// the function selectors of the compiled <c>IdentityRegistry</c> contract. The 4-byte selector
/// is <c>keccak256(canonicalSignature)[:4]</c>; if a parameter type or order drifts, the selector
/// changes and the contract would reject the call. These tests catch that at build time.
/// </summary>
public class AbiContractParityTests
{
    private static string SelectorOf(string canonicalSignature)
    {
        var hash = Sha3Keccack.Current.CalculateHash(Encoding.UTF8.GetBytes(canonicalSignature));
        return Convert.ToHexString(hash, 0, 4).ToLowerInvariant();
    }

    [Theory]
    [InlineData(typeof(RegisterDidFunction), "registerDid(bytes32,bytes32,address,bytes)")]
    [InlineData(typeof(UpdateRootFunction), "updateRoot(bytes32,bytes32)")]
    [InlineData(typeof(BumpRevocationFunction), "bumpRevocation(bytes32,uint8)")]
    [InlineData(typeof(RegisterIssuerFunction), "registerIssuer(bytes32,bytes32,string)")]
    [InlineData(typeof(DeactivateIssuerFunction), "deactivateIssuer(bytes32)")]
    [InlineData(typeof(GetAnchorFunction), "getAnchor(bytes32)")]
    public void DtoSelector_MatchesCanonicalSignature(Type functionType, string canonicalSignature)
    {
        var getAbi = typeof(ABITypedRegistry).GetMethod(nameof(ABITypedRegistry.GetFunctionABI), Type.EmptyTypes)!
            .MakeGenericMethod(functionType);
        var abi = (Nethereum.ABI.Model.FunctionABI)getAbi.Invoke(null, null)!;

        Assert.Equal(SelectorOf(canonicalSignature), abi.Sha3Signature.ToLowerInvariant());
    }

    [Fact]
    public void DtoSelectors_MatchCompiledContractAbi()
    {
        var abiPath = Path.Combine(AppContext.BaseDirectory, "IdentityRegistry.abi.json");
        Assert.True(File.Exists(abiPath), $"checked-in ABI not found at {abiPath}");

        using var doc = JsonDocument.Parse(File.ReadAllText(abiPath));
        var functions = doc.RootElement.EnumerateArray()
            .Where(e => e.GetProperty("type").GetString() == "function")
            .ToDictionary(
                e => e.GetProperty("name").GetString()!,
                e => SelectorOf(CanonicalSignature(e)));

        // Every binding we send must exist in the compiled contract with the same selector.
        Assert.Equal(functions["registerDid"], DtoSelector<RegisterDidFunction>());
        Assert.Equal(functions["updateRoot"], DtoSelector<UpdateRootFunction>());
        Assert.Equal(functions["bumpRevocation"], DtoSelector<BumpRevocationFunction>());
        Assert.Equal(functions["registerIssuer"], DtoSelector<RegisterIssuerFunction>());
        Assert.Equal(functions["deactivateIssuer"], DtoSelector<DeactivateIssuerFunction>());
        Assert.Equal(functions["getAnchor"], DtoSelector<GetAnchorFunction>());
    }

    [Fact]
    public void GetAnchor_OutputShape_MatchesContract()
    {
        var abiPath = Path.Combine(AppContext.BaseDirectory, "IdentityRegistry.abi.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(abiPath));
        var getAnchor = doc.RootElement.EnumerateArray()
            .First(e => e.GetProperty("type").GetString() == "function" && e.GetProperty("name").GetString() == "getAnchor");

        var outputs = getAnchor.GetProperty("outputs").EnumerateArray().Select(o => o.GetProperty("type").GetString()).ToArray();

        // Must match GetAnchorOutputDTO's ordered parameters.
        Assert.Equal(new[] { "bool", "address", "bytes32", "uint64", "uint64", "uint64" }, outputs);
    }

    private static string DtoSelector<T>() => ABITypedRegistry.GetFunctionABI<T>().Sha3Signature.ToLowerInvariant();

    private static string CanonicalSignature(JsonElement function)
    {
        var name = function.GetProperty("name").GetString();
        var inputs = function.GetProperty("inputs").EnumerateArray().Select(i => i.GetProperty("type").GetString());
        return $"{name}({string.Join(",", inputs)})";
    }
}
