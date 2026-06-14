using Tessera.Chains.Cardano;
using Tessera.Chains.Cardano.Internal;

namespace Tessera.Chains.Cardano.Tests;

/// <summary>
/// The policy id and script address the adapter derives from the embedded blueprint must match
/// what <c>aiken blueprint policy/address</c> produced — otherwise the adapter would anchor to the
/// wrong address. This is the C# counterpart of the Solana PdaTests.
/// </summary>
public class ScriptAddressTests
{
    // These pin the script hashes / address the adapter derives from the embedded blueprint to what
    // `aiken build` (v1.1.21 / stdlib v3.1.0) produces. Updated for the v3.2.0 governance-gated
    // issuer_registry (admin-parameterized) — see chains/cardano .../plutus.json.
    private const string IdentityAnchorPolicyId = "6d6f737ce5acbc23a4bb0daf5391a6b2bfb2f22adde5671d7bbb58d3";
    private const string IdentityAnchorPreprodAddress = "addr_test1wpkk7umuukktcgayhvx675u356etlvhj9tw72eca0wa435cx7hx7c";
    private const string IssuerRegistryPolicyId = "5fa90b33d76bde659c294dff557eae6df6c4157bba6048aa2ff8f477";

    [Fact]
    public void IdentityAnchor_PolicyId_MatchesAikenBlueprint()
    {
        var script = Blueprint.LoadIdentityAnchorScript();
        Assert.Equal(IdentityAnchorPolicyId, ScriptAddress.PolicyIdHex(script));
    }

    [Fact]
    public void IdentityAnchor_PreprodAddress_MatchesAikenBlueprint()
    {
        var script = Blueprint.LoadIdentityAnchorScript();
        var policy = ScriptAddress.PolicyId(script);
        Assert.Equal(IdentityAnchorPreprodAddress, ScriptAddress.EnterpriseAddress(policy, CardanoNetwork.Preprod));
    }

    [Fact]
    public void IssuerRegistry_PolicyId_MatchesAikenBlueprint()
    {
        var script = Blueprint.LoadIssuerRegistryScript();
        Assert.Equal(IssuerRegistryPolicyId, ScriptAddress.PolicyIdHex(script));
    }

    [Fact]
    public void MainnetAddress_UsesMainnetHrpAndHeader()
    {
        var policy = ScriptAddress.PolicyId(Blueprint.LoadIdentityAnchorScript());
        Assert.StartsWith("addr1", ScriptAddress.EnterpriseAddress(policy, CardanoNetwork.Mainnet));
    }
}
