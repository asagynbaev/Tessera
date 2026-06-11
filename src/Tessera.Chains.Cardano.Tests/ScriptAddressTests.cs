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
    private const string IdentityAnchorPolicyId = "73f81b6b4d9a0f348391acc37f7122cdca4dcc34a219c5ae111fdd60";
    private const string IdentityAnchorPreprodAddress = "addr_test1wpelsxmtfkdq7dyrjxkvxlm3ytxu5nwvxj3pn3dwzy0a6cqcu2k9g";
    private const string IssuerRegistryPolicyId = "3f94e0bc7163fef7ee132215bd94eee699b3a41fa5e049d4aca884e4";

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
