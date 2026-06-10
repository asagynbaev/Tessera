namespace Tessera.Chains.Evm.Tests.Smoke;

/// <summary>
/// Live-network smoke test for <see cref="EvmAllowlistGateway"/> against a deployed
/// <c>Allowlist</c> contract. Skipped unless the base EVM env (see <see cref="EvmTestnetConfig"/>)
/// plus <c>TESSERA_EVM_ALLOWLIST</c> (the deployed Allowlist address) are set, and the signing
/// account is an agent on that contract.
/// </summary>
[Collection("EvmTestnet")]
public class EvmAllowlistSmokeTests
{
    [SkippableFact]
    public async Task Add_Then_Revoke_RoundTrips()
    {
        Skip.IfNot(EvmTestnetConfig.TryLoad(out var config, out var reason), reason);
        var allowlistAddr = Environment.GetEnvironmentVariable("TESSERA_EVM_ALLOWLIST");
        Skip.If(string.IsNullOrWhiteSpace(allowlistAddr), "TESSERA_EVM_ALLOWLIST not set (deployed Allowlist address).");

        var gateway = new EvmAllowlistGateway(new EvmAllowlistGatewayOptions
        {
            RpcUrl = config!.RpcUrl,
            ChainId = config.ChainId,
            ContractAddress = allowlistAddr!,
            PrivateKey = config.PrivateKey,
        });

        // A throwaway target address (not the signer) we can freely flip.
        const string target = "0x000000000000000000000000000000000000bEEF";

        await gateway.AddAsync(target);
        Assert.True(await gateway.IsAllowedAsync(target));

        await gateway.RevokeAsync(target);
        Assert.False(await gateway.IsAllowedAsync(target));
    }
}
