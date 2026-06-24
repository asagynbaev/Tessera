namespace Tessera.Chains.Evm.Tests.Smoke;

/// <summary>
/// Resolves EVM testnet smoke-test configuration from environment variables. When any
/// required variable is missing, <see cref="TryLoad"/> returns false with a reason — surface
/// it in <c>Skip.IfNot</c>. See <c>chains/evm/README.md</c> for deploy + setup steps.
/// </summary>
/// <remarks>
/// Required env vars:
/// <list type="bullet">
///   <item><c>TESSERA_EVM_RPC</c>: JSON-RPC URL (e.g. a BNB Chain testnet endpoint)</item>
///   <item><c>TESSERA_EVM_KEY</c>: deployer/owner private key (hex, 0x optional), funded for gas</item>
///   <item><c>TESSERA_EVM_REGISTRY</c>: deployed IdentityRegistry contract address (0x-hex)</item>
///   <item><c>TESSERA_EVM_CHAINID</c>: EIP-155 chain id (e.g. 97 for BNB testnet)</item>
///   <item><c>TESSERA_EVM_LEGACY_GAS</c> (optional): "1"/"true" to force legacy gas pricing.
///         Auto-enabled for BNB Chain (56/97), which rejects zero-priority-fee 1559 txs.</item>
/// </list>
/// </remarks>
internal sealed class EvmTestnetConfig
{
    public required string RpcUrl { get; init; }
    public required string PrivateKey { get; init; }
    public required string ContractAddress { get; init; }
    public required long ChainId { get; init; }
    public required bool UseLegacyGas { get; init; }

    public static bool TryLoad(out EvmTestnetConfig? config, out string missingReason)
    {
        config = null;

        var rpc = Environment.GetEnvironmentVariable("TESSERA_EVM_RPC");
        if (string.IsNullOrWhiteSpace(rpc))
        {
            missingReason = "TESSERA_EVM_RPC not set (JSON-RPC endpoint of an EVM testnet).";
            return false;
        }

        var key = Environment.GetEnvironmentVariable("TESSERA_EVM_KEY");
        if (string.IsNullOrWhiteSpace(key))
        {
            missingReason = "TESSERA_EVM_KEY not set (funded owner private key, hex).";
            return false;
        }

        var registry = Environment.GetEnvironmentVariable("TESSERA_EVM_REGISTRY");
        if (string.IsNullOrWhiteSpace(registry))
        {
            missingReason = "TESSERA_EVM_REGISTRY not set (deployed IdentityRegistry address).";
            return false;
        }

        var chainIdRaw = Environment.GetEnvironmentVariable("TESSERA_EVM_CHAINID");
        if (string.IsNullOrWhiteSpace(chainIdRaw) || !long.TryParse(chainIdRaw.Trim(), out var chainId) || chainId <= 0)
        {
            missingReason = "TESSERA_EVM_CHAINID not set or not a positive integer (e.g. 97).";
            return false;
        }

        var legacyRaw = Environment.GetEnvironmentVariable("TESSERA_EVM_LEGACY_GAS");
        var legacy = legacyRaw is null
            ? chainId is 56 or 97   // BNB Chain mainnet/testnet reject zero-tip 1559 txs
            : legacyRaw.Trim() is "1" or "true" or "TRUE" or "True";

        config = new EvmTestnetConfig
        {
            RpcUrl = rpc.Trim(),
            PrivateKey = key.Trim(),
            ContractAddress = registry.Trim(),
            ChainId = chainId,
            UseLegacyGas = legacy,
        };
        missingReason = "";
        return true;
    }
}
