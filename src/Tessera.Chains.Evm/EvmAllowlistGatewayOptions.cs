using System.Numerics;

namespace Tessera.Chains.Evm;

/// <summary>How the target restriction contract exposes allow/disallow.</summary>
public enum AllowlistFunctionStyle
{
    /// <summary>Separate <c>add(address)</c> / <c>remove(address)</c> functions (the reference Allowlist contract).</summary>
    AddRemovePair,

    /// <summary>A single <c>set(address, bool)</c> flag function.</summary>
    SetBoolFlag,
}

/// <summary>
/// Configuration for <see cref="EvmAllowlistGateway"/>. The gateway is contract-agnostic: the
/// function names and call style are configuration, so the same code drives the reference
/// <c>Allowlist</c> contract, a custom whitelist, or an ERC-3643/T-REX whitelist module.
/// </summary>
public sealed record EvmAllowlistGatewayOptions
{
    public required string RpcUrl { get; init; }
    public required long ChainId { get; init; }

    /// <summary>Address of the transfer-restriction contract.</summary>
    public required string ContractAddress { get; init; }

    /// <summary>
    /// Private key of the signing account. It must be authorized on the restriction contract
    /// (e.g. an agent / owner) to modify the allowlist.
    /// </summary>
    public required string PrivateKey { get; init; }

    /// <summary>Logical chain tag surfaced as <see cref="IAllowlistGateway.ChainId"/>. Defaults to <c>"evm:{ChainId}"</c>.</summary>
    public string? ChainTag { get; init; }

    public AllowlistFunctionStyle Style { get; init; } = AllowlistFunctionStyle.AddRemovePair;

    /// <summary>Function called to allow an address (AddRemovePair style).</summary>
    public string AddFunctionName { get; init; } = "addToAllowlist";

    /// <summary>Function called to disallow an address (AddRemovePair style).</summary>
    public string RemoveFunctionName { get; init; } = "removeFromAllowlist";

    /// <summary>Function called with <c>(address, bool)</c> to set the flag (SetBoolFlag style).</summary>
    public string SetFunctionName { get; init; } = "setAllowed";

    /// <summary>View function returning whether an address is allowed.</summary>
    public string IsAllowedFunctionName { get; init; } = "isAllowed";

    /// <summary>Optional fixed gas limit for writes. Null = estimate.</summary>
    public BigInteger? GasLimit { get; init; }

    public EvmRetryPolicy Retry { get; init; } = EvmRetryPolicy.Default;

    public string EffectiveChainTag => ChainTag ?? $"evm:{ChainId}";
}
