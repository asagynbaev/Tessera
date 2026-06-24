using System.Numerics;

namespace Tessera.Chains.Evm;

/// <summary>
/// Composition-root configuration for <see cref="EvmChainAnchor"/>. The anchor is
/// network-agnostic: <see cref="ChainId"/> and <see cref="RpcUrl"/> are the only things
/// that change between EVM networks (the reference scenario uses BNB Chain).
/// </summary>
public sealed record EvmChainAnchorOptions
{
    /// <summary>JSON-RPC endpoint of the target EVM network.</summary>
    public required string RpcUrl { get; init; }

    /// <summary>EIP-155 chain id (e.g. 56 = BNB mainnet, 97 = BNB testnet). Used for replay protection.</summary>
    public required long ChainId { get; init; }

    /// <summary>Deployed <c>IdentityRegistry</c> contract address (0x-hex).</summary>
    public required string ContractAddress { get; init; }

    /// <summary>
    /// Private key (0x-hex, with or without prefix) of the account that signs writes.
    /// This account becomes the <c>owner</c> of any DID anchor it registers and must sign
    /// every subsequent update/revocation for that DID — parity with the Solana owner model.
    /// </summary>
    public required string PrivateKey { get; init; }

    /// <summary>
    /// Logical chain identifier surfaced as <see cref="EvmChainAnchor.ChainId"/> and bound
    /// into presentations. Defaults to <c>"evm:{ChainId}"</c>. Override to align with whatever
    /// chain tag your presentations use.
    /// </summary>
    public string? ChainTag { get; init; }

    /// <summary>Optional fixed gas limit for write transactions. Null = let the node estimate.</summary>
    public BigInteger? GasLimit { get; init; }

    /// <summary>
    /// Send legacy (type-0) transactions priced via <c>eth_gasPrice</c> instead of EIP-1559.
    /// Some chains — notably BNB Chain (testnet and mainnet) — reject 1559 transactions whose
    /// priority fee is zero ("gas tip cap 0, minimum needed 1"), which is what Nethereum's
    /// auto-fee path produces there; enable this to anchor on those chains. Default false (1559).
    /// </summary>
    public bool UseLegacyGasPricing { get; init; }

    /// <summary>Retry policy for transient RPC failures. Defaults to 3 attempts with backoff.</summary>
    public EvmRetryPolicy Retry { get; init; } = EvmRetryPolicy.Default;

    /// <summary>Resolved chain tag (never null).</summary>
    public string EffectiveChainTag => ChainTag ?? $"evm:{ChainId}";
}

/// <summary>Best-effort retry policy for transient JSON-RPC / network failures.</summary>
public sealed record EvmRetryPolicy
{
    /// <summary>Total attempts including the first. 1 = no retry.</summary>
    public int MaxAttempts { get; init; } = 3;

    /// <summary>Base delay; attempt N waits <c>BaseDelay * 2^(N-1)</c>.</summary>
    public TimeSpan BaseDelay { get; init; } = TimeSpan.FromMilliseconds(500);

    public static EvmRetryPolicy Default { get; } = new();
    public static EvmRetryPolicy None { get; } = new() { MaxAttempts = 1 };
}
