namespace Tessera.Chains.Midnight;

/// <summary>
/// Configuration for <see cref="MidnightChainAnchor"/>. Carries the endpoints and contract handle a
/// future Compact-based anchor will need. The adapter is a scaffold today — see the package README.
/// </summary>
public sealed record MidnightAnchorOptions
{
    /// <summary>Midnight network this adapter targets.</summary>
    public MidnightNetwork Network { get; init; } = MidnightNetwork.Testnet;

    /// <summary>Midnight node RPC endpoint. Used once the transaction layer is wired.</summary>
    public string? NodeUrl { get; init; }

    /// <summary>Indexer / pub-sub endpoint used to read contract state.</summary>
    public string? IndexerUrl { get; init; }

    /// <summary>Deployed anchor (Compact) contract address. Null until a contract is deployed.</summary>
    public string? ContractAddress { get; init; }
}

/// <summary>Midnight network the adapter talks to.</summary>
public enum MidnightNetwork
{
    /// <summary>The Midnight test network.</summary>
    Testnet = 0,

    /// <summary>Midnight mainnet (live).</summary>
    Mainnet = 1,
}
