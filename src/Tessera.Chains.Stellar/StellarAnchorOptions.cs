namespace Tessera.Chains.Stellar;

/// <summary>
/// Composition-root configuration for <see cref="StellarChainAnchor"/>. The adapter talks to
/// a deployed <c>attestation-anchor</c> Soroban contract over Soroban RPC. Like the Solana and
/// EVM adapters it is network-agnostic: only the RPC endpoint, the network passphrase, and the
/// contract id change between Stellar networks (the reference scenario uses testnet).
/// </summary>
public sealed record StellarAnchorOptions
{
    /// <summary>Soroban RPC endpoint (e.g. <c>https://soroban-testnet.stellar.org</c>).</summary>
    public required string SorobanRpcUrl { get; init; }

    /// <summary>Deployed <c>attestation-anchor</c> contract id (<c>C...</c>).</summary>
    public required string ContractId { get; init; }

    /// <summary>
    /// Secret seed (<c>S...</c>) of the account that signs writes and pays fees. This account
    /// becomes the <c>owner</c> of any DID anchor it registers and must sign every subsequent
    /// update/revocation for that DID — parity with the Solana/EVM owner model. Because the
    /// owner equals the transaction source account, Soroban source-account authorization covers
    /// the contract's <c>require_auth</c> with no separate signature. Never logged.
    /// </summary>
    public required string SigningKeySeed { get; init; }

    /// <summary>
    /// Network passphrase used when signing. Defaults to the public testnet passphrase
    /// (<c>"Test SDF Network ; September 2015"</c>). Use
    /// <c>"Public Global Stellar Network ; September 2015"</c> for mainnet.
    /// </summary>
    public string NetworkPassphrase { get; init; } = "Test SDF Network ; September 2015";

    /// <summary>How long to await on-chain confirmation of a submitted write. Default 2 minutes.</summary>
    public TimeSpan ConfirmationTimeout { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>Poll interval while awaiting confirmation. Default 3 seconds.</summary>
    public TimeSpan ConfirmationPollInterval { get; init; } = TimeSpan.FromSeconds(3);

    /// <summary>
    /// Extra stroops added to the simulated minimum resource fee as headroom against
    /// ledger-state fee drift between simulation and submission. Default 100,000 (0.01 XLM).
    /// </summary>
    public uint ResourceFeeBuffer { get; init; } = 100_000;
}
