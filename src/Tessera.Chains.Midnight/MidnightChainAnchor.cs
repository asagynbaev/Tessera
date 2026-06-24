using Tessera.Chains;
using Tessera.Core;

namespace Tessera.Chains.Midnight;

/// <summary>
/// Midnight implementation of <see cref="IChainAnchor"/> — <b>scaffold</b>. The intended design
/// mirrors the other backends: a Compact contract stores <c>(did_hash → root, revocation_epoch)</c>
/// and nothing else, with all proof verification staying off-chain in C#. The Compact contract and
/// the Midnight transaction layer are not wired yet, so:
/// <list type="bullet">
///   <item><see cref="GetAnchorAsync"/> / <see cref="IsRevokedSinceAsync"/> report "no anchor"
///   (null / false) rather than throwing, so a verifier degrades gracefully.</item>
///   <item><see cref="AnchorRootAsync"/> / <see cref="BumpRevocationAsync"/> throw
///   <see cref="NotSupportedException"/> — writes are not implemented, and the adapter does not
///   pretend otherwise.</item>
/// </list>
/// Midnight mainnet is live; this integration is on the roadmap and is the only remaining scaffold
/// (the Solana, EVM, Cardano, and Stellar adapters are complete and testnet-verified). See the
/// package README and <c>docs/architecture.md</c>.
/// </summary>
public sealed class MidnightChainAnchor : IChainAnchor
{
    private const string NotWired =
        "Midnight anchoring is a scaffold: the Compact anchor contract and the transaction layer are " +
        "not implemented yet. Track the roadmap in docs/architecture.md and the package README.";

    private readonly MidnightAnchorOptions _options;

    public MidnightChainAnchor(MidnightAnchorOptions? options = null)
        => _options = options ?? new MidnightAnchorOptions();

    /// <summary>The logical chain tag bound into presentations.</summary>
    public string ChainId => "midnight";

    /// <summary>Not implemented — Midnight writes are pending. Throws <see cref="NotSupportedException"/>.</summary>
    public Task<AnchorTxResult> AnchorRootAsync(DidId did, byte[] attestationRoot, CancellationToken ct = default)
        => throw new NotSupportedException(NotWired);

    /// <summary>Returns null — no anchor contract is deployed yet (scaffold).</summary>
    public Task<AnchorState?> GetAnchorAsync(DidId did, CancellationToken ct = default)
        => Task.FromResult<AnchorState?>(null);

    /// <summary>Not implemented — Midnight writes are pending. Throws <see cref="NotSupportedException"/>.</summary>
    public Task<AnchorTxResult> BumpRevocationAsync(DidId did, RevocationReason reason, CancellationToken ct = default)
        => throw new NotSupportedException(NotWired);

    /// <summary>Returns false — with no anchor deployed, nothing is reported as revoked (scaffold).</summary>
    public Task<bool> IsRevokedSinceAsync(DidId did, ulong asOfEpoch, CancellationToken ct = default)
        => Task.FromResult(false);
}
