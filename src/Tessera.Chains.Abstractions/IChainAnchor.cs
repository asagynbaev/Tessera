namespace Tessera.Chains;

using Tessera.Core;

/// <summary>
/// Minimal contract a chain backend must implement to anchor identity state.
/// Deliberately narrow: roots, revocation, and reads. No proof verification,
/// no balances, no chain-specific primitives leak through this interface.
/// </summary>
public interface IChainAnchor
{
    /// <summary>Identifies the chain this anchor speaks to ("solana", "stellar", ...).</summary>
    string ChainId { get; }

    /// <summary>
    /// Write or update the Merkle attestation root for a DID. The DID controller signs;
    /// implementations are responsible for translating that signature into a chain-native tx.
    /// </summary>
    Task<AnchorTxResult> AnchorRootAsync(DidId did, byte[] attestationRoot, CancellationToken ct = default);

    /// <summary>Read the current anchor record for a DID, or null if none exists.</summary>
    Task<AnchorState?> GetAnchorAsync(DidId did, CancellationToken ct = default);

    /// <summary>Bump the revocation epoch for a DID, signaling that prior presentations are stale.</summary>
    Task<AnchorTxResult> BumpRevocationAsync(DidId did, RevocationReason reason, CancellationToken ct = default);

    /// <summary>
    /// Verify that the anchor was current at <paramref name="asOfEpoch"/>. Used by verifiers
    /// to check that a presentation's <c>AsOfRevocationEpoch</c> has not been superseded.
    /// </summary>
    Task<bool> IsRevokedSinceAsync(DidId did, ulong asOfEpoch, CancellationToken ct = default);
}

public sealed record AnchorTxResult(string TxId, ulong? Slot, DateTimeOffset SubmittedAt);

public sealed record AnchorState
{
    public required DidId Did { get; init; }
    public required byte[] AttestationRoot { get; init; }
    public required ulong RevocationEpoch { get; init; }
    public required DateTimeOffset UpdatedAt { get; init; }

    /// <summary>
    /// The chain-native identifier of the account that owns/controls this anchor
    /// (EVM checksummed address, Solana base58 pubkey, Cardano controller key hash,
    /// Stellar account id), or <c>null</c> when the backend does not surface it.
    /// <para>
    /// Verifiers MUST compare this against the DID's expected controller to detect
    /// anchor substitution / squatting: a chain like Solana or Cardano can hold a
    /// second anchor for the same <c>did_hash</c> written by an attacker key, and the
    /// only off-chain defense is checking that the owner matches the real controller.
    /// </para>
    /// </summary>
    public string? Owner { get; init; }
}

public enum RevocationReason
{
    Unspecified = 0,
    HolderRequested = 1,
    KeyRotation = 2,
    IssuerRevoked = 3,
    Compromise = 4,
}
