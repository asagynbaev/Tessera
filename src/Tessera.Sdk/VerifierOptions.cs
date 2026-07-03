using Tessera.Attestations;
using Tessera.Chains;

namespace Tessera.Sdk;

/// <summary>
/// Composition-root configuration for <see cref="Verifier"/>.
/// </summary>
public sealed record VerifierOptions
{
    public required IIssuerRegistry IssuerRegistry { get; init; }
    public required ISignatureVerifier SignatureVerifier { get; init; }

    /// <summary>
    /// Optional on-chain anchor. When supplied, the verifier reads the holder's anchored root
    /// from chain instead of trusting a caller-supplied root, and can check revocation freshness.
    /// </summary>
    public IChainAnchor? ChainAnchor { get; init; }

    /// <summary>
    /// Clock used for presentation freshness checks (and attestation expiry), and for time-based
    /// policy checks such as <see cref="VerificationPolicy.SnapshotFreshness"/>. Defaults to
    /// <see cref="TimeProvider.System"/>. Inject a fake provider in tests.
    /// </summary>
    public TimeProvider? Clock { get; init; }

    /// <summary>
    /// When set, an attestation is rejected (<c>too_old</c>) once <c>now − IssuedAt</c> exceeds this,
    /// capping the lifetime of credentials whose issuer set no <c>ExpiresAt</c>. Null = no age cap.
    /// </summary>
    public TimeSpan? MaxAttestationAge { get; init; }

    /// <summary>
    /// When true, an attestation lacking an <c>ExpiresAt</c> is rejected (<c>missing_expiry</c>), so a
    /// sensitive credential cannot be valid forever. Default false (backward-compatible).
    /// </summary>
    public bool RequireExpiry { get; init; }

    /// <summary>
    /// Optional single-use nonce store for presentation anti-replay. When supplied,
    /// <see cref="Verifier.VerifyPresentationAsync"/> atomically consumes each presentation's
    /// (holder DID, session nonce) pair after the holder signature is verified — mirroring how
    /// wallet binding consumes its nonce — so a captured presentation cannot be replayed within its
    /// freshness window (rejected as <c>presentation_replayed</c>). Null (default) = no single-use
    /// enforcement; replay is then bounded only by <see cref="VerificationPolicy.MaxPresentationAge"/>.
    /// Only presentations carrying a non-empty session nonce are consumed.
    /// </summary>
    public Tessera.Did.INonceStore? NonceStore { get; init; }

    /// <summary>
    /// Optional DID store for defense-in-depth revocation. When supplied,
    /// <see cref="Verifier.VerifyPresentationAsync"/> rejects a presentation whose holder DID
    /// (<c>holder_did_revoked</c>) — or any disclosed attestation's issuer DID
    /// (<c>issuer_did_revoked</c>) — is present in the store and marked revoked, independently of the
    /// on-chain revocation epoch and the issuer registry. An absent DID is not treated as revoked.
    /// Null (default) = DID-level revocation is not consulted.
    /// </summary>
    public Tessera.Did.IDidStore? DidStore { get; init; }
}
