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
}
