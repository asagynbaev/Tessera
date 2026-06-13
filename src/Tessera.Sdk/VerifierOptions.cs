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
    /// Clock used for presentation freshness checks (and attestation expiry). Defaults to
    /// <see cref="TimeProvider.System"/>. Inject a fake provider in tests.
    /// </summary>
    public TimeProvider? Clock { get; init; }
}
