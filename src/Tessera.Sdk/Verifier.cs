using Tessera.Attestations;
using Tessera.Core;

namespace Tessera.Sdk;

/// <summary>
/// High-level verifier facade. Composes:
/// <list type="bullet">
///   <item><see cref="AttestationVerifier"/> — issuer signature + expiry + active status checks</item>
///   <item><see cref="PresentationVerifier"/> — Merkle inclusion + subject binding</item>
///   <item>Policy layer — verifier-DID match, session nonce match, revocation freshness</item>
/// </list>
/// </summary>
public sealed class Verifier
{
    private readonly VerifierOptions _options;
    private readonly AttestationVerifier _attVerifier;
    private readonly PresentationVerifier _presVerifier;

    public Verifier(VerifierOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _attVerifier = new AttestationVerifier(options.IssuerRegistry, options.SignatureVerifier);
        _presVerifier = new PresentationVerifier(_attVerifier);
    }

    /// <summary>
    /// Verify a single attestation envelope without presentation context (issuer signature,
    /// expiry, issuer-registry status). Use this for sanity-checking attestations before storing them.
    /// </summary>
    public Task<VerificationResult> VerifyAttestationAsync(Attestation attestation, CancellationToken ct = default)
        => _attVerifier.VerifyAsync(attestation, ct);

    /// <summary>
    /// Verify a presentation against an <see cref="VerificationPolicy"/>. Returns
    /// <see cref="VerificationResult.Valid"/> = true only when every layer passes.
    /// </summary>
    /// <remarks>
    /// Failure reasons added by this facade on top of <see cref="PresentationVerifier"/>'s set:
    /// <list type="bullet">
    ///   <item><c>verifier_mismatch</c> — presentation bound to a different verifier DID</item>
    ///   <item><c>session_nonce_mismatch</c> — replay or wrong session</item>
    ///   <item><c>no_anchored_root</c> — chain reports no anchor for the holder</item>
    ///   <item><c>revocation_stale</c> — chain epoch has moved past the presentation's <c>AsOfRevocationEpoch</c></item>
    /// </list>
    /// </remarks>
    public async Task<VerificationResult> VerifyPresentationAsync(
        Presentation presentation,
        VerificationPolicy policy,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(policy);

        // 1. Binding fields the cryptographic verifier doesn't check
        if (presentation.Binding.Verifier != policy.ExpectedVerifier)
            return new VerificationResult { Valid = false, Reason = "verifier_mismatch" };

        if (policy.ExpectedSessionNonce is { } expectedNonce
            && !presentation.Binding.SessionNonce.AsSpan().SequenceEqual(expectedNonce))
            return new VerificationResult { Valid = false, Reason = "session_nonce_mismatch" };

        // 2. Determine the expected anchor root
        byte[]? expectedRoot;
        if (policy.ExpectedAnchorRoot is { } caller)
        {
            expectedRoot = caller;
        }
        else if (_options.ChainAnchor is { } chain)
        {
            var state = await chain.GetAnchorAsync(presentation.Holder, ct).ConfigureAwait(false);
            if (state is null)
                return new VerificationResult { Valid = false, Reason = "no_anchored_root" };
            expectedRoot = state.AttestationRoot;

            // 3. Revocation freshness — if the policy demands the presentation is anchored
            // to the CURRENT epoch (not a stale one) and the chain has bumped past it.
            if (policy.RequireCurrentRevocationEpoch
                && state.RevocationEpoch > presentation.Binding.AsOfRevocationEpoch)
                return new VerificationResult { Valid = false, Reason = "revocation_stale" };
        }
        else
        {
            throw new InvalidOperationException(
                "No anchor root available: either supply policy.ExpectedAnchorRoot or configure VerifierOptions.ChainAnchor.");
        }

        // 4. Cryptographic + Merkle verification
        var cryptoResult = await _presVerifier.VerifyAsync(presentation, expectedRoot, ct).ConfigureAwait(false);
        if (!cryptoResult.Valid) return cryptoResult;

        // 5. Declarative rules: required attestation types + predicate requirements.
        //    Evaluated last, only on an otherwise-valid presentation.
        return PolicyEvaluation.EvaluateDeclarativeRules(presentation, policy);
    }
}

/// <summary>
/// Caller-supplied expectations for <see cref="Verifier.VerifyPresentationAsync"/>.
/// </summary>
public sealed record VerificationPolicy
{
    /// <summary>The DID of the verifier service expecting the presentation. Required.</summary>
    public required DidId ExpectedVerifier { get; init; }

    /// <summary>
    /// Session nonce the verifier issued to the holder. When set, the verifier rejects any
    /// presentation whose binding nonce doesn't match — prevents cross-session replay.
    /// </summary>
    public byte[]? ExpectedSessionNonce { get; init; }

    /// <summary>
    /// Pre-fetched anchor root. When set, the verifier compares the presentation against
    /// this root instead of querying the chain. Useful for cached or offline verification.
    /// </summary>
    public byte[]? ExpectedAnchorRoot { get; init; }

    /// <summary>
    /// When true and a chain anchor is configured, fail with <c>revocation_stale</c> if the
    /// chain's revocation epoch has advanced past <c>AsOfRevocationEpoch</c> in the presentation.
    /// </summary>
    public bool RequireCurrentRevocationEpoch { get; init; }

    /// <summary>
    /// Attestation types the presentation must disclose. Every listed type must appear among the
    /// disclosed attestations or verification fails with <c>missing_required_type:{type}</c>.
    /// Empty (default) = no type requirement. Declarative — no business logic baked in.
    /// </summary>
    public IReadOnlyList<string> RequiredTypes { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Predicate (range-proof) requirements the presentation must satisfy, e.g. "income ≥ threshold".
    /// Each must be met by a valid disclosed <see cref="CredentialProof"/> bundle or verification fails
    /// with <c>predicate_unsatisfied:{label}</c>. Empty (default) = no predicate requirement.
    /// See <see cref="PredicateRequirement"/> for the soundness caveat.
    /// </summary>
    public IReadOnlyList<PredicateRequirement> PredicateRequirements { get; init; } = Array.Empty<PredicateRequirement>();

    /// <summary>
    /// Claim-value requirements on disclosed (issuer-signed) attestations, e.g. "the jurisdiction
    /// attestation's <c>country</c> claim is one of {KZ}". Each must be met or verification fails
    /// with <c>claim_unsatisfied:{type}.{key}</c>. Empty (default) = no claim requirement.
    /// Claims are part of the signed canonical attestation, so they cannot be tampered post-issue.
    /// </summary>
    public IReadOnlyList<RequiredClaim> RequiredClaims { get; init; } = Array.Empty<RequiredClaim>();
}
