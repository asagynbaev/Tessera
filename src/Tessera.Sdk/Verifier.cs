using Tessera.Attestations;
using Tessera.Chains;
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

    private readonly TimeProvider _clock;

    public Verifier(VerifierOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _clock = options.Clock ?? TimeProvider.System;
        _attVerifier = new AttestationVerifier(options.IssuerRegistry, options.SignatureVerifier, options.Clock);
        _presVerifier = new PresentationVerifier(_attVerifier, options.SignatureVerifier);
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

        var binding = presentation.Binding;

        // 1. Audience binding. This plaintext compare is a fast reject; it is BACKED by the holder
        //    signature (the verifier DID is part of the signed challenge), checked in step 6, so it
        //    cannot be forged by a third party.
        if (binding.Verifier != policy.ExpectedVerifier)
            return new VerificationResult { Valid = false, Reason = "verifier_mismatch" };

        // 2. Session nonce (when the verifier issued one). Authenticated via the holder signature.
        if (policy.ExpectedSessionNonce is { } expectedNonce
            && !binding.SessionNonce.AsSpan().SequenceEqual(expectedNonce))
            return new VerificationResult { Valid = false, Reason = "session_nonce_mismatch" };

        // 3. Freshness window — always enforced so a captured presentation cannot be replayed
        //    indefinitely. CreatedAt is part of the signed challenge, so it is holder-authenticated.
        var now = _clock.GetUtcNow();
        if (now - binding.CreatedAt > policy.MaxPresentationAge)
            return new VerificationResult { Valid = false, Reason = "presentation_expired" };
        if (binding.CreatedAt - now > policy.MaxClockSkew)
            return new VerificationResult { Valid = false, Reason = "presentation_future_dated" };

        // 4. Resolve the anchor state (once) and the expected Merkle root.
        AnchorState? state = null;
        if (_options.ChainAnchor is { } anchor)
            state = await anchor.GetAnchorAsync(presentation.Holder, ct).ConfigureAwait(false);

        byte[] expectedRoot;
        if (policy.ExpectedAnchorRoot is { } caller)
            expectedRoot = caller;
        else if (state is not null)
            expectedRoot = state.AttestationRoot;
        else if (_options.ChainAnchor is null)
            throw new InvalidOperationException(
                "No anchor root available: either supply policy.ExpectedAnchorRoot or configure VerifierOptions.ChainAnchor.");
        else
            return new VerificationResult { Valid = false, Reason = "no_anchored_root" };

        // 5. Revocation freshness.
        //    (a) Whenever a chain anchor is reachable, a presentation bound to an epoch OLDER than the
        //        chain's current epoch is stale — rejected unconditionally (closes the opt-in gap).
        //    (b) RequireCurrentRevocationEpoch additionally FAILS CLOSED: it demands chain access and
        //        an EXACT match to the current epoch, so a holder cannot defeat the check by inflating
        //        AsOfRevocationEpoch (it must equal the chain, not merely be "not less than" it).
        if (state is not null && binding.AsOfRevocationEpoch < state.RevocationEpoch)
            return new VerificationResult { Valid = false, Reason = "revocation_stale" };

        if (policy.RequireCurrentRevocationEpoch)
        {
            if (_options.ChainAnchor is null)
                throw new InvalidOperationException(
                    "policy.RequireCurrentRevocationEpoch requires VerifierOptions.ChainAnchor; revocation freshness " +
                    "cannot be verified against a caller-supplied ExpectedAnchorRoot alone.");
            if (state is null)
                return new VerificationResult { Valid = false, Reason = "no_anchored_root" };
            if (binding.AsOfRevocationEpoch != state.RevocationEpoch)
                return new VerificationResult { Valid = false, Reason = "revocation_stale" };
        }

        // 6. Cryptographic verification: holder-binding signature + issuer signatures + Merkle inclusion.
        var cryptoResult = await _presVerifier.VerifyAsync(presentation, expectedRoot, ct).ConfigureAwait(false);
        if (!cryptoResult.Valid) return cryptoResult;

        // 7. Declarative rules: required types + predicate requirements + snapshot freshness.
        //    Evaluated last, only on an otherwise-valid presentation. Reuses the step-3 `now`.
        return PolicyEvaluation.EvaluateDeclarativeRules(presentation, policy, now);
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
    /// When true, revocation freshness FAILS CLOSED: a chain anchor must be configured and reachable,
    /// and the presentation's <c>AsOfRevocationEpoch</c> must EQUAL the chain's current revocation
    /// epoch (not merely be "not less than" it) — otherwise verification fails with
    /// <c>revocation_stale</c> (or throws if no chain anchor is configured). Independently of this
    /// flag, when a chain anchor is configured the verifier always rejects a presentation bound to an
    /// epoch older than the chain's current epoch.
    /// </summary>
    public bool RequireCurrentRevocationEpoch { get; init; }

    /// <summary>
    /// Maximum age of a presentation (now − <c>CreatedAt</c>) before it is rejected as
    /// <c>presentation_expired</c>. Always enforced; <c>CreatedAt</c> is part of the holder-signed
    /// challenge, so it cannot be back-dated by a third party. Default: 5 minutes.
    /// </summary>
    public TimeSpan MaxPresentationAge { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Allowed clock skew for a future-dated <c>CreatedAt</c> before rejection as
    /// <c>presentation_future_dated</c>. Default: 1 minute.
    /// </summary>
    public TimeSpan MaxClockSkew { get; init; } = TimeSpan.FromMinutes(1);

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

    /// <summary>
    /// Opt-in freshness requirement on the point-in-time <see cref="ChainSnapshot"/> carried by
    /// disclosed attestations (e.g. a Bitcoin balance must be observed within the last N blocks or
    /// the last N days). Null (default) = no snapshot check. Fails with <c>snapshot_stale:{type}</c>.
    /// </summary>
    public SnapshotFreshnessRequirement? SnapshotFreshness { get; init; }
}
