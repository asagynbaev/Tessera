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
        _attVerifier = new AttestationVerifier(
            options.IssuerRegistry, options.SignatureVerifier, options.Clock,
            options.MaxAttestationAge, options.RequireExpiry);
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
    ///   <item><c>anchor_owner_mismatch</c> — the anchor's on-chain owner ≠ the pinned <c>ExpectedAnchorOwner</c> (substitution / squatting)</item>
    ///   <item><c>anchor_owner_unverifiable</c> — <c>ExpectedAnchorOwner</c> set but the owner could not be observed (no live anchor / backend does not surface it); fail-closed</item>
    ///   <item><c>revocation_stale</c> — chain (or caller-supplied <c>ExpectedRevocationEpoch</c>) has moved past the presentation's <c>AsOfRevocationEpoch</c></item>
    ///   <item><c>revocation_unverifiable</c> — offline verification with neither a live anchor nor a trusted <c>ExpectedRevocationEpoch</c>; revocation could not be checked (fail-closed)</item>
    ///   <item><c>holder_did_revoked</c> / <c>issuer_did_revoked</c> — DID marked revoked in the configured <see cref="VerifierOptions.DidStore"/></item>
    ///   <item><c>presentation_replayed</c> — the (holder, session nonce) pair was already consumed by the configured <see cref="VerifierOptions.NonceStore"/></item>
    ///   <item><c>session_nonce_required</c> — a <see cref="VerifierOptions.NonceStore"/> is configured but the presentation carried an empty session nonce (which cannot be made single-use); fail-closed</item>
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
        {
            // A caller-supplied (cached/offline) root is honoured, but when a live anchor is ALSO
            // reachable it must match it. A root rotation that removed an attestation does NOT bump
            // the revocation epoch, so a stale cached root would otherwise still verify a presentation
            // of a since-removed attestation (use-after-removal / TOCTOU).
            if (state is not null && !caller.AsSpan().SequenceEqual(state.AttestationRoot))
                return new VerificationResult { Valid = false, Reason = "anchor_root_stale" };
            expectedRoot = caller;
        }
        else if (state is not null)
            expectedRoot = state.AttestationRoot;
        else if (_options.ChainAnchor is null)
            throw new InvalidOperationException(
                "No anchor root available: either supply policy.ExpectedAnchorRoot or configure VerifierOptions.ChainAnchor.");
        else
            return new VerificationResult { Valid = false, Reason = "no_anchored_root" };

        // 4a. Anchor ownership (opt-in): the off-chain defense against anchor substitution / squatting.
        var ownership = CheckAnchorOwnership(state, policy);
        if (ownership is not null) return ownership;

        // 5. Revocation freshness.
        var revocation = CheckRevocationFreshness(binding, state, policy);
        if (revocation is not null) return revocation;

        // 6. Cryptographic verification: holder-binding signature + issuer signatures + Merkle inclusion.
        var cryptoResult = await _presVerifier.VerifyAsync(presentation, expectedRoot, ct).ConfigureAwait(false);
        if (!cryptoResult.Valid) return cryptoResult;

        // 6a. DID-level revocation (opt-in): fail closed if the holder or any issuer DID is revoked in
        //     the configured store. Runs after crypto so only authenticated presentations trigger reads.
        var didRevocation = await CheckDidRevocationAsync(presentation, ct).ConfigureAwait(false);
        if (didRevocation is not null) return didRevocation;

        // 6b. Single-use presentation nonce (opt-in): consume the (holder, session nonce) pair so a
        //     replayed presentation is rejected. Only consumed once the holder signature is proven above.
        var replay = await ConsumePresentationNonceAsync(presentation, policy, ct).ConfigureAwait(false);
        if (replay is not null) return replay;

        // 7. Declarative rules: required types + predicate requirements + snapshot freshness.
        //    Evaluated last, only on an otherwise-valid presentation. Reuses the step-3 `now`.
        return PolicyEvaluation.EvaluateDeclarativeRules(presentation, policy, now);
    }

    /// <summary>
    /// Revocation-freshness gate. With a live anchor the chain epoch is authoritative (unchanged
    /// behaviour). Without one (offline / cached-root verification) the chain epoch is unknown, so
    /// freshness rests on a caller-supplied trusted <see cref="VerificationPolicy.ExpectedRevocationEpoch"/>;
    /// with neither, we FAIL CLOSED (<c>revocation_unverifiable</c>) rather than silently accept a
    /// possibly-revoked credential. Returns a failing result, or <c>null</c> when the check passes.
    /// </summary>
    /// <summary>
    /// Enforces <see cref="VerificationPolicy.ExpectedAnchorOwner"/>: the resolved anchor's on-chain
    /// owner must equal the caller-pinned controller. Off-chain defense against anchor substitution /
    /// squatting on chains without globally-unique anchor keys (Solana, Cardano). Fails closed when the
    /// owner cannot be observed. No expected owner set → skipped. Returns a failing result, or
    /// <c>null</c> when the check passes.
    /// </summary>
    private static VerificationResult? CheckAnchorOwnership(AnchorState? state, VerificationPolicy policy)
    {
        if (policy.ExpectedAnchorOwner is not { } expectedOwner)
            return null;
        if (state?.Owner is not { } actualOwner)
            return new VerificationResult { Valid = false, Reason = "anchor_owner_unverifiable" };
        if (!string.Equals(actualOwner, expectedOwner, StringComparison.Ordinal))
            return new VerificationResult { Valid = false, Reason = "anchor_owner_mismatch" };
        return null;
    }

    private VerificationResult? CheckRevocationFreshness(PresentationBinding binding, AnchorState? state, VerificationPolicy policy)
    {
        // (a) Live anchor reachable: a presentation bound to an epoch OLDER than the chain's current
        //     epoch is stale — rejected unconditionally (closes the opt-in gap).
        if (state is not null && binding.AsOfRevocationEpoch < state.RevocationEpoch)
            return new VerificationResult { Valid = false, Reason = "revocation_stale" };

        // (b) No live anchor state (offline / cached-root): revocation freshness rests on a trusted
        //     caller-supplied epoch. Skipped when RequireCurrentRevocationEpoch is set — (c) handles
        //     that stricter, chain-only path below (throw / no_anchored_root).
        if (state is null && !policy.RequireCurrentRevocationEpoch)
        {
            if (policy.ExpectedRevocationEpoch is { } expectedEpoch)
            {
                if (binding.AsOfRevocationEpoch < expectedEpoch)
                    return new VerificationResult { Valid = false, Reason = "revocation_stale" };
            }
            else
            {
                // Neither a live anchor nor a trusted epoch: do NOT silently pass revocation.
                return new VerificationResult { Valid = false, Reason = "revocation_unverifiable" };
            }
        }

        // (c) RequireCurrentRevocationEpoch FAILS CLOSED: it demands chain access and an EXACT match to
        //     the current epoch, so a holder cannot defeat the check by inflating AsOfRevocationEpoch
        //     (it must equal the chain, not merely be "not less than" it).
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

        return null;
    }

    /// <summary>
    /// Defense-in-depth DID revocation: when a <see cref="VerifierOptions.DidStore"/> is configured,
    /// reject if the holder DID or any disclosed issuer DID is present-and-revoked in the store. An
    /// absent DID is not treated as revoked (the store simply has no opinion). Returns a failing result,
    /// or <c>null</c> when the check passes / no store is configured.
    /// </summary>
    private async Task<VerificationResult?> CheckDidRevocationAsync(Presentation presentation, CancellationToken ct)
    {
        if (_options.DidStore is not { } didStore) return null;

        var holderDoc = await didStore.GetAsync(presentation.Holder, ct).ConfigureAwait(false);
        if (holderDoc is { Revoked: true })
            return new VerificationResult { Valid = false, Reason = "holder_did_revoked" };

        foreach (var issuer in presentation.Disclosures.Select(d => d.Attestation.Issuer).Distinct())
        {
            var issuerDoc = await didStore.GetAsync(issuer, ct).ConfigureAwait(false);
            if (issuerDoc is { Revoked: true })
                return new VerificationResult { Valid = false, Reason = "issuer_did_revoked" };
        }

        return null;
    }

    /// <summary>
    /// Single-use presentation-nonce consumption: when a <see cref="VerifierOptions.NonceStore"/> is
    /// configured, atomically consume the (holder, nonce) pair; a replay of the same pair is rejected
    /// as <c>presentation_replayed</c>. A configured store implies the verifier wants replay protection,
    /// so a presentation carrying an EMPTY session nonce (which cannot be consumed, and would otherwise
    /// replay freely within the freshness window) is rejected as <c>session_nonce_required</c> — enabling
    /// the store is by itself sufficient replay protection, without also having to pin
    /// <see cref="VerificationPolicy.ExpectedSessionNonce"/>. Returns a failing result, or <c>null</c>
    /// when fresh / no store configured.
    /// </summary>
    private async Task<VerificationResult?> ConsumePresentationNonceAsync(Presentation presentation, VerificationPolicy policy, CancellationToken ct)
    {
        var binding = presentation.Binding;
        if (_options.NonceStore is not { } nonceStore)
            return null;

        // A store means "prevent replay". An empty nonce cannot be consumed, so a captured presentation
        // would replay freely within the freshness window — fail closed instead of silently skipping.
        if (binding.SessionNonce.Length == 0)
            return new VerificationResult { Valid = false, Reason = "session_nonce_required" };

        // The nonce can no longer be presented once the freshness window (plus allowed skew) closes,
        // so the store may evict the entry after that point.
        var nonceExpiry = binding.CreatedAt + policy.MaxPresentationAge + policy.MaxClockSkew;
        var fresh = await nonceStore
            .TryConsumeAsync(presentation.Holder, binding.SessionNonce, nonceExpiry, ct)
            .ConfigureAwait(false);
        return fresh ? null : new VerificationResult { Valid = false, Reason = "presentation_replayed" };
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
    /// Supplying a root alone does NOT verify revocation — pair it with
    /// <see cref="ExpectedRevocationEpoch"/> so offline verification still gates on revocation.
    /// </summary>
    public byte[]? ExpectedAnchorRoot { get; init; }

    /// <summary>
    /// The chain-native identifier of the account that legitimately controls this DID's anchor
    /// (the DID controller's on-chain key), in the exact format the adapter emits in
    /// <see cref="AnchorState.Owner"/>: EIP-55 checksummed <c>0x…</c> for EVM, base58 pubkey for
    /// Solana, lowercase controller-key hex for Cardano, <c>G…</c> account id for Stellar.
    /// <para>
    /// When set, the verifier requires the resolved anchor's owner to equal this value — the
    /// off-chain defense against anchor substitution / squatting. A chain such as Solana or Cardano
    /// can hold a second anchor for the same <c>did_hash</c> written by an attacker key; only the
    /// owner distinguishes the real anchor from the impostor. Fails closed as
    /// <c>anchor_owner_mismatch</c> on a mismatch, or <c>anchor_owner_unverifiable</c> when the
    /// owner cannot be observed (no live anchor, or the backend does not surface it). Null (default)
    /// skips the check — do NOT leave it null when anchoring on a chain without globally-unique
    /// anchor keys. Comparison is case-sensitive (base58/base32 keys are case-significant).
    /// </para>
    /// </summary>
    public string? ExpectedAnchorOwner { get; init; }

    /// <summary>
    /// Trusted current revocation epoch for OFFLINE / cached-root verification (when no live
    /// <see cref="VerifierOptions.ChainAnchor"/> resolves anchor state). When set, a presentation whose
    /// <c>AsOfRevocationEpoch</c> is below this value is rejected as <c>revocation_stale</c>. When a live
    /// anchor IS reachable this is ignored — the chain's epoch is authoritative. When operating offline
    /// and this is <c>null</c>, revocation cannot be verified and the presentation is rejected as
    /// <c>revocation_unverifiable</c> (the verifier never silently skips revocation). Null (default).
    /// </summary>
    public ulong? ExpectedRevocationEpoch { get; init; }

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
    /// Each must be met by a valid disclosed <see cref="CredentialProof"/> bundle — proven BOUND to the
    /// commitment of a disclosed attestation of the required <see cref="PredicateRequirement.Type"/> —
    /// or verification fails with <c>predicate_unsatisfied:{label}</c>. A requirement whose
    /// <see cref="PredicateRequirement.Type"/> is null FAILS CLOSED. Empty (default) = no predicate
    /// requirement.
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
