using System.Text;
using Tessera.Attestations;

namespace Tessera.Sdk;

/// <summary>
/// A declarative predicate requirement: the presentation must include a valid
/// <see cref="CredentialBundle"/> (range proof) whose <see cref="CredentialBundle.Label"/> matches
/// and whose proven bound satisfies this requirement. Lets a verifier demand e.g. "income ≥ threshold"
/// without learning the value and without any hardwired business logic.
/// </summary>
/// <remarks>
/// <para><b>Soundness caveat (tracked for the crypto audit / A6):</b> the current
/// <see cref="CredentialProof"/> range proof commits to a fresh value not yet cryptographically
/// bound to the attestation's own committed attribute (<see cref="AttestationPayload.Commitment"/>).
/// This requirement therefore verifies that <em>a</em> valid proof of the asserted bound is present;
/// binding that proof to the specific attested value is a planned hardening. Do not rely on predicate
/// requirements alone for high-assurance gating until that binding lands.</para>
/// </remarks>
public sealed record PredicateRequirement
{
    /// <summary>Bundle label this requirement targets (e.g. <c>"income"</c>, <c>"age"</c>).</summary>
    public required string Label { get; init; }

    /// <summary>Whether a minimum (≥ threshold) or range proof is required.</summary>
    public CredentialProofType ProofType { get; init; } = CredentialProofType.Minimum;

    /// <summary>The minimum the proven value must meet (lower bound for range proofs).</summary>
    public long Threshold { get; init; }

    /// <summary>Optional required upper bound (range proofs only).</summary>
    public long? UpperBound { get; init; }
}

/// <summary>
/// An opt-in freshness requirement on the point-in-time <see cref="ChainSnapshot"/> carried by
/// disclosed attestations. A presentation fails when a targeted disclosure's snapshot is older than
/// the allowed age — by wall-clock time, by block count, or both. Default-off: a policy with no
/// <see cref="VerificationPolicy.SnapshotFreshness"/> performs no snapshot check.
/// </summary>
/// <remarks>
/// The snapshot rides in the issuer-signed canonical claims, so it cannot be tampered post-issue.
/// Disclosures that carry no snapshot are skipped — this rule freshness-checks snapshots that are
/// present, it does not mandate their presence (use <see cref="VerificationPolicy.RequiredTypes"/>
/// to mandate a type). The block-age check runs only when <see cref="CurrentBlockHeight"/> is set,
/// since the verifier — not the library — knows the current chain tip.
/// </remarks>
public sealed record SnapshotFreshnessRequirement
{
    /// <summary>
    /// Attestation types to enforce freshness on. Empty (default) = every disclosure that carries a
    /// snapshot.
    /// </summary>
    public IReadOnlyList<string> Types { get; init; } = Array.Empty<string>();

    /// <summary>Maximum allowed wall-clock age (now − snapshot time). Null = no time-based check.</summary>
    public TimeSpan? MaxAge { get; init; }

    /// <summary>
    /// Maximum allowed age in blocks (<see cref="CurrentBlockHeight"/> − snapshot height). Null = no
    /// block-based check. Requires <see cref="CurrentBlockHeight"/> to take effect.
    /// </summary>
    public long? MaxAgeBlocks { get; init; }

    /// <summary>
    /// The verifier's current chain-tip height, supplied at verification time for the block-age check.
    /// Null = the block-age check is skipped (no reference height available).
    /// </summary>
    public long? CurrentBlockHeight { get; init; }
}

/// <summary>
/// A declarative claim-value requirement: a disclosed attestation of <see cref="Type"/> must carry
/// claim <see cref="Key"/>, and (when <see cref="AllowedValues"/> is set) its value must be one of
/// them. Claims are part of the issuer-signed canonical attestation, so this gates on trusted data.
/// </summary>
public sealed record RequiredClaim
{
    /// <summary>Attestation type that must carry the claim (e.g. <c>"jurisdiction"</c>).</summary>
    public required string Type { get; init; }

    /// <summary>Claim key (e.g. <c>"country"</c>).</summary>
    public required string Key { get; init; }

    /// <summary>Allowed values (case-insensitive). Null/empty = presence of the key is sufficient.</summary>
    public IReadOnlyList<string>? AllowedValues { get; init; }
}

/// <summary>
/// Encodes/decodes a <see cref="CredentialBundle"/> to the opaque
/// <see cref="AttestationDisclosure.PredicateProof"/> byte payload. The convention is UTF-8 of the
/// bundle's canonical base64 serialization, so a holder attaches a predicate proof to a disclosure
/// and a verifier policy can recover and check it.
/// </summary>
public static class PredicateProofCodec
{
    public static byte[] Encode(CredentialBundle bundle)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        return Encoding.UTF8.GetBytes(new CredentialProof().Serialize(bundle));
    }

    public static CredentialBundle Decode(ReadOnlySpan<byte> proof)
        => new CredentialProof().Deserialize(Encoding.UTF8.GetString(proof));
}

/// <summary>
/// Evaluates the declarative (non-cryptographic-binding) rules of a <see cref="VerificationPolicy"/>
/// against a presentation: required attestation types and predicate requirements.
/// </summary>
/// <remarks>
/// Internal by design: it must run ONLY after <c>PresentationVerifier</c> has confirmed each
/// disclosed attestation's issuer signature, subject binding, and Merkle inclusion. <see cref="Verifier"/>
/// is the sole caller and enforces that ordering; exposing this publicly would let a caller evaluate
/// rules over unverified (forged) attestations.
/// </remarks>
internal static class PolicyEvaluation
{
    /// <summary>Overload using the system clock for time-based checks (e.g. snapshot freshness).</summary>
    public static VerificationResult EvaluateDeclarativeRules(Presentation presentation, VerificationPolicy policy)
        => EvaluateDeclarativeRules(presentation, policy, DateTimeOffset.UtcNow);

    public static VerificationResult EvaluateDeclarativeRules(Presentation presentation, VerificationPolicy policy, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(policy);

        // Evaluated in order; the first failing rule's reason is returned.
        var failure = CheckRequiredTypes(presentation, policy)
                   ?? CheckRequiredClaims(presentation, policy)
                   ?? CheckPredicates(presentation, policy)
                   ?? CheckSnapshotFreshness(presentation, policy, now);

        return failure is null ? VerificationResult.Ok() : VerificationResult.Fail(failure);
    }

    private static string? CheckSnapshotFreshness(Presentation presentation, VerificationPolicy policy, DateTimeOffset now)
    {
        var req = policy.SnapshotFreshness;
        if (req is null) return null;

        foreach (var disclosure in presentation.Disclosures)
        {
            var type = disclosure.Attestation.Type;
            if (req.Types.Count > 0 && !req.Types.Contains(type, StringComparer.Ordinal))
                continue;

            var snapshot = ChainSnapshot.TryFrom(disclosure.Attestation.Payload);
            if (snapshot is null) continue; // nothing to freshness-check on this disclosure

            if (req.MaxAge is { } maxAge && now - snapshot.TimeUtc > maxAge)
                return $"snapshot_stale:{type}";

            if (req.MaxAgeBlocks is { } maxBlocks && req.CurrentBlockHeight is { } tip
                && tip - snapshot.BlockHeight > maxBlocks)
                return $"snapshot_stale:{type}";
        }
        return null;
    }

    private static string? CheckRequiredTypes(Presentation presentation, VerificationPolicy policy)
    {
        if (policy.RequiredTypes.Count == 0) return null;

        var disclosed = new HashSet<string>(
            presentation.Disclosures.Select(d => d.Attestation.Type), StringComparer.Ordinal);

        foreach (var type in policy.RequiredTypes)
            if (!disclosed.Contains(type))
                return $"missing_required_type:{type}";
        return null;
    }

    private static string? CheckRequiredClaims(Presentation presentation, VerificationPolicy policy)
    {
        foreach (var req in policy.RequiredClaims)
            if (!SatisfiesClaim(presentation, req))
                return $"claim_unsatisfied:{req.Type}.{req.Key}";
        return null;
    }

    private static string? CheckPredicates(Presentation presentation, VerificationPolicy policy)
    {
        if (policy.PredicateRequirements.Count == 0) return null;

        var validBundles = ExtractValidBundles(presentation);
        foreach (var req in policy.PredicateRequirements)
            if (!validBundles.Any(b => Satisfies(b, req)))
                return $"predicate_unsatisfied:{req.Label}";
        return null;
    }

    private static bool SatisfiesClaim(Presentation presentation, RequiredClaim req)
    {
        foreach (var disclosure in presentation.Disclosures)
        {
            if (!string.Equals(disclosure.Attestation.Type, req.Type, StringComparison.Ordinal)) continue;

            var claims = disclosure.Attestation.Payload.Claims;
            if (claims is null || !claims.TryGetValue(req.Key, out var value)) continue;

            if (req.AllowedValues is null || req.AllowedValues.Count == 0)
                return true; // presence of the claim is sufficient

            var asText = value?.ToString();
            if (asText is not null && req.AllowedValues.Any(v => string.Equals(v, asText, StringComparison.OrdinalIgnoreCase)))
                return true;
        }
        return false;
    }

    private static List<CredentialBundle> ExtractValidBundles(Presentation presentation)
    {
        var proofChecker = new CredentialProof();
        var bundles = new List<CredentialBundle>();

        foreach (var disclosure in presentation.Disclosures)
        {
            var proof = disclosure.PredicateProof;
            if (proof is null || proof.Length == 0) continue;

            // The predicate proof must be BOUND to the commitment inside the attestation it is
            // attached to — otherwise a holder could attach a valid proof about an arbitrary value.
            var commitment = disclosure.Attestation.Payload.Commitment;
            if (commitment is null || commitment.Length == 0) continue; // nothing to bind to

            CredentialBundle bundle;
            try { bundle = PredicateProofCodec.Decode(proof); }
            catch { continue; } // malformed proof: ignore, requirement simply stays unsatisfied

            if (proofChecker.VerifyBound(commitment, bundle)) // valid AND bound to this attestation
                bundles.Add(bundle);
        }

        return bundles;
    }

    private static bool Satisfies(CredentialBundle bundle, PredicateRequirement req)
    {
        if (!string.Equals(bundle.Label, req.Label, StringComparison.Ordinal)) return false;
        if (bundle.ProofType != req.ProofType) return false;

        return req.ProofType switch
        {
            // Proof guarantees value ≥ bundle.Threshold; that satisfies the requirement when the
            // proven floor is at least what the verifier demands.
            CredentialProofType.Minimum => bundle.Threshold >= req.Threshold,

            // A two-sided bound proof guarantees value ∈ [bundle.Threshold, bundle.UpperBound] (BOTH
            // bounds cryptographically proven by VerifyBound). It satisfies the requirement when that
            // proven interval lies within the requested one: floor ≥ required floor AND ceiling ≤ required ceiling.
            CredentialProofType.Range => bundle.Threshold >= req.Threshold
                && (req.UpperBound is null || (bundle.UpperBound is { } ub && ub <= req.UpperBound.Value)),
            _ => false,
        };
    }
}
