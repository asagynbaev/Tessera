using Tessera.Attestations;
using Tessera.Core;
using Tessera.Sdk;

namespace Tessera.Sdk.Tests;

/// <summary>
/// Unit tests for the declarative policy rules in isolation (no chain / no Merkle): required
/// attestation types and predicate requirements. Predicate proofs are verified BOUND to the
/// commitment inside the attestation they are attached to.
/// </summary>
public class PolicyEvaluationTests
{
    private static AttestationDisclosure Disclosure(string type, byte[]? predicate = null, byte[]? commitment = null) => new()
    {
        Attestation = new Attestation
        {
            Schema = "s",
            Type = type,
            Issuer = new DidId("did:tessera:issuer"),
            Subject = new DidId("did:tessera:subject"),
            IssuedAt = DateTimeOffset.UnixEpoch,
            Nonce = new byte[16],
            Payload = new AttestationPayload { Method = "m", Commitment = commitment },
            Signature = new AttestationSignature { Algorithm = "ed25519", Value = new byte[64] },
        },
        MerkleProof = new MerkleInclusionProof
        {
            LeafHash = new byte[32],
            Path = Array.Empty<byte[]>(),
            Root = new byte[32],
            LeafIndex = 0,
        },
        PredicateProof = predicate,
    };

    private static Presentation Present(params AttestationDisclosure[] disclosures) => new()
    {
        Holder = new DidId("did:tessera:subject"),
        Disclosures = disclosures,
        Binding = new PresentationBinding
        {
            Verifier = new DidId("did:tessera:verifier"),
            SessionNonce = new byte[16],
            AsOfRevocationEpoch = 0,
            Chain = "test",
            HolderSignature = new byte[64],
            CreatedAt = DateTimeOffset.UnixEpoch,
        },
    };

    /// <summary>Build an attestation carrying a committed income, plus a bound proof of income ≥ floor.</summary>
    private static (byte[] commitment, byte[] proof) BoundIncome(long income, long floor, string label = "income")
    {
        var cp = new CredentialProof();
        var (commitment, opening) = cp.CommitValue(income);
        var bundle = cp.ProveBoundMinimum(income, floor, opening, label);
        return (commitment, PredicateProofCodec.Encode(bundle));
    }

    private static VerificationPolicy Policy(params PredicateRequirement[] predicates) => new()
    {
        ExpectedVerifier = new DidId("did:tessera:v"),
        PredicateRequirements = predicates,
    };

    [Fact]
    public void NoRules_Passes()
    {
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(Disclosure("kyc_verified")),
            new VerificationPolicy { ExpectedVerifier = new DidId("did:tessera:v") });
        Assert.True(r.Valid);
    }

    [Fact]
    public void RequiredTypes_AllPresent_Passes()
    {
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(Disclosure("kyc_verified"), Disclosure("jurisdiction")),
            new VerificationPolicy
            {
                ExpectedVerifier = new DidId("did:tessera:v"),
                RequiredTypes = new[] { "kyc_verified", "jurisdiction" },
            });
        Assert.True(r.Valid);
    }

    [Fact]
    public void RequiredTypes_Missing_Fails_WithReason()
    {
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(Disclosure("kyc_verified")),
            new VerificationPolicy
            {
                ExpectedVerifier = new DidId("did:tessera:v"),
                RequiredTypes = new[] { "kyc_verified", "jurisdiction" },
            });
        Assert.False(r.Valid);
        Assert.Equal("missing_required_type:jurisdiction", r.Reason);
    }

    [Fact]
    public void Predicate_BoundProofMeetsThreshold_Passes()
    {
        var (commit, proof) = BoundIncome(income: 50_000, floor: 40_000);
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(Disclosure("accredited", proof, commit)),
            Policy(new PredicateRequirement { Label = "income", Threshold = 30_000 }));
        Assert.True(r.Valid, r.Reason);
    }

    [Fact]
    public void Predicate_ProvenFloorBelowRequired_Fails()
    {
        var (commit, proof) = BoundIncome(income: 50_000, floor: 40_000);
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(Disclosure("accredited", proof, commit)),
            Policy(new PredicateRequirement { Label = "income", Threshold = 60_000 }));
        Assert.False(r.Valid);
        Assert.Equal("predicate_unsatisfied:income", r.Reason);
    }

    [Fact]
    public void Predicate_WrongLabel_Fails()
    {
        var (commit, proof) = BoundIncome(50_000, 40_000);
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(Disclosure("accredited", proof, commit)),
            Policy(new PredicateRequirement { Label = "age", Threshold = 18 }));
        Assert.False(r.Valid);
        Assert.Equal("predicate_unsatisfied:age", r.Reason);
    }

    [Fact]
    public void Predicate_NoProofAttached_Fails()
    {
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(Disclosure("accredited")),
            Policy(new PredicateRequirement { Label = "income", Threshold = 30_000 }));
        Assert.False(r.Valid);
    }

    [Fact]
    public void Predicate_TamperedProof_NotCounted()
    {
        var (commit, proof) = BoundIncome(50_000, 40_000);
        proof[^3] ^= 0xFF; // corrupt the encoded bundle
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(Disclosure("accredited", proof, commit)),
            Policy(new PredicateRequirement { Label = "income", Threshold = 30_000 }));
        Assert.False(r.Valid);
    }

    [Fact]
    public void Predicate_MalformedBytes_Ignored()
    {
        var (commit, _) = BoundIncome(50_000, 40_000);
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(Disclosure("accredited", new byte[] { 1, 2, 3, 4 }, commit)),
            Policy(new PredicateRequirement { Label = "income", Threshold = 30_000 }));
        Assert.False(r.Valid);
    }

    // ── soundness: the binding is what makes predicates trustworthy ──────────

    [Fact]
    public void Predicate_ProofBoundToDifferentCommitment_Fails()
    {
        // A valid proof, but attached to an attestation carrying a DIFFERENT commitment.
        var cp = new CredentialProof();
        var (_, openingA) = cp.CommitValue(50_000);
        var boundToA = cp.ProveBoundMinimum(50_000, 30_000, openingA, "income");
        var (commitB, _) = cp.CommitValue(50_000); // independent commitment

        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(Disclosure("accredited", PredicateProofCodec.Encode(boundToA), commitB)),
            Policy(new PredicateRequirement { Label = "income", Threshold = 30_000 }));
        Assert.False(r.Valid); // binding check rejects the mismatched commitment
    }

    [Fact]
    public void Predicate_UnboundProof_Fails_AgainstCommitment()
    {
        // The legacy unbound proof uses a fresh blinding unrelated to the attestation commitment.
        var cp = new CredentialProof();
        var (commit, _) = cp.CommitValue(50_000);
        var unbound = cp.ProveMinimum(50_000, 30_000, "income");

        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(Disclosure("accredited", PredicateProofCodec.Encode(unbound), commit)),
            Policy(new PredicateRequirement { Label = "income", Threshold = 30_000 }));
        Assert.False(r.Valid);
    }

    [Fact]
    public void Predicate_AttestationWithoutCommitment_Fails()
    {
        var (_, proof) = BoundIncome(50_000, 40_000);
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(Disclosure("accredited", proof, commitment: null)), // nothing to bind to
            Policy(new PredicateRequirement { Label = "income", Threshold = 30_000 }));
        Assert.False(r.Valid);
    }

    [Fact]
    public void Predicate_BoundRange_WithinBounds_Passes()
    {
        var cp = new CredentialProof();
        var (commit, opening) = cp.CommitValue(150);
        var bundle = cp.ProveBoundRange(actualValue: 150, min: 100, max: 200, opening, label: "age");

        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(Disclosure("age_band", PredicateProofCodec.Encode(bundle), commit)),
            Policy(new PredicateRequirement { Label = "age", ProofType = CredentialProofType.Range, Threshold = 100, UpperBound = 200 }));
        Assert.True(r.Valid, r.Reason);
    }

    [Fact]
    public void Predicate_RangeRequirement_NotMetByMinimumProof()
    {
        var (commit, proof) = BoundIncome(150, 100, label: "age");
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(Disclosure("age_band", proof, commit)),
            Policy(new PredicateRequirement { Label = "age", ProofType = CredentialProofType.Range, Threshold = 100, UpperBound = 200 }));
        Assert.False(r.Valid); // a Minimum proof does not satisfy a Range requirement
    }

    private static (byte[] commit, byte[] proof) BoundRange(long value, long min, long max, string label = "age")
    {
        var cp = new CredentialProof();
        var (commit, opening) = cp.CommitValue(value);
        return (commit, PredicateProofCodec.Encode(cp.ProveBoundRange(value, min, max, opening, label)));
    }

    [Fact]
    public void Predicate_BoundRange_ProvenCeilingAboveRequired_Fails()
    {
        // Proof guarantees value ∈ [100,200]; a requirement demanding ≤ 150 is NOT satisfied,
        // because the proof only bounds value at ≤ 200. This is now cryptographically enforced.
        var (commit, proof) = BoundRange(120, 100, 200);
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(Disclosure("age_band", proof, commit)),
            Policy(new PredicateRequirement { Label = "age", ProofType = CredentialProofType.Range, Threshold = 100, UpperBound = 150 }));
        Assert.False(r.Valid);
    }

    [Fact]
    public void Predicate_BoundRange_WithinRequestedInterval_Passes()
    {
        var (commit, proof) = BoundRange(120, 100, 200);
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(Disclosure("age_band", proof, commit)),
            Policy(new PredicateRequirement { Label = "age", ProofType = CredentialProofType.Range, Threshold = 50, UpperBound = 250 }));
        Assert.True(r.Valid, r.Reason);
    }

    // ── claim-value rules ────────────────────────────────────────────────────

    private static AttestationDisclosure JurisdictionDisclosure(string? country)
    {
        var d = Disclosure("jurisdiction");
        var payload = country is null
            ? new AttestationPayload { Method = "m" }
            : new AttestationPayload { Method = "m", Claims = new Dictionary<string, object> { ["country"] = country } };
        return d with { Attestation = d.Attestation with { Payload = payload } };
    }

    private static VerificationPolicy ClaimPolicy(RequiredClaim claim) => new()
    {
        ExpectedVerifier = new DidId("did:tessera:v"),
        RequiredClaims = new[] { claim },
    };

    [Fact]
    public void Claim_PresentAndAllowed_Passes()
    {
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(JurisdictionDisclosure("KZ")),
            ClaimPolicy(new RequiredClaim { Type = "jurisdiction", Key = "country", AllowedValues = new[] { "KZ" } }));
        Assert.True(r.Valid, r.Reason);
    }

    [Fact]
    public void Claim_WrongValue_Fails()
    {
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(JurisdictionDisclosure("US")),
            ClaimPolicy(new RequiredClaim { Type = "jurisdiction", Key = "country", AllowedValues = new[] { "KZ" } }));
        Assert.False(r.Valid);
        Assert.Equal("claim_unsatisfied:jurisdiction.country", r.Reason);
    }

    [Fact]
    public void Claim_CaseInsensitiveValue_Passes()
    {
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(JurisdictionDisclosure("kz")),
            ClaimPolicy(new RequiredClaim { Type = "jurisdiction", Key = "country", AllowedValues = new[] { "KZ" } }));
        Assert.True(r.Valid, r.Reason);
    }

    [Fact]
    public void Claim_MissingKey_Fails()
    {
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(JurisdictionDisclosure(country: null)),
            ClaimPolicy(new RequiredClaim { Type = "jurisdiction", Key = "country", AllowedValues = new[] { "KZ" } }));
        Assert.False(r.Valid);
    }

    [Fact]
    public void Claim_PresenceOnly_Passes_WhenNoAllowedValues()
    {
        var r = PolicyEvaluation.EvaluateDeclarativeRules(
            Present(JurisdictionDisclosure("anything")),
            ClaimPolicy(new RequiredClaim { Type = "jurisdiction", Key = "country" }));
        Assert.True(r.Valid, r.Reason);
    }
}
