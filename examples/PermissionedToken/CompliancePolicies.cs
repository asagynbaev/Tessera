using Tessera.Attestations;
using Tessera.Core;
using Tessera.Sdk;

namespace Tessera.Examples.PermissionedToken;

/// <summary>
/// Compliance policies for the reference scenario, composed declaratively from A4 rules.
/// No business logic is hardwired into the verifier — these are just data.
/// </summary>
public static class CompliancePolicies
{
    /// <summary>Residency this reference scenario admits (ISO-3166 alpha-2).</summary>
    public static readonly string[] AdmittedCountries = { "KZ" };

    /// <summary>
    /// Base admission: the holder must disclose a valid <c>kyc_verified</c> AND a <c>jurisdiction</c>
    /// attestation whose <c>country</c> is one of <see cref="AdmittedCountries"/> (i.e. a resident),
    /// bound to this verifier+session, anchored at the current revocation epoch.
    /// </summary>
    public static VerificationPolicy BaseAdmission(DidId verifier, byte[] sessionNonce) => new()
    {
        ExpectedVerifier = verifier,
        ExpectedSessionNonce = sessionNonce,
        RequireCurrentRevocationEpoch = true,
        RequiredTypes = new[] { AttestationTypes.KycVerified, AttestationTypes.Jurisdiction },
        RequiredClaims = new[]
        {
            new RequiredClaim { Type = AttestationTypes.Jurisdiction, Key = "country", AllowedValues = AdmittedCountries },
        },
    };

    /// <summary>
    /// Accredited tranche: base admission plus an <c>accredited</c> attestation and a predicate
    /// proof that committed income ≥ <paramref name="incomeThreshold"/> (value never revealed).
    /// </summary>
    public static VerificationPolicy AccreditedTranche(DidId verifier, byte[] sessionNonce, long incomeThreshold)
        => BaseAdmission(verifier, sessionNonce) with
        {
            RequiredTypes = new[] { AttestationTypes.KycVerified, AttestationTypes.Jurisdiction, AttestationTypes.Accredited },
            PredicateRequirements = new[] { new PredicateRequirement { Type = AttestationTypes.Accredited, Label = "income", Threshold = incomeThreshold } },
        };
}
