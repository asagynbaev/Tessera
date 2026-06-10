using System.Security.Cryptography;
using Tessera.Attestations;
using Tessera.Core;
using Tessera.Sdk;
using Tessera.Signing;

namespace Tessera.Sdk.Tests;

/// <summary>
/// Full-flow tests that the declarative policy rules (required types + predicates) are enforced
/// by <see cref="Verifier.VerifyPresentationAsync"/> on top of the cryptographic verification.
/// </summary>
public class PolicyVerificationFlowTests
{
    private sealed record Fixture(Holder Holder, InMemoryChainAnchor Chain, Issuer Issuer, InMemoryIssuerRegistry Registry, Ed25519Verifier Sig);

    private static async Task<Fixture> BuildAsync()
    {
        var sig = new Ed25519Verifier();
        var registry = new InMemoryIssuerRegistry();
        var chain = new InMemoryChainAnchor();

        var (issuerPriv, _) = Ed25519.GenerateKeypair();
        var issuer = new Issuer(new DidId("did:tessera:kyc-issuer"), new Ed25519IssuerSigner(issuerPriv));
        registry.Register(issuer.BuildRegistryRecord("https://schemas.tessera/kyc/v1"));

        var (_, holderPub) = Ed25519.GenerateKeypair();
        var holder = await Holder.CreateAsync(holderPub, new HolderOptions
        {
            Store = new Tessera.Did.InMemoryDidStore(),
            SignatureVerifier = sig,
            ChainAnchor = chain,
        });

        return new Fixture(holder, chain, issuer, registry, sig);
    }

    private static byte[] Rand(int n)
    {
        var b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    private Verifier NewVerifier(Fixture f) => new(new VerifierOptions
    {
        IssuerRegistry = f.Registry,
        SignatureVerifier = f.Sig,
        ChainAnchor = f.Chain,
    });

    [Fact]
    public async Task RequiredTypes_Present_Passes()
    {
        var f = await BuildAsync();
        f.Holder.AcceptAttestation(f.Issuer.Issue("kyc_verified", f.Holder.Did, new AttestationPayload { Method = "kyc" }));
        f.Holder.AcceptAttestation(f.Issuer.Issue("jurisdiction", f.Holder.Did, new AttestationPayload { Method = "registry" }));
        await f.Holder.AnchorRootAsync();

        var verifierDid = new DidId("did:tessera:token-gate");
        var nonce = Rand(16);
        var presentation = f.Holder.BuildPresentation(verifierDid, new[] { "kyc_verified", "jurisdiction" }, nonce, 0, "test", Rand(64));

        var result = await NewVerifier(f).VerifyPresentationAsync(presentation, new VerificationPolicy
        {
            ExpectedVerifier = verifierDid,
            ExpectedSessionNonce = nonce,
            RequireCurrentRevocationEpoch = true,
            RequiredTypes = new[] { "kyc_verified", "jurisdiction" },
        });

        Assert.True(result.Valid, result.Reason);
    }

    [Fact]
    public async Task RequiredTypes_Missing_Fails()
    {
        var f = await BuildAsync();
        f.Holder.AcceptAttestation(f.Issuer.Issue("kyc_verified", f.Holder.Did, new AttestationPayload { Method = "kyc" }));
        await f.Holder.AnchorRootAsync();

        var verifierDid = new DidId("did:tessera:token-gate");
        var nonce = Rand(16);
        // discloses only kyc_verified, but policy also requires jurisdiction
        var presentation = f.Holder.BuildPresentation(verifierDid, new[] { "kyc_verified" }, nonce, 0, "test", Rand(64));

        var result = await NewVerifier(f).VerifyPresentationAsync(presentation, new VerificationPolicy
        {
            ExpectedVerifier = verifierDid,
            ExpectedSessionNonce = nonce,
            RequiredTypes = new[] { "kyc_verified", "jurisdiction" },
        });

        Assert.False(result.Valid);
        Assert.Equal("missing_required_type:jurisdiction", result.Reason);
    }

    [Fact]
    public async Task Predicate_AttachedAndMeetsThreshold_Passes()
    {
        var f = await BuildAsync();

        // Issuer commits to the holder's income in the attestation; holder keeps the opening.
        var cp = new CredentialProof();
        var (commitment, opening) = cp.CommitValue(120_000);
        f.Holder.AcceptAttestation(f.Issuer.Issue("accredited", f.Holder.Did, new AttestationPayload { Method = "income", Commitment = commitment }));
        await f.Holder.AnchorRootAsync();

        var verifierDid = new DidId("did:tessera:token-gate");
        var nonce = Rand(16);
        var presentation = f.Holder.BuildPresentation(verifierDid, new[] { "accredited" }, nonce, 0, "test", Rand(64));

        // Attach a predicate proof (income ≥ 100k) BOUND to the attestation's commitment.
        var bundle = cp.ProveBoundMinimum(actualValue: 120_000, minimumRequired: 100_000, opening, label: "income");
        var withProof = presentation.Disclosures[0] with { PredicateProof = PredicateProofCodec.Encode(bundle) };
        presentation = presentation with { Disclosures = new[] { withProof } };

        var result = await NewVerifier(f).VerifyPresentationAsync(presentation, new VerificationPolicy
        {
            ExpectedVerifier = verifierDid,
            ExpectedSessionNonce = nonce,
            RequiredTypes = new[] { "accredited" },
            PredicateRequirements = new[] { new PredicateRequirement { Label = "income", Threshold = 100_000 } },
        });

        Assert.True(result.Valid, result.Reason);
    }

    [Fact]
    public async Task Predicate_NotAttached_Fails()
    {
        var f = await BuildAsync();
        f.Holder.AcceptAttestation(f.Issuer.Issue("accredited", f.Holder.Did, new AttestationPayload { Method = "income" }));
        await f.Holder.AnchorRootAsync();

        var verifierDid = new DidId("did:tessera:token-gate");
        var nonce = Rand(16);
        var presentation = f.Holder.BuildPresentation(verifierDid, new[] { "accredited" }, nonce, 0, "test", Rand(64));

        var result = await NewVerifier(f).VerifyPresentationAsync(presentation, new VerificationPolicy
        {
            ExpectedVerifier = verifierDid,
            ExpectedSessionNonce = nonce,
            PredicateRequirements = new[] { new PredicateRequirement { Label = "income", Threshold = 100_000 } },
        });

        Assert.False(result.Valid);
        Assert.Equal("predicate_unsatisfied:income", result.Reason);
    }

    [Fact]
    public async Task DeclarativeRules_OnlyApply_AfterCryptoPasses()
    {
        // A bad audience must fail with verifier_mismatch, not a policy-rule reason.
        var f = await BuildAsync();
        f.Holder.AcceptAttestation(f.Issuer.Issue("kyc_verified", f.Holder.Did, new AttestationPayload { Method = "kyc" }));
        await f.Holder.AnchorRootAsync();

        var nonce = Rand(16);
        var presentation = f.Holder.BuildPresentation(new DidId("did:tessera:real"), new[] { "kyc_verified" }, nonce, 0, "test", Rand(64));

        var result = await NewVerifier(f).VerifyPresentationAsync(presentation, new VerificationPolicy
        {
            ExpectedVerifier = new DidId("did:tessera:WRONG"),
            RequiredTypes = new[] { "kyc_verified", "jurisdiction" }, // would also fail, but crypto check comes first
        });

        Assert.False(result.Valid);
        Assert.Equal("verifier_mismatch", result.Reason);
    }
}
