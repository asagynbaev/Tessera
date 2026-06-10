using System.Security.Cryptography;
using Tessera.Attestations;
using Tessera.Core;
using Tessera.Did;
using Tessera.Examples.PermissionedToken;
using Tessera.Sdk;
using Tessera.Signing;
using Tessera.Sources.Sumsub;
using Tessera.Sources.XRoad;

namespace Tessera.Examples.PermissionedToken.Tests;

/// <summary>
/// Headline Layer-3 end-to-end: KYC + registry onboarding → DID + attestations → presentation →
/// compliance policy → allowlist → token ownership; then revocation makes the presentation stale,
/// the address is removed, and transfers are blocked. Fully in-memory and deterministic.
/// </summary>
public class ComplianceFlowTests
{
    // ── plugin client fakes (stand in for Sumsub / X-Road services) ──────────
    private sealed class FakeSumsub : ISumsubClient
    {
        public Task<SumsubApplicantReview?> GetApplicantReviewAsync(string applicantId, CancellationToken ct = default)
            => Task.FromResult<SumsubApplicantReview?>(new SumsubApplicantReview
            {
                ApplicantId = applicantId, Approved = true, ReviewAnswer = "GREEN", LevelName = "id-and-liveness", Country = "KZ",
            });
    }

    private sealed class FakeXRoad : IXRoadClient
    {
        public Task<XRoadRegistryRecord?> LookupAsync(XRoadQuery query, CancellationToken ct = default)
            => Task.FromResult<XRoadRegistryRecord?>(new XRoadRegistryRecord
            {
                PersonFound = true, ResidencyCountry = "KZ", PropertyOwnershipConfirmed = true,
                ParcelId = query.ParcelId, EncumbranceStatus = "none",
            });
    }

    private const string AliceAddr = "0x000000000000000000000000000000000000A11C";
    private const string BobAddr = "0x000000000000000000000000000000000000B0B0";
    private static readonly DidId VerifierDid = new("did:tessera:permissioned-token-app");

    private static byte[] Rand(int n) { var b = new byte[n]; RandomNumberGenerator.Fill(b); return b; }

    [Fact]
    public async Task FullFlow_Onboard_Admit_Transfer_Revoke_BlocksTransfers()
    {
        // ── infrastructure ───────────────────────────────────────────────────
        var sigVerifier = new Ed25519Verifier();
        var registry = new InMemoryIssuerRegistry();
        var chain = new InMemoryComplianceChain();
        var gateway = new InMemoryAllowlistGateway();
        var token = new PermissionedTokenLedger(gateway.IsAllowed);

        // ── issuer + onboarding pipeline (Sumsub + X-Road → Issuer → registry) ─
        var (issuerPriv, _) = Ed25519.GenerateKeypair();
        using var issuerSigner = new Ed25519IssuerSigner(issuerPriv);
        var issuer = new Issuer(new DidId("did:tessera:compliance-issuer"), issuerSigner);
        var pipeline = new IssuancePipeline(
            issuer,
            new IAttestationSource[] { new SumsubAttestationSource(new FakeSumsub()), new XRoadAttestationSource(new FakeXRoad()) },
            registry,
            SchemaRegistry.StandardSchemas[0].SchemaUri);

        // ── holder (alice) creates a DID and is onboarded ──────────────────────
        var (_, holderPub) = Ed25519.GenerateKeypair();
        var holder = await Holder.CreateAsync(holderPub, new HolderOptions
        {
            Store = new InMemoryDidStore(),
            SignatureVerifier = sigVerifier,
            ChainAnchor = chain,
        });

        var subject = new SubjectContext
        {
            Subject = holder.Did,
            Parameters = new Dictionary<string, string>
            {
                [SumsubAttestationSource.ApplicantIdKey] = "sumsub-app-alice",
                [XRoadAttestationSource.NationalIdKey] = "990101300123",
                [XRoadAttestationSource.ParcelIdKey] = "09-123-456",
            },
        };

        foreach (var att in await pipeline.IssueForAsync(subject))
            holder.AcceptAttestation(att);
        await holder.AnchorRootAsync();

        // sanity: onboarding produced KYC + jurisdiction (and property/encumbrance from X-Road)
        Assert.Contains(holder.Attestations, a => a.Type == AttestationTypes.KycVerified);
        Assert.Contains(holder.Attestations, a => a.Type == AttestationTypes.Jurisdiction);

        // ── admission: verify presentation against the compliance policy ───────
        var verifier = new Verifier(new VerifierOptions { IssuerRegistry = registry, SignatureVerifier = sigVerifier, ChainAnchor = chain });
        var nonce = Rand(16);
        var presentation = holder.BuildPresentation(
            VerifierDid,
            new[] { AttestationTypes.KycVerified, AttestationTypes.Jurisdiction },
            nonce, asOfRevocationEpoch: 0, chain: chain.ChainId, holderSignature: Rand(64));

        var admission = await verifier.VerifyPresentationAsync(presentation, CompliancePolicies.BaseAdmission(VerifierDid, nonce));
        Assert.True(admission.Valid, $"admission rejected: {admission.Reason}");

        // valid presentation → address admitted to the allowlist
        await gateway.AddAsync(AliceAddr);
        await gateway.AddAsync(BobAddr); // bob admitted via the same flow (elided)

        // ── token ownership works between admitted addresses ──────────────────
        token.Mint(AliceAddr, 1_000);
        token.Transfer(AliceAddr, BobAddr, 250);
        Assert.Equal(750, token.BalanceOf(AliceAddr));
        Assert.Equal(250, token.BalanceOf(BobAddr));

        // ── revocation: KYC revoked → presentation stale → address removed ────
        await chain.BumpRevocationAsync(holder.Did, Tessera.Chains.RevocationReason.IssuerRevoked);

        var afterRevoke = await verifier.VerifyPresentationAsync(presentation, CompliancePolicies.BaseAdmission(VerifierDid, nonce));
        Assert.False(afterRevoke.Valid);
        Assert.Equal("revocation_stale", afterRevoke.Reason);

        await gateway.RevokeAsync(AliceAddr); // compliance action driven by the failed re-check

        // ── revoked holder can no longer transfer ─────────────────────────────
        var blocked = Assert.Throws<PermissionedTransferBlockedException>(() => token.Transfer(AliceAddr, BobAddr, 10));
        Assert.Equal(AliceAddr, blocked.Address);
        // balances unchanged by the blocked transfer
        Assert.Equal(750, token.BalanceOf(AliceAddr));
    }

    [Fact]
    public async Task AccreditedTranche_PredicateGatesOnIncome()
    {
        var sigVerifier = new Ed25519Verifier();
        var registry = new InMemoryIssuerRegistry();
        var chain = new InMemoryComplianceChain();

        var (issuerPriv, _) = Ed25519.GenerateKeypair();
        using var issuerSigner = new Ed25519IssuerSigner(issuerPriv);
        var issuer = new Issuer(new DidId("did:tessera:compliance-issuer"), issuerSigner);
        registry.Register(issuer.BuildRegistryRecord(SchemaRegistry.StandardSchemas[0].SchemaUri));

        var (_, holderPub) = Ed25519.GenerateKeypair();
        var holder = await Holder.CreateAsync(holderPub, new HolderOptions
        {
            Store = new InMemoryDidStore(), SignatureVerifier = sigVerifier, ChainAnchor = chain,
        });

        // Issuer commits to the holder's income (C = income·G + r·H) in the accredited attestation;
        // the holder keeps the opening to build a predicate proof BOUND to that commitment.
        var cp = new CredentialProof();
        var (incomeCommitment, incomeOpening) = cp.CommitValue(120_000);
        var incomeProof = cp.ProveBoundMinimum(actualValue: 120_000, minimumRequired: 100_000, incomeOpening, label: "income");

        holder.AcceptAttestation(issuer.Issue(AttestationTypes.KycVerified, holder.Did, new AttestationPayload { Method = "sumsub" }));
        holder.AcceptAttestation(issuer.Issue(AttestationTypes.Jurisdiction, holder.Did,
            new AttestationPayload { Method = "sumsub", Claims = new Dictionary<string, object> { ["country"] = "KZ" } }));
        holder.AcceptAttestation(issuer.Issue(AttestationTypes.Accredited, holder.Did,
            new AttestationPayload { Method = "issuer-committed", Commitment = incomeCommitment }));
        await holder.AnchorRootAsync();

        var nonce = Rand(16);
        var presentation = BuildPresentationWithPredicate(holder, incomeProof, nonce, chain.ChainId);

        var verifier = new Verifier(new VerifierOptions { IssuerRegistry = registry, SignatureVerifier = sigVerifier, ChainAnchor = chain });

        // income 120k clears a 100k tranche...
        var pass = await verifier.VerifyPresentationAsync(presentation, CompliancePolicies.AccreditedTranche(VerifierDid, nonce, 100_000));
        Assert.True(pass.Valid, $"accredited admission rejected: {pass.Reason}");

        // ...but not a 200k tranche (the proven floor is only 100k).
        var fail = await verifier.VerifyPresentationAsync(presentation, CompliancePolicies.AccreditedTranche(VerifierDid, nonce, 200_000));
        Assert.False(fail.Valid);
        Assert.Equal("predicate_unsatisfied:income", fail.Reason);
    }

    [Fact]
    public async Task NonResident_IsRejected_ByResidencyClaim()
    {
        var sigVerifier = new Ed25519Verifier();
        var registry = new InMemoryIssuerRegistry();
        var chain = new InMemoryComplianceChain();

        var (issuerPriv, _) = Ed25519.GenerateKeypair();
        using var issuerSigner = new Ed25519IssuerSigner(issuerPriv);
        var issuer = new Issuer(new DidId("did:tessera:compliance-issuer"), issuerSigner);
        registry.Register(issuer.BuildRegistryRecord(SchemaRegistry.StandardSchemas[0].SchemaUri));

        var (_, holderPub) = Ed25519.GenerateKeypair();
        var holder = await Holder.CreateAsync(holderPub, new HolderOptions
        {
            Store = new InMemoryDidStore(), SignatureVerifier = sigVerifier, ChainAnchor = chain,
        });

        // KYC'd, but resident of a non-admitted country.
        holder.AcceptAttestation(issuer.Issue(AttestationTypes.KycVerified, holder.Did, new AttestationPayload { Method = "sumsub" }));
        holder.AcceptAttestation(issuer.Issue(AttestationTypes.Jurisdiction, holder.Did,
            new AttestationPayload { Method = "sumsub", Claims = new Dictionary<string, object> { ["country"] = "US" } }));
        await holder.AnchorRootAsync();

        var nonce = Rand(16);
        var presentation = holder.BuildPresentation(
            VerifierDid,
            new[] { AttestationTypes.KycVerified, AttestationTypes.Jurisdiction },
            nonce, asOfRevocationEpoch: 0, chain: chain.ChainId, holderSignature: Rand(64));

        var verifier = new Verifier(new VerifierOptions { IssuerRegistry = registry, SignatureVerifier = sigVerifier, ChainAnchor = chain });
        var result = await verifier.VerifyPresentationAsync(presentation, CompliancePolicies.BaseAdmission(VerifierDid, nonce));

        Assert.False(result.Valid);
        Assert.Equal("claim_unsatisfied:jurisdiction.country", result.Reason);
    }

    /// <summary>
    /// Assemble a presentation disclosing kyc + jurisdiction + accredited, with the income range
    /// proof attached to the accredited disclosure. Mirrors what a wallet would build when a
    /// verifier asks for an accredited-tranche presentation.
    /// </summary>
    private static Presentation BuildPresentationWithPredicate(Holder holder, CredentialBundle incomeProof, byte[] nonce, string chainId)
    {
        var bundle = new AttestationBundle(holder.Attestations);
        var disclosures = new List<AttestationDisclosure>();
        for (var i = 0; i < holder.Attestations.Count; i++)
        {
            var d = bundle.DisclosureFor(i);
            if (d.Attestation.Type == AttestationTypes.Accredited)
                d = d with { PredicateProof = PredicateProofCodec.Encode(incomeProof) };
            disclosures.Add(d);
        }

        return new Presentation
        {
            Holder = holder.Did,
            Disclosures = disclosures,
            Binding = new PresentationBinding
            {
                Verifier = VerifierDid,
                SessionNonce = nonce,
                AsOfRevocationEpoch = 0,
                Chain = chainId,
                HolderSignature = Rand(64),
                CreatedAt = DateTimeOffset.UnixEpoch,
            },
        };
    }
}
