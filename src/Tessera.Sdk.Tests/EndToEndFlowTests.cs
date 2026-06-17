using System.Security.Cryptography;
using Tessera.Attestations;
using Tessera.Core;
using Tessera.Sdk;
using Tessera.Signing;

namespace Tessera.Sdk.Tests;

/// <summary>
/// Full SDK flow with real cryptography and an in-memory chain anchor: issuer onboards,
/// holder creates DID, accepts attestation, anchors root, builds presentation, verifier
/// validates against policy. If any of these break, the SDK is not usable end-to-end
/// even when each unit test passes.
/// </summary>
public class EndToEndFlowTests
{
    [Fact]
    public async Task FullFlow_HolderToIssuerToVerifier_Succeeds()
    {
        // ── shared infrastructure ───────────────────────────────────────────
        var verifier = new Ed25519Verifier();
        var registry = new InMemoryIssuerRegistry();
        var chain = new InMemoryChainAnchor();

        // ── issuer side ─────────────────────────────────────────────────────
        var (issuerPriv, _) = Ed25519.GenerateKeypair();
        using var issuerSigner = new Ed25519IssuerSigner(issuerPriv);
        var issuer = new Issuer(new DidId("did:tessera:issuer-app"), issuerSigner);

        registry.Register(issuer.BuildRegistryRecord(schemaUri: "https://schemas.tessera/attestation/v1"));

        // ── holder side ─────────────────────────────────────────────────────
        var (holderPriv, holderPub) = Ed25519.GenerateKeypair();
        var holderOpts = new HolderOptions
        {
            Store = new Tessera.Did.InMemoryDidStore(),
            SignatureVerifier = verifier,
            ChainAnchor = chain,
        };
        var holder = await Holder.CreateAsync(holderPub, holderOpts);

        // issuer issues an attestation FOR the holder
        var att = issuer.Issue("phone_verified", holder.Did, new AttestationPayload { Method = "test_carrier" });
        holder.AcceptAttestation(att);

        // holder anchors the resulting root on-chain
        await holder.AnchorRootAsync();

        // ── verifier side ───────────────────────────────────────────────────
        var verifierDid = new DidId("did:tessera:my-relying-app");
        var sessionNonce = RandomBytes(16);
        var presentation = holder.BuildSignedPresentation(
            verifier: verifierDid,
            attestationTypes: new[] { "phone_verified" },
            sessionNonce: sessionNonce,
            asOfRevocationEpoch: 0,
            chain: "test",
            signChallenge: ch => Ed25519.Sign(holderPriv, ch.Span));

        var zkpVerifier = new Verifier(new VerifierOptions
        {
            IssuerRegistry = registry,
            SignatureVerifier = verifier,
            ChainAnchor = chain,
        });

        var result = await zkpVerifier.VerifyPresentationAsync(presentation, new VerificationPolicy
        {
            ExpectedVerifier = verifierDid,
            ExpectedSessionNonce = sessionNonce,
            RequireCurrentRevocationEpoch = true,
        });

        Assert.True(result.Valid, $"presentation rejected: {result.Reason}");
    }

    [Fact]
    public async Task Verifier_VerifierMismatch_Fails()
    {
        var (holder, holderPriv, chain, issuer, registry, verifier) = await BuildPair();
        var att = issuer.Issue("phone_verified", holder.Did, new AttestationPayload { Method = "x" });
        holder.AcceptAttestation(att);
        await holder.AnchorRootAsync();

        var nonce = RandomBytes(16);
        var presentation = holder.BuildSignedPresentation(
            verifier: new DidId("did:tessera:app-A"),
            attestationTypes: new[] { "phone_verified" },
            sessionNonce: nonce,
            asOfRevocationEpoch: 0,
            chain: "test",
            signChallenge: ch => Ed25519.Sign(holderPriv, ch.Span));

        var zkpVerifier = new Verifier(new VerifierOptions
        {
            IssuerRegistry = registry,
            SignatureVerifier = verifier,
            ChainAnchor = chain,
        });

        var result = await zkpVerifier.VerifyPresentationAsync(presentation, new VerificationPolicy
        {
            ExpectedVerifier = new DidId("did:tessera:app-B"),  // wrong audience
            ExpectedSessionNonce = nonce,
        });

        Assert.False(result.Valid);
        Assert.Equal("verifier_mismatch", result.Reason);
    }

    [Fact]
    public async Task Verifier_SessionNonceMismatch_Fails()
    {
        var (holder, holderPriv, chain, issuer, registry, verifier) = await BuildPair();
        holder.AcceptAttestation(issuer.Issue("phone_verified", holder.Did, new AttestationPayload { Method = "x" }));
        await holder.AnchorRootAsync();

        var verifierDid = new DidId("did:tessera:app");
        var presentationNonce = RandomBytes(16);
        var presentation = holder.BuildSignedPresentation(
            verifier: verifierDid,
            attestationTypes: new[] { "phone_verified" },
            sessionNonce: presentationNonce,
            asOfRevocationEpoch: 0,
            chain: "test",
            signChallenge: ch => Ed25519.Sign(holderPriv, ch.Span));

        var zkpVerifier = new Verifier(new VerifierOptions
        {
            IssuerRegistry = registry,
            SignatureVerifier = verifier,
            ChainAnchor = chain,
        });

        var result = await zkpVerifier.VerifyPresentationAsync(presentation, new VerificationPolicy
        {
            ExpectedVerifier = verifierDid,
            ExpectedSessionNonce = RandomBytes(16),  // expected something else
        });

        Assert.False(result.Valid);
        Assert.Equal("session_nonce_mismatch", result.Reason);
    }

    [Fact]
    public async Task Verifier_RevocationStale_FailsWhenPolicyDemands()
    {
        var (holder, holderPriv, chain, issuer, registry, verifier) = await BuildPair();
        holder.AcceptAttestation(issuer.Issue("phone_verified", holder.Did, new AttestationPayload { Method = "x" }));
        await holder.AnchorRootAsync();

        var verifierDid = new DidId("did:tessera:app");
        var presentation = holder.BuildSignedPresentation(
            verifier: verifierDid,
            attestationTypes: new[] { "phone_verified" },
            sessionNonce: RandomBytes(16),
            asOfRevocationEpoch: 0,  // bound to epoch 0
            chain: "test",
            signChallenge: ch => Ed25519.Sign(holderPriv, ch.Span));

        // simulate the on-chain epoch advancing past the presentation's snapshot
        await chain.BumpRevocationAsync(holder.Did, Tessera.Chains.RevocationReason.HolderRequested);

        var zkpVerifier = new Verifier(new VerifierOptions
        {
            IssuerRegistry = registry,
            SignatureVerifier = verifier,
            ChainAnchor = chain,
        });

        var result = await zkpVerifier.VerifyPresentationAsync(presentation, new VerificationPolicy
        {
            ExpectedVerifier = verifierDid,
            RequireCurrentRevocationEpoch = true,
        });

        Assert.False(result.Valid);
        Assert.Equal("revocation_stale", result.Reason);
    }

    [Fact]
    public async Task Verifier_NoAnchorOnChain_Fails()
    {
        var (holder, holderPriv, chain, issuer, registry, verifier) = await BuildPair();
        // attestation accepted but NEVER anchored
        holder.AcceptAttestation(issuer.Issue("phone_verified", holder.Did, new AttestationPayload { Method = "x" }));

        var verifierDid = new DidId("did:tessera:app");
        var presentation = holder.BuildSignedPresentation(
            verifier: verifierDid,
            attestationTypes: new[] { "phone_verified" },
            sessionNonce: RandomBytes(16),
            asOfRevocationEpoch: 0,
            chain: "test",
            signChallenge: ch => Ed25519.Sign(holderPriv, ch.Span));

        var zkpVerifier = new Verifier(new VerifierOptions
        {
            IssuerRegistry = registry,
            SignatureVerifier = verifier,
            ChainAnchor = chain,
        });

        var result = await zkpVerifier.VerifyPresentationAsync(presentation, new VerificationPolicy
        {
            ExpectedVerifier = verifierDid,
        });

        Assert.False(result.Valid);
        Assert.Equal("no_anchored_root", result.Reason);
    }

    [Fact]
    public async Task Verifier_WithCallerSuppliedRoot_BypassesChainLookup()
    {
        var (holder, holderPriv, _, issuer, registry, verifier) = await BuildPair();
        holder.AcceptAttestation(issuer.Issue("phone_verified", holder.Did, new AttestationPayload { Method = "x" }));

        var verifierDid = new DidId("did:tessera:app");
        var presentation = holder.BuildSignedPresentation(
            verifier: verifierDid,
            attestationTypes: new[] { "phone_verified" },
            sessionNonce: RandomBytes(16),
            asOfRevocationEpoch: 0,
            chain: "test",
            signChallenge: ch => Ed25519.Sign(holderPriv, ch.Span));

        // No chain anchor configured — caller supplies the expected root directly.
        var zkpVerifier = new Verifier(new VerifierOptions
        {
            IssuerRegistry = registry,
            SignatureVerifier = verifier,
            ChainAnchor = null,
        });

        var result = await zkpVerifier.VerifyPresentationAsync(presentation, new VerificationPolicy
        {
            ExpectedVerifier = verifierDid,
            ExpectedAnchorRoot = holder.CurrentRoot,
        });

        Assert.True(result.Valid, $"failed: {result.Reason}");
    }

    [Fact]
    public async Task Verifier_NoChainAndNoRoot_Throws()
    {
        var (holder, holderPriv, _, issuer, registry, verifier) = await BuildPair();
        holder.AcceptAttestation(issuer.Issue("phone_verified", holder.Did, new AttestationPayload { Method = "x" }));

        var presentation = holder.BuildSignedPresentation(
            verifier: new DidId("did:tessera:app"),
            attestationTypes: new[] { "phone_verified" },
            sessionNonce: RandomBytes(16),
            asOfRevocationEpoch: 0,
            chain: "test",
            signChallenge: ch => Ed25519.Sign(holderPriv, ch.Span));

        var zkpVerifier = new Verifier(new VerifierOptions
        {
            IssuerRegistry = registry,
            SignatureVerifier = verifier,
            ChainAnchor = null,
        });

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            zkpVerifier.VerifyPresentationAsync(presentation, new VerificationPolicy
            {
                ExpectedVerifier = new DidId("did:tessera:app"),
            }));
    }

    [Fact]
    public async Task Verifier_StaleCachedRoot_VsLiveAnchor_Fails()
    {
        // TOCTOU: a cached ExpectedAnchorRoot must not be trusted when a live anchor disagrees — a
        // root rotation that removed an attestation does NOT bump the revocation epoch, so the stale
        // root would otherwise still verify a presentation of the since-removed attestation.
        var (holder, holderPriv, chain, issuer, registry, verifier) = await BuildPair();
        holder.AcceptAttestation(issuer.Issue("phone_verified", holder.Did, new AttestationPayload { Method = "x" }));
        await holder.AnchorRootAsync();
        var staleRoot = holder.CurrentRoot; // R1, cached by the verifier

        var verifierDid = new DidId("did:tessera:app");
        var presentation = holder.BuildSignedPresentation(
            verifier: verifierDid,
            attestationTypes: new[] { "phone_verified" },
            sessionNonce: RandomBytes(16),
            asOfRevocationEpoch: 0,
            chain: "test",
            signChallenge: ch => Ed25519.Sign(holderPriv, ch.Span));

        // Anchored root rotates to R2 (!= R1) WITHOUT bumping the epoch.
        await chain.AnchorRootAsync(holder.Did, new byte[32]);

        var zkpVerifier = new Verifier(new VerifierOptions
        {
            IssuerRegistry = registry,
            SignatureVerifier = verifier,
            ChainAnchor = chain,
        });

        var result = await zkpVerifier.VerifyPresentationAsync(presentation, new VerificationPolicy
        {
            ExpectedVerifier = verifierDid,
            ExpectedAnchorRoot = staleRoot, // cached R1, but the live anchor now holds R2
        });

        Assert.False(result.Valid);
        Assert.Equal("anchor_root_stale", result.Reason);
    }

    // ── helpers ──────────────────────────────────────────────────────────

    private record FlowFixture(
        Holder Holder,
        byte[] HolderPriv,
        InMemoryChainAnchor Chain,
        Issuer Issuer,
        InMemoryIssuerRegistry Registry,
        Ed25519Verifier SignatureVerifier);

    private static async Task<FlowFixture> BuildPair()
    {
        var verifier = new Ed25519Verifier();
        var registry = new InMemoryIssuerRegistry();
        var chain = new InMemoryChainAnchor();

        var (issuerPriv, _) = Ed25519.GenerateKeypair();
        var issuerSigner = new Ed25519IssuerSigner(issuerPriv);
        var issuer = new Issuer(new DidId("did:tessera:flow-issuer"), issuerSigner);
        registry.Register(issuer.BuildRegistryRecord(schemaUri: "https://schemas.tessera/attestation/v1"));

        var (holderPriv, holderPub) = Ed25519.GenerateKeypair();
        var holder = await Holder.CreateAsync(holderPub, new HolderOptions
        {
            Store = new Tessera.Did.InMemoryDidStore(),
            SignatureVerifier = verifier,
            ChainAnchor = chain,
        });

        return new FlowFixture(holder, holderPriv, chain, issuer, registry, verifier);
    }

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }
}
