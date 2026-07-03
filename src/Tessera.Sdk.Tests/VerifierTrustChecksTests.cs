using System.Security.Cryptography;
using Tessera.Attestations;
using Tessera.Core;
using Tessera.Did;
using Tessera.Sdk;
using Tessera.Signing;

namespace Tessera.Sdk.Tests;

/// <summary>
/// Full-flow tests for the opt-in trust checks layered onto <see cref="Verifier.VerifyPresentationAsync"/>:
/// single-use presentation nonces (M-1, anti-replay) and DID-level revocation (M-3). Both are inert
/// unless the corresponding store is configured, so the defaults stay backward-compatible.
/// </summary>
public class VerifierTrustChecksTests
{
    private sealed record Fixture(
        Holder Holder,
        byte[] HolderPriv,
        InMemoryChainAnchor Chain,
        Issuer Issuer,
        InMemoryIssuerRegistry Registry,
        Ed25519Verifier Sig,
        InMemoryDidStore DidStore);

    private static async Task<Fixture> BuildAsync()
    {
        var sig = new Ed25519Verifier();
        var registry = new InMemoryIssuerRegistry();
        var chain = new InMemoryChainAnchor();
        var store = new InMemoryDidStore();

        var (issuerPriv, _) = Ed25519.GenerateKeypair();
        var issuer = new Issuer(new DidId("did:tessera:kyc-issuer"), new Ed25519IssuerSigner(issuerPriv));
        registry.Register(issuer.BuildRegistryRecord("https://schemas.tessera/kyc/v1"));

        var (holderPriv, holderPub) = Ed25519.GenerateKeypair();
        var holder = await Holder.CreateAsync(holderPub, new HolderOptions
        {
            Store = store,
            SignatureVerifier = sig,
            ChainAnchor = chain,
        });

        return new Fixture(holder, holderPriv, chain, issuer, registry, sig, store);
    }

    private static byte[] Rand(int n)
    {
        var b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    private static async Task<(Fixture f, Presentation presentation, DidId verifierDid, byte[] nonce)> AnchoredPresentationAsync()
    {
        var f = await BuildAsync();
        f.Holder.AcceptAttestation(f.Issuer.Issue("kyc_verified", f.Holder.Did, new AttestationPayload { Method = "kyc" }));
        await f.Holder.AnchorRootAsync();

        var verifierDid = new DidId("did:tessera:token-gate");
        var nonce = Rand(16);
        var presentation = f.Holder.BuildSignedPresentation(
            verifierDid, new[] { "kyc_verified" }, nonce, 0, "test", ch => Ed25519.Sign(f.HolderPriv, ch.Span));
        return (f, presentation, verifierDid, nonce);
    }

    // ── M-1: single-use presentation nonce (anti-replay) ──────────────────────

    [Fact]
    public async Task Replay_SamePresentation_Rejected_WhenNonceStoreConfigured()
    {
        var (f, presentation, verifierDid, nonce) = await AnchoredPresentationAsync();

        var verifier = new Verifier(new VerifierOptions
        {
            IssuerRegistry = f.Registry,
            SignatureVerifier = f.Sig,
            ChainAnchor = f.Chain,
            NonceStore = new InMemoryNonceStore(),
        });
        var policy = new VerificationPolicy { ExpectedVerifier = verifierDid, ExpectedSessionNonce = nonce };

        var first = await verifier.VerifyPresentationAsync(presentation, policy);
        Assert.True(first.Valid, first.Reason);

        // Same holder + session nonce presented twice → the second is a replay.
        var replay = await verifier.VerifyPresentationAsync(presentation, policy);
        Assert.False(replay.Valid);
        Assert.Equal("presentation_replayed", replay.Reason);
    }

    [Fact]
    public async Task Replay_SamePresentation_Allowed_WhenNoNonceStore()
    {
        var (f, presentation, verifierDid, nonce) = await AnchoredPresentationAsync();

        // No nonce store → legacy behaviour: replay is only bounded by the freshness window.
        var verifier = new Verifier(new VerifierOptions
        {
            IssuerRegistry = f.Registry,
            SignatureVerifier = f.Sig,
            ChainAnchor = f.Chain,
        });
        var policy = new VerificationPolicy { ExpectedVerifier = verifierDid, ExpectedSessionNonce = nonce };

        Assert.True((await verifier.VerifyPresentationAsync(presentation, policy)).Valid);
        Assert.True((await verifier.VerifyPresentationAsync(presentation, policy)).Valid);
    }

    [Fact]
    public async Task EmptySessionNonce_Rejected_WhenNonceStoreConfigured()
    {
        // A configured nonce store means "prevent replay". A presentation with an empty session nonce
        // cannot be made single-use, so it must be rejected rather than silently replay within the window.
        var f = await BuildAsync();
        f.Holder.AcceptAttestation(f.Issuer.Issue("kyc_verified", f.Holder.Did, new AttestationPayload { Method = "kyc" }));
        await f.Holder.AnchorRootAsync();

        var verifierDid = new DidId("did:tessera:token-gate");
        var presentation = f.Holder.BuildSignedPresentation(
            verifierDid, new[] { "kyc_verified" }, Array.Empty<byte>(), 0, "test", ch => Ed25519.Sign(f.HolderPriv, ch.Span));

        var verifier = new Verifier(new VerifierOptions
        {
            IssuerRegistry = f.Registry,
            SignatureVerifier = f.Sig,
            ChainAnchor = f.Chain,
            NonceStore = new InMemoryNonceStore(),
        });
        // No ExpectedSessionNonce pinned — the store alone must still enforce a usable nonce.
        var policy = new VerificationPolicy { ExpectedVerifier = verifierDid };

        var result = await verifier.VerifyPresentationAsync(presentation, policy);
        Assert.False(result.Valid);
        Assert.Equal("session_nonce_required", result.Reason);
    }

    // ── M-3: DID-level revocation (defense-in-depth) ──────────────────────────

    [Fact]
    public async Task HolderDidRevoked_InStore_FailsClosed()
    {
        var (f, presentation, verifierDid, nonce) = await AnchoredPresentationAsync();

        // Revoke the holder DID in the store AFTER the presentation was built and anchored.
        var doc = await f.DidStore.GetAsync(f.Holder.Did);
        var revokeChallenge = DidService.BuildRevokeChallenge(f.Holder.Did, doc!.Version);
        await f.Holder.RevokeAsync(Ed25519.Sign(f.HolderPriv, revokeChallenge));

        var verifier = new Verifier(new VerifierOptions
        {
            IssuerRegistry = f.Registry,
            SignatureVerifier = f.Sig,
            ChainAnchor = f.Chain,
            DidStore = f.DidStore,
        });

        var result = await verifier.VerifyPresentationAsync(presentation, new VerificationPolicy
        {
            ExpectedVerifier = verifierDid,
            ExpectedSessionNonce = nonce,
        });

        Assert.False(result.Valid);
        Assert.Equal("holder_did_revoked", result.Reason);
    }

    [Fact]
    public async Task IssuerDidRevoked_InStore_FailsClosed()
    {
        var (f, presentation, verifierDid, nonce) = await AnchoredPresentationAsync();

        // Mark the issuer DID revoked in the store (independent of the issuer registry / chain epoch).
        await f.DidStore.SaveAsync(new DidDocument
        {
            Id = f.Issuer.Did,
            Controller = f.Issuer.Did,
            VerificationMethods = Array.Empty<VerificationMethod>(),
            Revoked = true,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
        });

        var verifier = new Verifier(new VerifierOptions
        {
            IssuerRegistry = f.Registry,
            SignatureVerifier = f.Sig,
            ChainAnchor = f.Chain,
            DidStore = f.DidStore,
        });

        var result = await verifier.VerifyPresentationAsync(presentation, new VerificationPolicy
        {
            ExpectedVerifier = verifierDid,
            ExpectedSessionNonce = nonce,
        });

        Assert.False(result.Valid);
        Assert.Equal("issuer_did_revoked", result.Reason);
    }

    [Fact]
    public async Task ActiveDids_InStore_StillVerify()
    {
        // A configured DID store must not over-reject: an active (present, non-revoked) holder passes.
        var (f, presentation, verifierDid, nonce) = await AnchoredPresentationAsync();

        var verifier = new Verifier(new VerifierOptions
        {
            IssuerRegistry = f.Registry,
            SignatureVerifier = f.Sig,
            ChainAnchor = f.Chain,
            DidStore = f.DidStore,
        });

        var result = await verifier.VerifyPresentationAsync(presentation, new VerificationPolicy
        {
            ExpectedVerifier = verifierDid,
            ExpectedSessionNonce = nonce,
        });

        Assert.True(result.Valid, result.Reason);
    }
}
