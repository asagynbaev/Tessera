using Tessera.Attestations;
using Tessera.Core;
using Tessera.Did;
using Tessera.Signing;

namespace Tessera.Signing.Tests;

/// <summary>
/// End-to-end smoke tests proving the real cryptographic stack works without stubs:
/// real Ed25519 signing → DID creation → wallet binding → attestation issuance →
/// Merkle bundling → selective disclosure → presentation verification.
/// </summary>
/// <remarks>
/// If any of these fail, something in the production pipeline is broken even if every
/// unit test passes. These are the integration anchor for "the SDK actually works".
/// </remarks>
public class EndToEndFlowTests
{
    [Fact]
    public async Task FullFlow_RealCrypto_VerifiesPresentation()
    {
        // ── 1. Generate three independent keypairs: holder, wallet, issuer
        var (holderPriv, holderPub) = Ed25519.GenerateKeypair();
        var (walletPriv, walletPub) = Ed25519.GenerateKeypair();
        using var issuerSigner = new Ed25519IssuerSigner(Ed25519.GenerateKeypair().PrivateKey);

        var verifier = new Ed25519Verifier();

        // ── 2. Create the DID using the holder's public key as controller
        var didService = new DidService(new InMemoryDidStore(), verifier);
        var didDoc = await didService.CreateAsync(holderPub);

        Assert.True(didDoc.Id.IsWellFormed);
        Assert.False(didDoc.Revoked);

        // ── 3. Wallet binding: the wallet signs the canonical challenge
        //   The Solana address must be provably controlled by the key: address == Base58(pubkey).
        var bindingRequest = new WalletBindingRequest
        {
            Chain = "solana",
            Address = Base58.Encode(walletPub),
            WalletPublicKey = walletPub,
            Nonce = RandomBytes(16),
            Expiry = DateTimeOffset.UtcNow.AddMinutes(5),
            Signature = Array.Empty<byte>(),
        };
        var challenge = DidService.BuildWalletChallenge(didDoc.Id, bindingRequest);
        var walletSig = Ed25519.Sign(walletPriv, challenge);
        bindingRequest = bindingRequest with { Signature = walletSig };

        var afterBinding = await didService.BindWalletAsync(didDoc.Id, bindingRequest);
        Assert.Single(afterBinding.Wallets);
        Assert.Equal("solana", afterBinding.Wallets[0].Chain);

        // ── 4. Register the issuer
        var issuerDid = new DidId("did:tessera:issuer-end-to-end");
        var issuerRegistry = new InMemoryIssuerRegistry();
        issuerRegistry.Register(new IssuerRecord
        {
            Did = issuerDid,
            PublicKey = issuerSigner.PublicKey,
            Algorithm = issuerSigner.Algorithm,
            SchemaUri = "https://schemas.tessera/attestation/v1",
            Active = true,
        });

        // ── 5. Issue an attestation
        var issuer = new AttestationIssuer(issuerDid, issuerSigner);
        var attestation = issuer.Issue(
            AttestationTypes.PhoneVerified,
            subject: didDoc.Id,
            payload: new AttestationPayload { Method = "twilio_v2" });

        Assert.Equal(issuerDid, attestation.Issuer);
        Assert.Equal(didDoc.Id, attestation.Subject);
        Assert.Equal("ed25519", attestation.Signature.Algorithm);
        Assert.Equal(Ed25519.SignatureSize, attestation.Signature.Value.Length);

        // ── 6. Verify the standalone attestation
        var attestationVerifier = new AttestationVerifier(issuerRegistry, verifier);
        var attResult = await attestationVerifier.VerifyAsync(attestation);
        Assert.True(attResult.Valid, $"attestation verify failed: {attResult.Reason}");

        // ── 7. Bundle + presentation
        //   The presenter authenticates by signing the canonical challenge with the holder
        //   controller key; HolderPublicKey re-derives to didDoc.Id.
        var bundle = new AttestationBundle(new[] { attestation });
        var presentation = new Presentation
        {
            Holder = didDoc.Id,
            Disclosures = new[] { bundle.DisclosureFor(0) },
            Binding = new PresentationBinding
            {
                Verifier = new DidId("did:tessera:verifier-app"),
                SessionNonce = RandomBytes(16),
                AsOfRevocationEpoch = 0,
                Chain = "solana",
                HolderSignature = Array.Empty<byte>(), // placeholder, replaced below
                HolderPublicKey = holderPub,
                CreatedAt = DateTimeOffset.UtcNow,
            },
        };
        presentation = presentation with
        {
            Binding = presentation.Binding with
            {
                HolderSignature = Ed25519.Sign(holderPriv, PresentationChallenge.Compute(presentation)),
            },
        };

        var presentationVerifier = new PresentationVerifier(attestationVerifier, verifier);
        var result = await presentationVerifier.VerifyAsync(presentation, bundle.Root);

        Assert.True(result.Valid, $"presentation verify failed: {result.Reason}");
    }

    [Fact]
    public async Task FullFlow_TamperedAttestationSignature_FailsVerification()
    {
        // Same setup but a single bit flip in the issuer signature must invalidate the chain.
        var (_, holderPub) = Ed25519.GenerateKeypair();
        using var issuerSigner = new Ed25519IssuerSigner(Ed25519.GenerateKeypair().PrivateKey);
        var verifier = new Ed25519Verifier();

        var didService = new DidService(new InMemoryDidStore(), verifier);
        var didDoc = await didService.CreateAsync(holderPub);

        var issuerDid = new DidId("did:tessera:issuer-tamper-test");
        var registry = new InMemoryIssuerRegistry();
        registry.Register(new IssuerRecord
        {
            Did = issuerDid,
            PublicKey = issuerSigner.PublicKey,
            Algorithm = "ed25519",
            SchemaUri = "https://schemas.tessera/attestation/v1",
            Active = true,
        });

        var issuer = new AttestationIssuer(issuerDid, issuerSigner);
        var attestation = issuer.Issue(
            AttestationTypes.HumanVerified,
            didDoc.Id,
            new AttestationPayload { Method = "civic" });

        var tamperedSig = (byte[])attestation.Signature.Value.Clone();
        tamperedSig[0] ^= 0x01;
        var tampered = attestation with
        {
            Signature = attestation.Signature with { Value = tamperedSig },
        };

        var attVerifier = new AttestationVerifier(registry, verifier);
        var result = await attVerifier.VerifyAsync(tampered);

        Assert.False(result.Valid);
        Assert.Equal("bad_signature", result.Reason);
    }

    [Fact]
    public async Task FullFlow_WalletBindingWithWrongSignature_Rejected()
    {
        var (_, holderPub) = Ed25519.GenerateKeypair();
        var (_, walletPub) = Ed25519.GenerateKeypair();
        var (attackerPriv, _) = Ed25519.GenerateKeypair();
        var verifier = new Ed25519Verifier();

        var didService = new DidService(new InMemoryDidStore(), verifier);
        var didDoc = await didService.CreateAsync(holderPub);

        var bindingRequest = new WalletBindingRequest
        {
            Chain = "solana",
            Address = Base58.Encode(walletPub), // a genuinely-controlled address, so the SIGNATURE is what's rejected
            WalletPublicKey = walletPub,
            Nonce = RandomBytes(16),
            Expiry = DateTimeOffset.UtcNow.AddMinutes(5),
            Signature = Array.Empty<byte>(),
        };
        var challenge = DidService.BuildWalletChallenge(didDoc.Id, bindingRequest);

        // Attacker signs the right challenge with the wrong key.
        var forgedSig = Ed25519.Sign(attackerPriv, challenge);
        var forgedRequest = bindingRequest with { Signature = forgedSig };

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => didService.BindWalletAsync(didDoc.Id, forgedRequest));
    }

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        System.Security.Cryptography.RandomNumberGenerator.Fill(b);
        return b;
    }
}
