using Tessera.Attestations;
using Tessera.Core;
using Tessera.Sdk;
using Tessera.Signing;

namespace Tessera.Sdk.Tests;

public class IssuancePipelineTests
{
    private static Issuer NewIssuer(out Ed25519IssuerSigner signer, string did = "did:tessera:kyc-issuer")
    {
        var (priv, _) = Ed25519.GenerateKeypair();
        signer = new Ed25519IssuerSigner(priv);
        return new Issuer(new DidId(did), signer);
    }

    [Fact]
    public async Task IssueFor_SignsAllDrafts_RegistersIssuer_AndIsVerifiable()
    {
        using var signer = new Ed25519IssuerSigner(Ed25519.GenerateKeypair().Item1);
        var issuer = new Issuer(new DidId("did:tessera:kyc-issuer"), signer);
        var registry = new InMemoryIssuerRegistry();

        var source = new InMemoryAttestationSource(
            "kyc.test",
            new AttestationDraft(AttestationTypes.HumanVerified, new AttestationPayload { Method = "kyc_provider" }, TimeSpan.FromDays(30)),
            new AttestationDraft(AttestationTypes.PhoneVerified, new AttestationPayload { Method = "kyc_provider" }));

        var pipeline = new IssuancePipeline(issuer, new[] { source }, registry, "https://schemas.tessera/kyc/v1");
        var subject = new DidId("did:tessera:subject-1");

        var issued = await pipeline.IssueForAsync(new SubjectContext { Subject = subject });

        // Both drafts signed for the subject under the configured schema.
        Assert.Equal(2, issued.Count);
        Assert.All(issued, a => Assert.Equal(subject, a.Subject));
        Assert.All(issued, a => Assert.Equal(issuer.Did, a.Issuer));
        Assert.All(issued, a => Assert.Equal("https://schemas.tessera/kyc/v1", a.Schema));
        Assert.Equal(AttestationTypes.HumanVerified, issued[0].Type);
        Assert.Equal(AttestationTypes.PhoneVerified, issued[1].Type);

        // Validity maps to expiry; zero/absent validity means no expiry.
        Assert.NotNull(issued[0].ExpiresAt);
        Assert.Null(issued[1].ExpiresAt);

        // Issuer was published to the registry.
        var record = await registry.ResolveAsync(issuer.Did);
        Assert.NotNull(record);
        Assert.True(record!.Active);
        Assert.Equal(signer.PublicKey, record.PublicKey);
        Assert.Equal("https://schemas.tessera/kyc/v1", record.SchemaUri);

        // End-to-end: every issued attestation verifies against the now-registered issuer.
        var verifier = new Verifier(new VerifierOptions
        {
            IssuerRegistry = registry,
            SignatureVerifier = new Ed25519Verifier(),
        });
        foreach (var att in issued)
            Assert.True((await verifier.VerifyAttestationAsync(att)).Valid);
    }

    [Fact]
    public async Task IssueFor_WithoutRegistrar_DoesNotRegister()
    {
        using var signer = new Ed25519IssuerSigner(Ed25519.GenerateKeypair().Item1);
        var issuer = new Issuer(new DidId("did:tessera:kyc-issuer"), signer);
        var registry = new InMemoryIssuerRegistry();

        var source = new InMemoryAttestationSource("kyc.test",
            new AttestationDraft(AttestationTypes.HumanVerified, new AttestationPayload { Method = "x" }));
        var pipeline = new IssuancePipeline(issuer, new[] { source });  // no registrar

        var issued = await pipeline.IssueForAsync(new SubjectContext { Subject = new DidId("did:tessera:s") });

        Assert.Single(issued);
        Assert.Null(await registry.ResolveAsync(issuer.Did));  // never registered
    }

    [Fact]
    public async Task IssueFor_UsesSubjectContextParameters()
    {
        using var signer = new Ed25519IssuerSigner(Ed25519.GenerateKeypair().Item1);
        var issuer = new Issuer(new DidId("did:tessera:issuer"), signer);

        var source = new InMemoryAttestationSource("kyc.test", ctx =>
            new[] { new AttestationDraft($"tier_{ctx.Get("tier")}", new AttestationPayload { Method = "x" }) });
        var pipeline = new IssuancePipeline(issuer, new[] { source });

        var issued = await pipeline.IssueForAsync(new SubjectContext
        {
            Subject = new DidId("did:tessera:s"),
            Parameters = new Dictionary<string, string> { ["tier"] = "gold" },
        });

        Assert.Equal("tier_gold", Assert.Single(issued).Type);
    }

    [Fact]
    public async Task IssueFor_EmptySource_ProducesNothing()
    {
        using var signer = new Ed25519IssuerSigner(Ed25519.GenerateKeypair().Item1);
        var issuer = new Issuer(new DidId("did:tessera:issuer"), signer);
        var source = new InMemoryAttestationSource("empty", _ => Array.Empty<AttestationDraft>());
        var pipeline = new IssuancePipeline(issuer, new[] { source });

        var issued = await pipeline.IssueForAsync(new SubjectContext { Subject = new DidId("did:tessera:s") });
        Assert.Empty(issued);
    }

    [Fact]
    public void Ctor_Rejects_EmptySources()
    {
        using var signer = new Ed25519IssuerSigner(Ed25519.GenerateKeypair().Item1);
        var issuer = new Issuer(new DidId("did:tessera:issuer"), signer);
        Assert.Throws<ArgumentException>(() => new IssuancePipeline(issuer, Array.Empty<IAttestationSource>()));
    }
}
