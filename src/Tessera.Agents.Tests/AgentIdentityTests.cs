using Tessera.Attestations;
using Tessera.Core;
using Tessera.Signing;

namespace Tessera.Agents.Tests;

public class AgentIdentityTests
{
    private static (InMemoryIssuerRegistry Registry, DidId Principal, Ed25519IssuerSigner Signer) NewPrincipal()
    {
        var (signer, pub) = Ed25519IssuerSigner.Generate();
        var principalDid = DidId.FromControllerKey(pub);
        var registry = new InMemoryIssuerRegistry();
        registry.Register(new IssuerRecord
        {
            Did = principalDid,
            PublicKey = pub,
            Algorithm = signer.Algorithm,
            SchemaUri = AgentIdentity.DefaultSchema,
            Active = true,
        });
        return (registry, principalDid, signer);
    }

    private static DidId FreshAgent()
    {
        var (_, pub) = Ed25519.GenerateKeypair();
        return DidId.FromControllerKey(pub);
    }

    [Fact]
    public async Task IssueAndVerify_Binding_RoundTrips_WithScopes()
    {
        var (registry, principal, signer) = NewPrincipal();
        var agent = FreshAgent();

        var attestation = AgentIdentity.IssueBinding(
            principal, signer, agent, scopes: ["read", "write"], validity: TimeSpan.FromDays(30));

        var result = await AgentIdentity.VerifyBindingAsync(
            attestation, registry, new Ed25519Verifier(), expectedAgent: agent, expectedPrincipal: principal);

        Assert.True(result.Valid, result.Reason);
        Assert.Equal(agent, result.Binding!.Agent);
        Assert.Equal(principal, result.Binding.Principal);
        Assert.Equal(new[] { "read", "write" }, result.Binding.Scopes);
    }

    [Fact]
    public async Task Verify_Fails_OnWrongExpectedAgent()
    {
        var (registry, principal, signer) = NewPrincipal();
        var attestation = AgentIdentity.IssueBinding(principal, signer, FreshAgent());

        var result = await AgentIdentity.VerifyBindingAsync(
            attestation, registry, new Ed25519Verifier(), expectedAgent: FreshAgent());

        Assert.False(result.Valid);
        Assert.Equal("agent_mismatch", result.Reason);
    }

    [Fact]
    public async Task Verify_Fails_OnTamperedSubject()
    {
        var (registry, principal, signer) = NewPrincipal();
        var attestation = AgentIdentity.IssueBinding(principal, signer, FreshAgent());
        var tampered = attestation with { Subject = FreshAgent() }; // breaks the issuer signature

        var result = await AgentIdentity.VerifyBindingAsync(tampered, registry, new Ed25519Verifier());

        Assert.False(result.Valid);
        Assert.Equal("bad_signature", result.Reason);
    }

    [Fact]
    public async Task Verify_Fails_OnWrongType()
    {
        var (registry, principal, signer) = NewPrincipal();
        var attestation = AgentIdentity.IssueBinding(principal, signer, FreshAgent()) with { Type = AttestationTypes.PhoneVerified };

        var result = await AgentIdentity.VerifyBindingAsync(attestation, registry, new Ed25519Verifier());

        Assert.False(result.Valid);
        Assert.Equal("not_agent_identity", result.Reason);
    }
}
