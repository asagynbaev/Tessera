using Tessera.Attestations;
using Tessera.Core;

namespace Tessera.Agents;

/// <summary>
/// A verified agent→principal binding: the principal (the attestation's issuer) asserts that the agent
/// (the subject) acts on its behalf, optionally within a set of scopes.
/// </summary>
public sealed record AgentBinding
{
    /// <summary>The agent's DID (subject) — typically a <c>did:tessera</c> derived from the agent's controller key.</summary>
    public required DidId Agent { get; init; }

    /// <summary>The principal's DID (issuer) — the human or organization the agent acts for.</summary>
    public required DidId Principal { get; init; }

    /// <summary>Scopes the principal granted the agent (may be empty).</summary>
    public IReadOnlyList<string> Scopes { get; init; } = Array.Empty<string>();
}

/// <summary>Outcome of verifying an <c>agent_identity</c> attestation as an agent→principal binding.</summary>
public sealed record AgentBindingResult
{
    public required bool Valid { get; init; }

    /// <summary>Machine-readable failure reason, or null when valid.</summary>
    public string? Reason { get; init; }

    /// <summary>The extracted binding when <see cref="Valid"/> is true.</summary>
    public AgentBinding? Binding { get; init; }

    internal static AgentBindingResult Fail(string reason) => new() { Valid = false, Reason = reason };
}

/// <summary>
/// Issue and verify the <c>agent_identity</c> attestation that binds an autonomous agent to the
/// principal it acts for. The principal is the attestation issuer; the agent is the subject. This is
/// the identity half of a "verified agent": pair it with an RFC 9421 HTTP signature
/// (<see cref="HttpMessageSignatures.HttpMessageSigner"/>) whose signer DID equals
/// <see cref="AgentBinding.Agent"/> to prove the request came from that agent.
/// </summary>
public static class AgentIdentity
{
    /// <summary>Claim key under which granted scopes are stored (space-separated).</summary>
    public const string ScopeClaim = "scope";

    /// <summary>Default schema URI for an agent-identity attestation.</summary>
    public const string DefaultSchema = "https://schemas.tessera/agent-identity/v1";

    /// <summary>
    /// Issue an <c>agent_identity</c> attestation: the <paramref name="principal"/> (signing with
    /// <paramref name="principalSigner"/>) attests that <paramref name="agent"/> acts on its behalf.
    /// </summary>
    public static Attestation IssueBinding(
        DidId principal,
        IIssuerSigner principalSigner,
        DidId agent,
        IEnumerable<string>? scopes = null,
        TimeSpan? validity = null,
        string schema = DefaultSchema,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(principalSigner);

        var scopeList = scopes?
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s.Trim())
            .ToArray() ?? Array.Empty<string>();

        var claims = scopeList.Length > 0
            ? new Dictionary<string, object> { [ScopeClaim] = string.Join(' ', scopeList) }
            : null;

        var payload = new AttestationPayload { Method = "agent-identity", Claims = claims };
        var issuer = new AttestationIssuer(principal, principalSigner, clock);
        return issuer.Issue(AttestationTypes.AgentIdentity, agent, payload, validity, schema);
    }

    /// <summary>
    /// Verify that <paramref name="attestation"/> is a valid <c>agent_identity</c> binding: its issuer
    /// signature checks out against the registry, its type is correct, and it matches the optional
    /// expected agent / principal. Returns the extracted <see cref="AgentBinding"/> on success.
    /// </summary>
    public static async Task<AgentBindingResult> VerifyBindingAsync(
        Attestation attestation,
        IIssuerRegistry registry,
        ISignatureVerifier signatureVerifier,
        DidId? expectedAgent = null,
        DidId? expectedPrincipal = null,
        TimeProvider? clock = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(attestation);

        if (attestation.Type != AttestationTypes.AgentIdentity)
            return AgentBindingResult.Fail("not_agent_identity");

        var verifier = new AttestationVerifier(registry, signatureVerifier, clock);
        var result = await verifier.VerifyAsync(attestation, ct).ConfigureAwait(false);
        if (!result.Valid)
            return AgentBindingResult.Fail(result.Reason ?? "invalid_attestation");

        if (expectedAgent is { } agent && attestation.Subject != agent)
            return AgentBindingResult.Fail("agent_mismatch");
        if (expectedPrincipal is { } principal && attestation.Issuer != principal)
            return AgentBindingResult.Fail("principal_mismatch");

        return new AgentBindingResult
        {
            Valid = true,
            Binding = new AgentBinding
            {
                Agent = attestation.Subject,
                Principal = attestation.Issuer,
                Scopes = ExtractScopes(attestation.Payload),
            },
        };
    }

    private static IReadOnlyList<string> ExtractScopes(AttestationPayload payload)
    {
        if (payload.Claims is { } claims &&
            claims.TryGetValue(ScopeClaim, out var value) &&
            value?.ToString() is { Length: > 0 } scope)
        {
            return scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        return Array.Empty<string>();
    }
}
