namespace Tessera.Attestations;

/// <summary>
/// Write-side counterpart of <see cref="IIssuerRegistry"/>: publishes an issuer record so that
/// verifiers (reading via <see cref="IIssuerRegistry"/>) can resolve and trust the issuer.
/// Kept separate from the read interface so verifier-side code never gains a write path.
/// </summary>
/// <remarks>
/// Implemented by <c>InMemoryIssuerRegistry</c> and <c>EfCoreIssuerRegistry</c>. The issuance
/// pipeline uses it to ensure the issuer is registered before its attestations are handed out.
/// </remarks>
public interface IIssuerRegistrar
{
    /// <summary>Insert or update the issuer record.</summary>
    Task RegisterAsync(IssuerRecord record, CancellationToken ct = default);
}
