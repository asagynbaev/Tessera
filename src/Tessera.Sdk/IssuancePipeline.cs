using Tessera.Attestations;
using Tessera.Core;

namespace Tessera.Sdk;

/// <summary>
/// Generic issuance pipeline: pulls <see cref="AttestationDraft"/>s from one or more
/// <see cref="IAttestationSource"/>s, signs each with the configured <see cref="Issuer"/>, and
/// (optionally) ensures the issuer is published to an <see cref="IIssuerRegistrar"/> so verifiers
/// can resolve it. Domain- and provider-neutral: any source plugs in without changes here.
/// </summary>
/// <remarks>
/// The pipeline does not anchor or bundle — the holder collects the returned attestations into
/// an <see cref="AttestationBundle"/> and anchors its root via <c>IChainAnchor</c>.
/// </remarks>
public sealed class IssuancePipeline
{
    /// <summary>Default schema URI used when none is supplied (matches <see cref="AttestationIssuer"/>'s default).</summary>
    public const string DefaultSchemaUri = "https://schemas.tessera/attestation/v1";

    private readonly Issuer _issuer;
    private readonly IReadOnlyList<IAttestationSource> _sources;
    private readonly IIssuerRegistrar? _registrar;
    private readonly string _schemaUri;
    private int _registered;

    /// <param name="issuer">The signing issuer facade.</param>
    /// <param name="sources">Attestation sources to resolve drafts from, in order.</param>
    /// <param name="registrar">
    /// Optional write-side issuer registry. When supplied, the issuer record is published once
    /// (lazily, on first issuance) so verifiers can resolve the issuer.
    /// </param>
    /// <param name="schemaUri">Schema URI stamped on issued attestations and the issuer record.</param>
    public IssuancePipeline(
        Issuer issuer,
        IEnumerable<IAttestationSource> sources,
        IIssuerRegistrar? registrar = null,
        string? schemaUri = null)
    {
        _issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        ArgumentNullException.ThrowIfNull(sources);
        _sources = sources.ToList();
        if (_sources.Count == 0) throw new ArgumentException("At least one source is required.", nameof(sources));
        if (_sources.Any(s => s is null)) throw new ArgumentException("Sources must not contain null.", nameof(sources));
        _registrar = registrar;
        _schemaUri = string.IsNullOrWhiteSpace(schemaUri) ? DefaultSchemaUri : schemaUri;
    }

    /// <summary>
    /// Resolve drafts from every source for <paramref name="subject"/> and sign each into a
    /// fully-signed <see cref="Attestation"/>. Ensures the issuer is registered first (if a
    /// registrar was supplied). Sources that return no drafts contribute nothing.
    /// </summary>
    public async Task<IReadOnlyList<Attestation>> IssueForAsync(SubjectContext subject, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(subject);
        await EnsureIssuerRegisteredAsync(ct).ConfigureAwait(false);

        var issued = new List<Attestation>();
        foreach (var source in _sources)
        {
            var drafts = await source.ResolveAsync(subject, ct).ConfigureAwait(false);
            if (drafts is null) continue;
            foreach (var draft in drafts)
            {
                ct.ThrowIfCancellationRequested();
                issued.Add(_issuer.Issue(draft.Type, subject.Subject, draft.Payload, draft.ValidityOrNull, _schemaUri));
            }
        }

        return issued;
    }

    private async Task EnsureIssuerRegisteredAsync(CancellationToken ct)
    {
        if (_registrar is null) return;
        // Register exactly once across concurrent callers.
        if (Interlocked.Exchange(ref _registered, 1) == 1) return;
        try
        {
            await _registrar.RegisterAsync(_issuer.BuildRegistryRecord(_schemaUri), ct).ConfigureAwait(false);
        }
        catch
        {
            Volatile.Write(ref _registered, 0); // allow a later retry if registration failed
            throw;
        }
    }
}
