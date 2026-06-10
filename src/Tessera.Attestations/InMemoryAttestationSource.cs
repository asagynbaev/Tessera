namespace Tessera.Attestations;

/// <summary>
/// In-memory <see cref="IAttestationSource"/> for tests and local composition. Real provider
/// sources (KYC, government registry, ...) live in their own satellite packages — the core
/// ships only this neutral test source.
/// </summary>
public sealed class InMemoryAttestationSource : IAttestationSource
{
    private readonly Func<SubjectContext, IReadOnlyList<AttestationDraft>> _resolver;

    /// <summary>A source that always returns the same drafts regardless of subject.</summary>
    public InMemoryAttestationSource(string sourceId, params AttestationDraft[] drafts)
        : this(sourceId, _ => drafts)
    {
    }

    /// <summary>A source that computes drafts from the subject context.</summary>
    public InMemoryAttestationSource(string sourceId, Func<SubjectContext, IReadOnlyList<AttestationDraft>> resolver)
    {
        ArgumentException.ThrowIfNullOrEmpty(sourceId);
        SourceId = sourceId;
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
    }

    public string SourceId { get; }

    public Task<IReadOnlyList<AttestationDraft>> ResolveAsync(SubjectContext subject, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(subject);
        return Task.FromResult(_resolver(subject));
    }
}
