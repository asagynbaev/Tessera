namespace Tessera.Attestations;

using System.Collections.Concurrent;
using Tessera.Core;

public sealed class InMemoryIssuerRegistry : IIssuerRegistry, IIssuerRegistrar
{
    private readonly ConcurrentDictionary<DidId, IssuerRecord> _records = new();

    public void Register(IssuerRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        _records[record.Did] = record;
    }

    /// <summary>Write-side <see cref="IIssuerRegistrar"/> entry point; wraps <see cref="Register"/>.</summary>
    public Task RegisterAsync(IssuerRecord record, CancellationToken ct = default)
    {
        Register(record);
        return Task.CompletedTask;
    }

    public Task<IssuerRecord?> ResolveAsync(DidId issuer, CancellationToken ct = default)
        => Task.FromResult(_records.TryGetValue(issuer, out var r) ? r : null);
}
