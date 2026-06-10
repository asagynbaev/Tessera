using Tessera.Chains;

namespace Tessera.Examples.PermissionedToken;

/// <summary>
/// In-memory <see cref="IAllowlistGateway"/> for the reference scenario and its tests. Records the
/// set of admitted addresses; the on-chain equivalent is <c>EvmAllowlistGateway</c> driving the
/// <c>Allowlist</c> contract. Demonstrates the A2 seam without a live chain.
/// </summary>
public sealed class InMemoryAllowlistGateway : IAllowlistGateway
{
    private readonly HashSet<string> _allowed = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    public string ChainId => "memory";

    public Task AddAsync(string address, CancellationToken ct = default)
    {
        lock (_lock) _allowed.Add(address);
        return Task.CompletedTask;
    }

    public Task RevokeAsync(string address, CancellationToken ct = default)
    {
        lock (_lock) _allowed.Remove(address);
        return Task.CompletedTask;
    }

    /// <summary>Whether an address is currently admitted.</summary>
    public bool IsAllowed(string address)
    {
        lock (_lock) return _allowed.Contains(address);
    }
}
