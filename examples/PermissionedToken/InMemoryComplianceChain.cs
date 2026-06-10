using System.Collections.Concurrent;
using Tessera.Chains;
using Tessera.Core;

namespace Tessera.Examples.PermissionedToken;

/// <summary>
/// In-memory <see cref="IChainAnchor"/> for the reference scenario: stores the attestation root and
/// a monotonically increasing revocation epoch per DID, exactly like the on-chain IdentityRegistry.
/// Used so the end-to-end flow is deterministic without a live chain (the real backend is
/// <c>EvmChainAnchor</c> / <c>SolanaChainAnchor</c>).
/// </summary>
public sealed class InMemoryComplianceChain : IChainAnchor
{
    private readonly ConcurrentDictionary<DidId, AnchorState> _state = new();

    public string ChainId => "memory";

    public Task<AnchorTxResult> AnchorRootAsync(DidId did, byte[] attestationRoot, CancellationToken ct = default)
    {
        _state.AddOrUpdate(
            did,
            _ => new AnchorState { Did = did, AttestationRoot = (byte[])attestationRoot.Clone(), RevocationEpoch = 0, UpdatedAt = DateTimeOffset.UnixEpoch },
            (_, existing) => existing with { AttestationRoot = (byte[])attestationRoot.Clone() });
        return Task.FromResult(new AnchorTxResult("mem-" + did.Value, null, DateTimeOffset.UnixEpoch));
    }

    public Task<AnchorState?> GetAnchorAsync(DidId did, CancellationToken ct = default)
        => Task.FromResult(_state.TryGetValue(did, out var s) ? s : null);

    public Task<AnchorTxResult> BumpRevocationAsync(DidId did, RevocationReason reason, CancellationToken ct = default)
    {
        if (!_state.TryGetValue(did, out var existing))
            throw new InvalidOperationException($"Cannot bump revocation for unanchored DID: {did}.");
        _state[did] = existing with { RevocationEpoch = existing.RevocationEpoch + 1 };
        return Task.FromResult(new AnchorTxResult("mem-revoke-" + did.Value, null, DateTimeOffset.UnixEpoch));
    }

    public Task<bool> IsRevokedSinceAsync(DidId did, ulong asOfEpoch, CancellationToken ct = default)
        => Task.FromResult(_state.TryGetValue(did, out var s) && s.RevocationEpoch > asOfEpoch);
}
