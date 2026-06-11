using Tessera.Core;

namespace Tessera.Chains.Cardano.Internal;

/// <summary>
/// Pure mapping from decoded on-chain data to the chain-agnostic <see cref="AnchorState"/>, plus
/// the revocation-freshness rule. Kept static and side-effect-free so it is unit-tested directly,
/// mirroring <c>EvmChainAnchor.ToAnchorState</c> / <c>IsRevokedSince</c>.
/// </summary>
internal static class AnchorStateMapper
{
    /// <summary>Map a decoded <c>DidAnchorDatum</c> (+ the anchoring tx's block time) to an <see cref="AnchorState"/>.</summary>
    public static AnchorState ToAnchorState(DidId did, DidAnchorDatumValue datum, DateTimeOffset updatedAt) => new()
    {
        Did = did,
        AttestationRoot = datum.AttestationRoot,
        RevocationEpoch = datum.RevocationEpoch,
        UpdatedAt = updatedAt,
    };

    /// <summary>Map a Metadata-mode record to an <see cref="AnchorState"/>.</summary>
    public static AnchorState ToAnchorState(DidId did, byte[] attestationRoot, ulong revocationEpoch, DateTimeOffset updatedAt) => new()
    {
        Did = did,
        AttestationRoot = attestationRoot,
        RevocationEpoch = revocationEpoch,
        UpdatedAt = updatedAt,
    };

    /// <summary>A presentation anchored at <paramref name="asOfEpoch"/> is stale once the chain epoch moves past it.</summary>
    public static bool IsRevokedSince(ulong currentEpoch, ulong asOfEpoch) => currentEpoch > asOfEpoch;
}
