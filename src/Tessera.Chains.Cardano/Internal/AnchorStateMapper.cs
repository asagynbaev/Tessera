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
        // The datum's controller (28-byte payment key hash) is the on-chain owner the validator
        // enforces on every spend. Surface it (lowercase hex) so verifiers can compare it against
        // the DID's expected controller and detect a substituted/squatted anchor.
        Owner = Convert.ToHexString(datum.Controller).ToLowerInvariant(),
    };

    /// <summary>Map a Metadata-mode record to an <see cref="AnchorState"/>.</summary>
    /// <param name="owner">
    /// The authenticated controller key hash (lowercase hex) that signed the metadata attestation,
    /// or null if unknown. In metadata mode the read already authenticates against this controller.
    /// </param>
    public static AnchorState ToAnchorState(DidId did, byte[] attestationRoot, ulong revocationEpoch, DateTimeOffset updatedAt, string? owner = null) => new()
    {
        Did = did,
        AttestationRoot = attestationRoot,
        RevocationEpoch = revocationEpoch,
        UpdatedAt = updatedAt,
        Owner = owner,
    };

    /// <summary>A presentation anchored at <paramref name="asOfEpoch"/> is stale once the chain epoch moves past it.</summary>
    public static bool IsRevokedSince(ulong currentEpoch, ulong asOfEpoch) => currentEpoch > asOfEpoch;
}
