namespace Tessera.Attestations;

using Tessera.Core;

/// <summary>
/// What a holder hands to a verifier. Contains the attestation(s) being disclosed,
/// the Merkle path proving inclusion in the holder's anchored attestation root,
/// optional selective-disclosure proofs over commitments, and a freshness nonce
/// signed by the holder to bind the presentation to a specific verifier + session.
/// </summary>
public sealed record Presentation
{
    public required DidId Holder { get; init; }
    public required IReadOnlyList<AttestationDisclosure> Disclosures { get; init; }
    public required PresentationBinding Binding { get; init; }
}

public sealed record AttestationDisclosure
{
    public required Attestation Attestation { get; init; }
    public required MerkleInclusionProof MerkleProof { get; init; }
    public byte[]? PredicateProof { get; init; }
}

public sealed record MerkleInclusionProof
{
    public required byte[] LeafHash { get; init; }
    public required IReadOnlyList<byte[]> Path { get; init; }
    public required byte[] Root { get; init; }
    public required ulong LeafIndex { get; init; }
}

/// <summary>
/// Holder-signed envelope tying this presentation to a specific verifier, session, and chain epoch.
/// Prevents replay across verifiers and across revocation states.
/// </summary>
/// <remarks>
/// <see cref="HolderSignature"/> is an Ed25519 signature over <see cref="PresentationChallenge"/>
/// (which covers the verifier, nonce, epoch, chain, timestamp, and disclosed leaf hashes), made with
/// the holder's controller private key. <see cref="HolderPublicKey"/> is the matching controller
/// public key; the verifier confirms <c>DidId.FromControllerKey(HolderPublicKey) == Holder</c> and
/// then checks the signature, authenticating the presenter as the holder without trusting any store.
/// </remarks>
public sealed record PresentationBinding
{
    public required DidId Verifier { get; init; }
    public required byte[] SessionNonce { get; init; }
    public required ulong AsOfRevocationEpoch { get; init; }
    public required string Chain { get; init; }
    public required byte[] HolderSignature { get; init; }

    /// <summary>The holder's 32-byte Ed25519 controller public key; must re-derive to <c>Holder</c>.</summary>
    public required byte[] HolderPublicKey { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
}
