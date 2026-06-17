namespace Tessera.Attestations;

using Tessera.Core;

/// <summary>
/// CRYPTOGRAPHIC verification of a holder's presentation ONLY: the holder signature on the binding
/// verifies against the key the holder DID derives from, each disclosed attestation verifies against
/// its issuer, and each Merkle inclusion path hashes to the <paramref name="expectedAnchorRoot"/>
/// supplied by the caller.
/// </summary>
/// <remarks>
/// This class does NOT enforce revocation freshness, presentation freshness, verifier/audience
/// binding, or that <c>expectedAnchorRoot</c> is the CURRENT on-chain root for the holder DID — it
/// trusts the root it is handed. Those checks are the caller's responsibility; use
/// <see cref="Tessera.Sdk.Verifier"/> for full end-to-end verification (it resolves the live anchor,
/// rejects stale <c>AsOfRevocationEpoch</c>, and enforces the freshness window before delegating the
/// cryptographic content here). Calling this class directly with a cached or holder-supplied root
/// skips revocation and accepts a revoked or stale credential.
/// </remarks>
public sealed class PresentationVerifier
{
    private readonly AttestationVerifier _attestationVerifier;
    private readonly ISignatureVerifier _signatureVerifier;

    public PresentationVerifier(AttestationVerifier attestationVerifier, ISignatureVerifier signatureVerifier)
    {
        _attestationVerifier = attestationVerifier ?? throw new ArgumentNullException(nameof(attestationVerifier));
        _signatureVerifier = signatureVerifier ?? throw new ArgumentNullException(nameof(signatureVerifier));
    }

    /// <summary>
    /// Verify the cryptographic content of a presentation, INCLUDING the holder's signature on the
    /// binding (the presenter is proven to control the holder DID). The caller still confirms that
    /// <paramref name="expectedAnchorRoot"/> is the current on-chain root for the holder DID at the
    /// presented revocation epoch — see <see cref="Tessera.Sdk.Verifier"/>.
    /// </summary>
    public async Task<VerificationResult> VerifyAsync(
        Presentation presentation,
        ReadOnlyMemory<byte> expectedAnchorRoot,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(presentation);

        if (presentation.Disclosures.Count == 0)
            return VerificationResult.Fail("no_disclosures");

        // ── Holder authentication ────────────────────────────────────────────
        // The presenter must prove control of the holder DID: a 32-byte controller key that
        // re-derives to Holder, plus a signature over the canonical presentation challenge.
        var binding = presentation.Binding;
        if (binding.HolderPublicKey is not { Length: 32 })
            return VerificationResult.Fail("holder_key_missing");

        DidId derivedHolder;
        try { derivedHolder = DidId.FromControllerKey(binding.HolderPublicKey); }
        catch (ArgumentException) { return VerificationResult.Fail("holder_key_invalid"); }
        if (derivedHolder != presentation.Holder)
            return VerificationResult.Fail("holder_key_mismatch");

        if (binding.HolderSignature is null || binding.HolderSignature.Length == 0)
            return VerificationResult.Fail("holder_signature_missing");

        var challenge = PresentationChallenge.Compute(presentation);
        if (!_signatureVerifier.Verify(binding.HolderPublicKey, challenge, binding.HolderSignature))
            return VerificationResult.Fail("holder_signature_invalid");

        foreach (var disclosure in presentation.Disclosures)
        {
            var sigResult = await _attestationVerifier.VerifyAsync(disclosure.Attestation, ct).ConfigureAwait(false);
            if (!sigResult.Valid) return sigResult;

            if (disclosure.Attestation.Subject != presentation.Holder)
                return VerificationResult.Fail("subject_mismatch");

            var canonical = AttestationCanonical.BuildSigningInput(disclosure.Attestation);
            var expectedLeafHash = MerkleTree.HashLeaf(canonical);
            if (!disclosure.MerkleProof.LeafHash.AsSpan().SequenceEqual(expectedLeafHash))
                return VerificationResult.Fail("leaf_hash_mismatch");

            if (!disclosure.MerkleProof.Root.AsSpan().SequenceEqual(expectedAnchorRoot.Span))
                return VerificationResult.Fail("root_not_anchored");

            if (!MerkleTree.VerifyInclusion(
                    disclosure.MerkleProof.LeafHash,
                    disclosure.MerkleProof.Path,
                    disclosure.MerkleProof.LeafIndex,
                    expectedAnchorRoot.Span))
                return VerificationResult.Fail("merkle_path_invalid");
        }

        return VerificationResult.Ok();
    }
}
