namespace Tessera.Attestations;

using Tessera.Core;

/// <summary>
/// The canonical byte string a holder signs to authenticate a <see cref="Presentation"/>.
/// It binds the presentation to a specific holder DID, verifier (audience), session nonce,
/// revocation epoch, chain, creation timestamp, and the exact set of disclosed leaf hashes.
/// </summary>
/// <remarks>
/// <para>
/// Both sides compute the identical bytes: the holder when producing
/// <see cref="PresentationBinding.HolderSignature"/>, and the verifier when checking it. Every
/// field is length-framed (counts and lengths are written before variable-length data, strings via
/// <see cref="BinaryWriter"/>'s 7-bit length prefix), so the encoding is injective — no two distinct
/// bindings can collide onto the same signed bytes.
/// </para>
/// <para>
/// Binding the disclosed leaf hashes means a captured signature cannot be re-used over a different
/// set of attestations, and authenticating the verifier/nonce/epoch defeats cross-verifier replay,
/// session replay, and stale-revocation replay.
/// </para>
/// </remarks>
public static class PresentationChallenge
{
    /// <summary>Domain-separation tag, versioned so the format can evolve without ambiguity.</summary>
    public const string Domain = "Tessera/v1/presentation";

    public static byte[] Compute(
        DidId holder,
        DidId verifier,
        ReadOnlySpan<byte> sessionNonce,
        ulong asOfRevocationEpoch,
        string chain,
        DateTimeOffset createdAt,
        IReadOnlyList<byte[]> disclosedLeafHashes)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(disclosedLeafHashes);

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write(Domain);
        w.Write(holder.Value);
        w.Write(verifier.Value);
        w.Write(sessionNonce.Length);
        w.Write(sessionNonce);
        w.Write(asOfRevocationEpoch);
        w.Write(chain);
        w.Write(createdAt.ToUnixTimeSeconds());
        w.Write(disclosedLeafHashes.Count);
        foreach (var leafHash in disclosedLeafHashes)
        {
            var hash = leafHash ?? Array.Empty<byte>();
            w.Write(hash.Length);
            w.Write(hash);
        }
        w.Flush();
        return ms.ToArray();
    }

    /// <summary>
    /// Convenience overload: compute the challenge directly from a <see cref="Presentation"/>'s
    /// binding and disclosures. Used by the verifier.
    /// </summary>
    public static byte[] Compute(Presentation presentation)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        var binding = presentation.Binding;
        var leafHashes = new List<byte[]>(presentation.Disclosures.Count);
        foreach (var disclosure in presentation.Disclosures)
            leafHashes.Add(disclosure.MerkleProof.LeafHash);

        return Compute(
            presentation.Holder,
            binding.Verifier,
            binding.SessionNonce,
            binding.AsOfRevocationEpoch,
            binding.Chain,
            binding.CreatedAt,
            leafHashes);
    }
}
