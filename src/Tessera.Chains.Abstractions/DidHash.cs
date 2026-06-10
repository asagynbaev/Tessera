namespace Tessera.Chains;

using System.Security.Cryptography;
using System.Text;
using Tessera.Core;

/// <summary>
/// Canonical DID-hash derivation shared by every chain anchor. A DID hashes to the
/// same 32 bytes on every backend — Solana, EVM, Stellar — so the same identity keys
/// the same on-chain record regardless of which chain it is anchored to.
/// </summary>
/// <remarks>
/// This is the chain-side hash used to key on-chain anchor records. It is unrelated to
/// the attestation Merkle root (which is domain-separated SHA-256 over the bundle).
/// </remarks>
public static class DidHash
{
    /// <summary>SHA-256 over the UTF-8 bytes of the DID string. Always 32 bytes.</summary>
    public static byte[] Compute(DidId did)
    {
        if (string.IsNullOrEmpty(did.Value))
            throw new ArgumentException("DID has no value.", nameof(did));
        return SHA256.HashData(Encoding.UTF8.GetBytes(did.Value));
    }
}
