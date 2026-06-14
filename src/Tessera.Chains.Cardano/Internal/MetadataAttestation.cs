using System.Buffers.Binary;
using CardanoSharp.Wallet.Extensions.Models;
using CardanoSharp.Wallet.Models.Keys;

namespace Tessera.Chains.Cardano.Internal;

/// <summary>
/// The controller-authored authentication envelope embedded in Metadata-mode auxiliary data.
/// <para>
/// The transaction-metadata label is a shared, permissionless CIP-10 namespace: ANY address can
/// publish a tx under it with an arbitrary <c>{ did, root, epoch }</c> body. Reads therefore cannot
/// trust the payload on the strength of the label alone. To close this, every Metadata-mode write
/// additionally carries the controller's Ed25519 public key (<c>pk</c>) and a detached signature
/// (<c>sig</c>) over the canonical message <c>did_hash ‖ root ‖ epoch</c>. On read the adapter both
/// (a) requires the tx to originate from the controller's address, and (b) verifies this signature
/// binds the payload to the controller key the caller configured.
/// </para>
/// </summary>
internal static class MetadataAttestation
{
    /// <summary>JSON keys for the embedded controller public key and signature (hex, lower-case).</summary>
    public const string PubKeyField = "pk";
    public const string SignatureField = "sig";

    /// <summary>
    /// Canonical signed message: <c>did_hash (32) ‖ attestation_root (32) ‖ epoch (8, big-endian)</c>.
    /// Big-endian, fixed-width fields make the encoding unambiguous and independent of JSON shape.
    /// </summary>
    public static byte[] Message(byte[] didHash, byte[] attestationRoot, ulong epoch)
    {
        var msg = new byte[didHash.Length + attestationRoot.Length + 8];
        Buffer.BlockCopy(didHash, 0, msg, 0, didHash.Length);
        Buffer.BlockCopy(attestationRoot, 0, msg, didHash.Length, attestationRoot.Length);
        BinaryPrimitives.WriteUInt64BigEndian(msg.AsSpan(didHash.Length + attestationRoot.Length), epoch);
        return msg;
    }

    /// <summary>Sign the canonical message with the controller key (raw 64-byte Ed25519 signature).</summary>
    public static byte[] Sign(ControllerKey key, byte[] didHash, byte[] attestationRoot, ulong epoch)
        => key.Sign(Message(didHash, attestationRoot, epoch));

    /// <summary>
    /// Verify that <paramref name="signatureHex"/> is a valid controller signature over
    /// <c>(didHash‖root‖epoch)</c> produced by <paramref name="pubKeyHex"/>. Returns false on any
    /// malformed input rather than throwing, so a single poisoned metadata tx cannot break reads.
    /// </summary>
    public static bool Verify(string? pubKeyHex, string? signatureHex, byte[] didHash, byte[] attestationRoot, ulong epoch)
    {
        if (string.IsNullOrEmpty(pubKeyHex) || string.IsNullOrEmpty(signatureHex)) return false;
        byte[] pk, sig;
        try
        {
            pk = Convert.FromHexString(pubKeyHex);
            sig = Convert.FromHexString(signatureHex);
        }
        catch (FormatException) { return false; }
        if (pk.Length != 32 || sig.Length != 64) return false;

        try
        {
            // Ed25519 verification ignores the chaincode; an empty one keeps the key-only path clean.
            return new PublicKey(pk, Array.Empty<byte>()).Verify(Message(didHash, attestationRoot, epoch), sig);
        }
        catch (Exception) { return false; }
    }

    /// <summary>blake2b-224 key hash of an embedded 32-byte Ed25519 public key, or null if malformed.</summary>
    public static byte[]? KeyHash(string? pubKeyHex)
    {
        if (string.IsNullOrEmpty(pubKeyHex)) return null;
        byte[] pk;
        try { pk = Convert.FromHexString(pubKeyHex); }
        catch (FormatException) { return null; }
        return pk.Length == 32 ? CardanoSharp.Wallet.Utilities.HashUtility.Blake2b224(pk) : null;
    }
}
