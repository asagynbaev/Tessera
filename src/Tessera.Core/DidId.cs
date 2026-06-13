namespace Tessera.Core;

using System.Security.Cryptography;

/// <summary>
/// A decentralized identifier. Opaque string of the form <c>did:tessera:&lt;identifier&gt;</c>.
/// </summary>
public readonly record struct DidId(string Value)
{
    public const string MethodPrefix = "did:tessera:";

    public bool IsWellFormed =>
        !string.IsNullOrEmpty(Value)
        && Value.StartsWith(MethodPrefix, StringComparison.Ordinal)
        && Value.Length > MethodPrefix.Length;

    public override string ToString() => Value;

    public static DidId Parse(string value)
    {
        var did = new DidId(value);
        if (!did.IsWellFormed)
            throw new FormatException($"Not a well-formed did:tessera identifier: '{value}'.");
        return did;
    }

    /// <summary>
    /// Derive the DID identifier deterministically from its Ed25519 controller public key:
    /// <c>did:tessera:base58(sha-256(pubkey || "v1"))</c>. The identifier is a one-way function of
    /// the key, so anyone holding the key (and only them) can produce a signature that re-derives to
    /// this DID — this is the single source of truth for binding a key to an identifier. A verifier
    /// can therefore authenticate a holder from a self-supplied public key without trusting any store.
    /// </summary>
    /// <remarks>
    /// Requires exactly 32 bytes (Ed25519). The fixed length is also a hard bound on the stack buffer,
    /// so an attacker-supplied key in a presentation cannot trigger an oversized <c>stackalloc</c>.
    /// </remarks>
    public static DidId FromControllerKey(ReadOnlySpan<byte> controllerPublicKey)
    {
        if (controllerPublicKey.Length != 32)
            throw new ArgumentException("Controller public key must be 32 bytes (Ed25519).", nameof(controllerPublicKey));

        // Domain-separated digest so the same pubkey under a different DID method produces a
        // different identifier.
        Span<byte> buf = stackalloc byte[34];
        controllerPublicKey.CopyTo(buf);
        buf[32] = (byte)'v';
        buf[33] = (byte)'1';
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(buf, digest);
        return new DidId(MethodPrefix + Base58.Encode(digest));
    }
}
