namespace Tessera.Did;

using System.Security.Cryptography;
using Tessera.Core;

/// <summary>
/// Orchestrates DID lifecycle: creation, wallet binding, revocation, document retrieval.
/// </summary>
/// <remarks>
/// Signature verification (Ed25519) is delegated via <see cref="ISignatureVerifier"/> so
/// that hosts can plug in whichever crypto stack they already use. The default
/// <see cref="Ed25519SignatureVerifier"/> uses .NET's built-in primitives where available.
/// </remarks>
public sealed class DidService
{
    private readonly IDidStore _store;
    private readonly ISignatureVerifier _verifier;
    private readonly TimeProvider _clock;

    public DidService(IDidStore store, ISignatureVerifier verifier, TimeProvider? clock = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        _clock = clock ?? TimeProvider.System;
    }

    /// <summary>
    /// Create a new DID derived from the controller's public key. The DID is computed
    /// deterministically: <c>did:tessera:base58(sha-256(pubkey || "v1"))</c>. The caller
    /// cannot choose the identifier — this prevents squatting and ties the identifier
    /// to provable control.
    /// </summary>
    public async Task<DidDocument> CreateAsync(
        ReadOnlyMemory<byte> controllerPublicKey,
        CancellationToken ct = default)
    {
        if (controllerPublicKey.Length != 32)
            throw new ArgumentException("Controller public key must be 32 bytes (Ed25519).", nameof(controllerPublicKey));

        var did = DeriveDidFromKey(controllerPublicKey.Span);
        if (await _store.ExistsAsync(did, ct).ConfigureAwait(false))
            throw new InvalidOperationException($"DID already exists: {did}.");

        var now = _clock.GetUtcNow();
        var publicKeyMultibase = ToMultibaseBase58(controllerPublicKey.Span);
        var doc = new DidDocument
        {
            Id = did,
            Controller = did,
            VerificationMethods = new[]
            {
                new VerificationMethod
                {
                    Id = $"{did}#key-1",
                    Type = "Ed25519VerificationKey2020",
                    PublicKeyMultibase = publicKeyMultibase,
                },
            },
            CreatedAt = now,
            UpdatedAt = now,
            Version = 1,
        };
        await _store.SaveAsync(doc, ct).ConfigureAwait(false);
        return doc;
    }

    public Task<DidDocument?> GetAsync(DidId did, CancellationToken ct = default)
        => _store.GetAsync(did, ct);

    /// <summary>
    /// Bind a wallet to a DID by verifying that the wallet itself signed a challenge
    /// containing <c>{did, chain, address, nonce, expiry}</c>. The binding is verifiable
    /// without trusting any issuer.
    /// </summary>
    public async Task<DidDocument> BindWalletAsync(
        DidId did,
        WalletBindingRequest request,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var doc = await GetRequiredAsync(did, ct).ConfigureAwait(false);

        if (doc.Revoked)
            throw new InvalidOperationException($"DID is revoked: {did}.");

        if (request.Expiry < _clock.GetUtcNow())
            throw new InvalidOperationException("Wallet binding challenge has expired.");

        var challenge = BuildWalletChallenge(did, request);
        if (!_verifier.Verify(request.WalletPublicKey, challenge, request.Signature))
            throw new InvalidOperationException("Wallet signature did not verify against the challenge.");

        var binding = new WalletBinding
        {
            Chain = request.Chain,
            Address = request.Address,
            ProofSignature = request.Signature.ToArray(),
            BoundAt = _clock.GetUtcNow(),
        };

        var updated = doc with
        {
            Wallets = doc.Wallets
                .Where(w => !(w.Chain == request.Chain && w.Address == request.Address))
                .Append(binding)
                .ToArray(),
            UpdatedAt = _clock.GetUtcNow(),
        };
        await _store.SaveAsync(updated, ct).ConfigureAwait(false);
        return updated;
    }

    /// <summary>
    /// Produce a canonical challenge for wallet binding. The wallet must sign this exact
    /// byte sequence with its private key; the resulting signature is verified during
    /// <see cref="BindWalletAsync"/>.
    /// </summary>
    public static byte[] BuildWalletChallenge(DidId did, WalletBindingRequest request)
    {
        // Canonical form: "Tessera/v1/wallet-bind" || did || chain || address || nonce || expiry_unix_seconds
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write("Tessera/v1/wallet-bind");
        w.Write(did.Value);
        w.Write(request.Chain);
        w.Write(request.Address);
        w.Write(request.Nonce.Length);
        w.Write(request.Nonce);
        w.Write(request.Expiry.ToUnixTimeSeconds());
        return ms.ToArray();
    }

    /// <summary>
    /// Revoke a DID. Marks the document revoked and bumps its version.
    /// On-chain anchoring of the revocation epoch is the caller's responsibility
    /// (via <c>IChainAnchor.BumpRevocationAsync</c>).
    /// </summary>
    public async Task<DidDocument> RevokeAsync(
        DidId did,
        ReadOnlyMemory<byte> controllerSignature,
        CancellationToken ct = default)
    {
        var doc = await GetRequiredAsync(did, ct).ConfigureAwait(false);
        if (doc.Revoked) return doc;

        var controllerKey = ResolveControllerKey(doc);
        var revokeChallenge = BuildRevokeChallenge(did, doc.Version);
        if (!_verifier.Verify(controllerKey, revokeChallenge, controllerSignature.Span))
            throw new InvalidOperationException("Controller signature did not verify against the revoke challenge.");

        var updated = doc with
        {
            Revoked = true,
            Version = doc.Version + 1,
            UpdatedAt = _clock.GetUtcNow(),
        };
        await _store.SaveAsync(updated, ct).ConfigureAwait(false);
        return updated;
    }

    public static byte[] BuildRevokeChallenge(DidId did, int currentVersion)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write("Tessera/v1/did-revoke");
        w.Write(did.Value);
        w.Write(currentVersion);
        return ms.ToArray();
    }

    /// <summary>
    /// Attach a channel binding (phone, email, Telegram, etc.) to the DID document.
    /// The commitment is opaque to this service — callers compute it externally (typically
    /// via <c>ChannelBindingService</c>) using a pepper held outside the library.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Multiple bindings of the same type are allowed (e.g. two phone numbers). To remove
    /// or replace a binding, use <see cref="RemoveChannelBindingAsync"/> first.
    /// </para>
    /// <para>
    /// This method bumps the DID document version. The on-chain attestation root is NOT
    /// touched — that's a separate operation via <c>IChainAnchor.AnchorRootAsync</c> once
    /// the new root is computed.
    /// </para>
    /// </remarks>
    public async Task<DidDocument> AddChannelBindingAsync(
        DidId did,
        ChannelBinding binding,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(binding);
        if (binding.Commitment is null || binding.Commitment.Length == 0)
            throw new ArgumentException("Channel binding commitment must not be empty.", nameof(binding));

        var doc = await GetRequiredAsync(did, ct).ConfigureAwait(false);
        if (doc.Revoked)
            throw new InvalidOperationException($"DID is revoked: {did}.");

        var updated = doc with
        {
            Bindings = doc.Bindings.Append(binding).ToArray(),
            Version = doc.Version + 1,
            UpdatedAt = _clock.GetUtcNow(),
        };
        await _store.SaveAsync(updated, ct).ConfigureAwait(false);
        return updated;
    }

    /// <summary>
    /// Remove a channel binding by type + commitment. Returns the updated document, or the
    /// unmodified one if no matching binding was found.
    /// </summary>
    public async Task<DidDocument> RemoveChannelBindingAsync(
        DidId did,
        string channelType,
        ReadOnlyMemory<byte> commitment,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(channelType);

        var doc = await GetRequiredAsync(did, ct).ConfigureAwait(false);
        if (doc.Revoked)
            throw new InvalidOperationException($"DID is revoked: {did}.");

        var commitmentArray = commitment.ToArray();
        var filtered = doc.Bindings
            .Where(b => !(b.Type == channelType && b.Commitment.AsSpan().SequenceEqual(commitmentArray)))
            .ToArray();

        if (filtered.Length == doc.Bindings.Count)
            return doc;

        var updated = doc with
        {
            Bindings = filtered,
            Version = doc.Version + 1,
            UpdatedAt = _clock.GetUtcNow(),
        };
        await _store.SaveAsync(updated, ct).ConfigureAwait(false);
        return updated;
    }

    private async Task<DidDocument> GetRequiredAsync(DidId did, CancellationToken ct)
    {
        var doc = await _store.GetAsync(did, ct).ConfigureAwait(false);
        return doc ?? throw new InvalidOperationException($"Unknown DID: {did}.");
    }

    private static byte[] ResolveControllerKey(DidDocument doc)
    {
        var method = doc.VerificationMethods.FirstOrDefault()
            ?? throw new InvalidOperationException("DID document has no verification methods.");
        return FromMultibaseBase58(method.PublicKeyMultibase);
    }

    internal static DidId DeriveDidFromKey(ReadOnlySpan<byte> publicKey)
    {
        // Domain-separated digest so that the same pubkey under a different DID method
        // produces a different identifier. SHA-256 is used here for portability; v2 may
        // upgrade to BLAKE2b-256 to match the wider DID ecosystem.
        Span<byte> buf = stackalloc byte[publicKey.Length + 2];
        publicKey.CopyTo(buf);
        buf[publicKey.Length] = (byte)'v';
        buf[publicKey.Length + 1] = (byte)'1';
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(buf, digest);
        return new DidId(DidId.MethodPrefix + Base58.Encode(digest));
    }

    private static string ToMultibaseBase58(ReadOnlySpan<byte> publicKey)
        => "z" + Base58.Encode(publicKey);

    private static byte[] FromMultibaseBase58(string multibase)
    {
        if (string.IsNullOrEmpty(multibase) || multibase[0] != 'z')
            throw new FormatException("Expected base58btc multibase string starting with 'z'.");
        return Base58.Decode(multibase.AsSpan(1));
    }
}

/// <summary>
/// Inputs the holder produces before calling <see cref="DidService.BindWalletAsync"/>.
/// </summary>
public sealed record WalletBindingRequest
{
    public required string Chain { get; init; }
    public required string Address { get; init; }
    public required byte[] WalletPublicKey { get; init; }
    public required byte[] Nonce { get; init; }
    public required DateTimeOffset Expiry { get; init; }
    public required byte[] Signature { get; init; }
}

public interface ISignatureVerifier
{
    bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature);
}
