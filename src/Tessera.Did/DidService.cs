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
    private readonly IWalletControlVerifier _walletControl;
    private readonly INonceStore? _nonceStore;

    /// <summary>
    /// Create a DID service.
    /// </summary>
    /// <param name="store">DID document store.</param>
    /// <param name="verifier">Ed25519 signature verifier.</param>
    /// <param name="clock">Optional clock (defaults to <see cref="TimeProvider.System"/>).</param>
    /// <param name="walletControl">
    /// Optional verifier proving a bound wallet <c>Address</c> is genuinely controlled by the
    /// <c>WalletPublicKey</c>. Defaults to <see cref="DefaultWalletControlVerifier"/>, which handles
    /// chains whose address is a direct encoding of the Ed25519 key (e.g. Solana) and fails closed
    /// on every other chain. Supply a custom verifier for exotic chains (EVM, Bitcoin, smart-contract
    /// or multisig wallets).
    /// </param>
    /// <param name="nonceStore">
    /// Optional anti-replay store. When supplied, <see cref="BindWalletAsync"/> consumes the signed
    /// wallet-binding nonce atomically so a captured challenge cannot be replayed. When <c>null</c>,
    /// the nonce is signed but not enforced for single use (legacy behaviour) — supply a store in
    /// production to close the replay window.
    /// </param>
    public DidService(
        IDidStore store,
        ISignatureVerifier verifier,
        TimeProvider? clock = null,
        IWalletControlVerifier? walletControl = null,
        INonceStore? nonceStore = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        _clock = clock ?? TimeProvider.System;
        _walletControl = walletControl ?? new DefaultWalletControlVerifier();
        _nonceStore = nonceStore;
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

    /// <summary>
    /// Resolve a DID document, whether or not it is revoked. Callers that need to inspect a
    /// revoked document (e.g. to surface revocation status, or to read its last-known state) use
    /// this. Callers that must only act on a live identity should prefer <see cref="GetActiveAsync"/>,
    /// which enforces <see cref="DidDocument.Revoked"/>.
    /// </summary>
    public Task<DidDocument?> GetAsync(DidId did, CancellationToken ct = default)
        => _store.GetAsync(did, ct);

    /// <summary>
    /// Resolve a DID document only if it is active. Returns <c>null</c> for an unknown DID
    /// <em>or</em> a revoked one. This is the defense-in-depth resolve path: it guarantees a caller
    /// never treats a revoked DID as usable. (All mutating paths already reject revoked DIDs.)
    /// </summary>
    public async Task<DidDocument?> GetActiveAsync(DidId did, CancellationToken ct = default)
    {
        var doc = await _store.GetAsync(did, ct).ConfigureAwait(false);
        return doc is { Revoked: false } ? doc : null;
    }

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

        // The signature only proves control of WalletPublicKey, not of the caller-chosen Address.
        // Require independent proof that Address is genuinely derived from / controlled by the key,
        // so a holder cannot bind an address they do not own. DefaultWalletControlVerifier fails
        // closed on chains it does not understand.
        if (!_walletControl.VerifiesControl(request.Chain, request.Address, request.WalletPublicKey))
            throw new InvalidOperationException(
                $"Wallet address '{request.Address}' is not provably controlled by the supplied public key on chain '{request.Chain}'. " +
                "Supply an IWalletControlVerifier that understands this chain's address derivation.");

        // Single-use nonce enforcement (when a store is configured): consume atomically and reject
        // any replay of a previously presented binding challenge.
        if (_nonceStore is not null)
        {
            var fresh = await _nonceStore
                .TryConsumeAsync(did, request.Nonce, request.Expiry, ct)
                .ConfigureAwait(false);
            if (!fresh)
                throw new InvalidOperationException("Wallet binding nonce has already been used (replay rejected).");
        }

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
    /// <remarks>
    /// The wallet public key is included (length-prefixed) so the signed message is unambiguously
    /// bound to the key being attested, not merely to the caller-chosen address. The control of the
    /// address itself is checked separately via <see cref="IWalletControlVerifier"/>.
    /// </remarks>
    public static byte[] BuildWalletChallenge(DidId did, WalletBindingRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        // Canonical form:
        // "Tessera/v1/wallet-bind" || did || chain || address
        //   || len(wallet_pubkey) || wallet_pubkey || len(nonce) || nonce || expiry_unix_seconds
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write("Tessera/v1/wallet-bind");
        w.Write(did.Value);
        w.Write(request.Chain);
        w.Write(request.Address);
        w.Write(request.WalletPublicKey.Length);
        w.Write(request.WalletPublicKey);
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
    /// <b>Trusted-caller-only overload.</b> This overload performs NO controller authorization —
    /// it bumps the document version and writes the binding on the caller's say-so. It exists only
    /// for hosts that have already authenticated the controller out-of-band (and for backward
    /// compatibility). Untrusted/remote callers MUST use
    /// <see cref="AddChannelBindingAsync(DidId, ChannelBinding, ReadOnlyMemory{byte}, CancellationToken)"/>,
    /// which requires a controller signature over a canonical challenge.
    /// </para>
    /// <para>
    /// Multiple bindings of the same type are allowed (e.g. two phone numbers). To remove
    /// or replace a binding, use <see cref="RemoveChannelBindingAsync(DidId, string, ReadOnlyMemory{byte}, CancellationToken)"/> first.
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

        return await AppendBindingAsync(doc, binding, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Authenticated overload of <see cref="AddChannelBindingAsync(DidId, ChannelBinding, CancellationToken)"/>.
    /// Requires <paramref name="controllerSignature"/> over the canonical "channel-bind" challenge
    /// (see <see cref="BuildChannelBindChallenge"/>) verified against the DID's controller key, so
    /// only the controller can attach a binding. Mirrors the revoke-challenge pattern.
    /// </summary>
    public async Task<DidDocument> AddChannelBindingAsync(
        DidId did,
        ChannelBinding binding,
        ReadOnlyMemory<byte> controllerSignature,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(binding);
        if (binding.Commitment is null || binding.Commitment.Length == 0)
            throw new ArgumentException("Channel binding commitment must not be empty.", nameof(binding));

        var doc = await GetRequiredAsync(did, ct).ConfigureAwait(false);
        if (doc.Revoked)
            throw new InvalidOperationException($"DID is revoked: {did}.");

        var controllerKey = ResolveControllerKey(doc);
        var challenge = BuildChannelBindChallenge(did, doc.Version, binding.Type, binding.Commitment);
        if (!_verifier.Verify(controllerKey, challenge, controllerSignature.Span))
            throw new InvalidOperationException("Controller signature did not verify against the channel-bind challenge.");

        return await AppendBindingAsync(doc, binding, ct).ConfigureAwait(false);
    }

    private async Task<DidDocument> AppendBindingAsync(DidDocument doc, ChannelBinding binding, CancellationToken ct)
    {
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
    /// <remarks>
    /// <b>Trusted-caller-only overload.</b> Performs NO controller authorization. Untrusted/remote
    /// callers MUST use
    /// <see cref="RemoveChannelBindingAsync(DidId, string, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, CancellationToken)"/>,
    /// which requires a controller signature over a canonical "channel-unbind" challenge.
    /// </remarks>
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

        return await RemoveBindingAsync(doc, channelType, commitment, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Authenticated overload of <see cref="RemoveChannelBindingAsync(DidId, string, ReadOnlyMemory{byte}, CancellationToken)"/>.
    /// Requires <paramref name="controllerSignature"/> over the canonical "channel-unbind" challenge
    /// (see <see cref="BuildChannelUnbindChallenge"/>) verified against the DID's controller key.
    /// </summary>
    public async Task<DidDocument> RemoveChannelBindingAsync(
        DidId did,
        string channelType,
        ReadOnlyMemory<byte> commitment,
        ReadOnlyMemory<byte> controllerSignature,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(channelType);

        var doc = await GetRequiredAsync(did, ct).ConfigureAwait(false);
        if (doc.Revoked)
            throw new InvalidOperationException($"DID is revoked: {did}.");

        var controllerKey = ResolveControllerKey(doc);
        var challenge = BuildChannelUnbindChallenge(did, doc.Version, channelType, commitment.Span);
        if (!_verifier.Verify(controllerKey, challenge, controllerSignature.Span))
            throw new InvalidOperationException("Controller signature did not verify against the channel-unbind challenge.");

        return await RemoveBindingAsync(doc, channelType, commitment, ct).ConfigureAwait(false);
    }

    private async Task<DidDocument> RemoveBindingAsync(
        DidDocument doc,
        string channelType,
        ReadOnlyMemory<byte> commitment,
        CancellationToken ct)
    {
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

    /// <summary>
    /// Canonical challenge a controller signs to authorize attaching a channel binding. Binds the
    /// DID, current document version (prevents replay across versions), channel type, and commitment.
    /// </summary>
    public static byte[] BuildChannelBindChallenge(
        DidId did,
        int currentVersion,
        string channelType,
        ReadOnlySpan<byte> commitment)
    {
        ArgumentException.ThrowIfNullOrEmpty(channelType);
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write("Tessera/v1/channel-bind");
        w.Write(did.Value);
        w.Write(currentVersion);
        w.Write(channelType);
        w.Write(commitment.Length);
        w.Write(commitment);
        return ms.ToArray();
    }

    /// <summary>
    /// Canonical challenge a controller signs to authorize removing a channel binding. Binds the
    /// DID, current document version, channel type, and commitment.
    /// </summary>
    public static byte[] BuildChannelUnbindChallenge(
        DidId did,
        int currentVersion,
        string channelType,
        ReadOnlySpan<byte> commitment)
    {
        ArgumentException.ThrowIfNullOrEmpty(channelType);
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write("Tessera/v1/channel-unbind");
        w.Write(did.Value);
        w.Write(currentVersion);
        w.Write(channelType);
        w.Write(commitment.Length);
        w.Write(commitment);
        return ms.ToArray();
    }

    private async Task<DidDocument> GetRequiredAsync(DidId did, CancellationToken ct)
    {
        var doc = await _store.GetAsync(did, ct).ConfigureAwait(false);
        return doc ?? throw new InvalidOperationException($"Unknown DID: {did}.");
    }

    /// <summary>
    /// Extract the Ed25519 controller public key from a DID document's first verification method.
    /// This is the key a verifier re-derives the DID from (see <see cref="DidId.FromControllerKey"/>)
    /// and against which holder/controller signatures are checked.
    /// </summary>
    public static byte[] ResolveControllerKey(DidDocument doc)
    {
        ArgumentNullException.ThrowIfNull(doc);
        var method = doc.VerificationMethods.FirstOrDefault()
            ?? throw new InvalidOperationException("DID document has no verification methods.");
        return FromMultibaseBase58(method.PublicKeyMultibase);
    }

    // Single source of truth lives in Tessera.Core so layers that cannot reference Tessera.Did
    // (e.g. the Attestations presentation verifier) can re-derive a DID from a controller key.
    internal static DidId DeriveDidFromKey(ReadOnlySpan<byte> publicKey) => DidId.FromControllerKey(publicKey);

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
