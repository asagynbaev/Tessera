using Tessera.Attestations;
using Tessera.Chains;
using Tessera.Core;
using Tessera.Did;

namespace Tessera.Sdk;

/// <summary>
/// High-level holder/wallet facade: owns a single DID, accumulates issued attestations,
/// builds presentations for verifiers, and (optionally) anchors the attestation root on-chain.
/// </summary>
/// <remarks>
/// <para>
/// One instance per DID. Hold attestation state in memory for the lifetime of the instance;
/// consumers persist the list of <see cref="Attestation"/> objects however they prefer
/// (database, encrypted file, secure enclave) and pass them back through
/// <see cref="LoadAsync(DidId, IReadOnlyList{Attestation}, HolderOptions, CancellationToken)"/>
/// at startup.
/// </para>
/// </remarks>
public sealed class Holder
{
    private readonly DidService _didService;
    private readonly HolderOptions _options;
    private readonly List<Attestation> _attestations = new();
    private DidDocument _document;

    private Holder(DidDocument document, DidService didService, HolderOptions options)
    {
        _document = document;
        _didService = didService;
        _options = options;
    }

    public DidId Did => _document.Id;
    public DidDocument Document => _document;
    public IReadOnlyList<Attestation> Attestations => _attestations;

    /// <summary>
    /// Current Merkle attestation root, or null if no attestations have been accepted yet.
    /// Recomputed on every call.
    /// </summary>
    public byte[]? CurrentRoot
        => _attestations.Count == 0 ? null : new AttestationBundle(_attestations).Root;

    // ── factories ────────────────────────────────────────────────────────

    /// <summary>
    /// Create a fresh DID from the controller public key and persist it.
    /// The DID identifier is derived deterministically — callers cannot pick it.
    /// </summary>
    public static async Task<Holder> CreateAsync(
        ReadOnlyMemory<byte> controllerPublicKey,
        HolderOptions options,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var didService = new DidService(options.Store, options.SignatureVerifier, options.Clock);
        var doc = await didService.CreateAsync(controllerPublicKey, ct).ConfigureAwait(false);
        return new Holder(doc, didService, options);
    }

    /// <summary>Load an existing DID from the store with no prior attestations.</summary>
    public static Task<Holder> LoadAsync(
        DidId did,
        HolderOptions options,
        CancellationToken ct = default)
        => LoadAsync(did, Array.Empty<Attestation>(), options, ct);

    /// <summary>
    /// Load an existing DID from the store and seed it with previously accepted attestations.
    /// </summary>
    public static async Task<Holder> LoadAsync(
        DidId did,
        IReadOnlyList<Attestation> attestations,
        HolderOptions options,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(attestations);

        var didService = new DidService(options.Store, options.SignatureVerifier, options.Clock);
        var doc = await options.Store.GetAsync(did, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"DID not found in store: {did}.");

        var holder = new Holder(doc, didService, options);
        holder._attestations.AddRange(attestations);
        return holder;
    }

    // ── wallet binding ────────────────────────────────────────────────────

    /// <summary>
    /// Compute the canonical challenge a wallet must sign to be bound to this DID.
    /// Hand this byte array to your wallet SDK for signing; pass the resulting signature
    /// back through <see cref="BindWalletAsync"/>.
    /// </summary>
    public byte[] BuildWalletChallenge(WalletBindingRequest request)
        => DidService.BuildWalletChallenge(_document.Id, request);

    /// <summary>
    /// Bind a wallet to this DID. <paramref name="request"/>.Signature must already contain
    /// the wallet's signature over the bytes returned by <see cref="BuildWalletChallenge"/>.
    /// </summary>
    public async Task BindWalletAsync(WalletBindingRequest request, CancellationToken ct = default)
    {
        _document = await _didService.BindWalletAsync(_document.Id, request, ct).ConfigureAwait(false);
    }

    // ── attestations ──────────────────────────────────────────────────────

    /// <summary>
    /// Accept an issuer-signed attestation. The holder does NOT verify the issuer signature
    /// here — that is the verifier's job at presentation time. Use <see cref="Verifier"/>
    /// off-flow if you want to sanity-check before storing.
    /// </summary>
    public void AcceptAttestation(Attestation attestation)
    {
        ArgumentNullException.ThrowIfNull(attestation);
        if (attestation.Subject != _document.Id)
            throw new ArgumentException(
                $"Attestation subject ({attestation.Subject}) does not match this holder's DID ({_document.Id}).",
                nameof(attestation));
        _attestations.Add(attestation);
    }

    /// <summary>
    /// Remove an attestation by index. Does not touch the on-chain anchor — call
    /// <see cref="AnchorRootAsync"/> afterwards to publish the new root if needed.
    /// </summary>
    public void RemoveAttestation(int index)
    {
        if (index < 0 || index >= _attestations.Count)
            throw new ArgumentOutOfRangeException(nameof(index));
        _attestations.RemoveAt(index);
    }

    // ── chain anchoring ───────────────────────────────────────────────────

    /// <summary>
    /// Publish the current attestation root on the configured chain. Throws if no
    /// <see cref="IChainAnchor"/> was provided or the holder has no attestations.
    /// </summary>
    public async Task<AnchorTxResult> AnchorRootAsync(CancellationToken ct = default)
    {
        var chain = _options.ChainAnchor
            ?? throw new InvalidOperationException("No IChainAnchor configured; cannot anchor.");
        var root = CurrentRoot
            ?? throw new InvalidOperationException("Holder has no attestations to anchor.");

        return await chain.AnchorRootAsync(_document.Id, root, ct).ConfigureAwait(false);
    }

    /// <summary>Read the holder's anchored state from chain. Null if not yet anchored.</summary>
    public async Task<AnchorState?> GetAnchorAsync(CancellationToken ct = default)
    {
        var chain = _options.ChainAnchor
            ?? throw new InvalidOperationException("No IChainAnchor configured; cannot read anchor state.");
        return await chain.GetAnchorAsync(_document.Id, ct).ConfigureAwait(false);
    }

    // ── presentation building ─────────────────────────────────────────────

    /// <summary>
    /// Compute the canonical challenge the holder must sign for a presentation. Hand these bytes to
    /// your signer (the controller private key) and pass the resulting signature, together with the
    /// SAME <paramref name="createdAt"/>, to <see cref="BuildPresentation(DidId, IEnumerable{int}, byte[], ulong, string, byte[], DateTimeOffset)"/>.
    /// Prefer <see cref="BuildSignedPresentation(DidId, IEnumerable{int}, byte[], ulong, string, Func{ReadOnlyMemory{byte}, byte[]})"/>,
    /// which coordinates the timestamp for you.
    /// </summary>
    public byte[] BuildPresentationChallenge(
        DidId verifier,
        IEnumerable<int> indices,
        byte[] sessionNonce,
        ulong asOfRevocationEpoch,
        string chain,
        DateTimeOffset createdAt)
    {
        ArgumentNullException.ThrowIfNull(sessionNonce);
        ArgumentNullException.ThrowIfNull(chain);
        var disclosures = ResolveDisclosures(indices);
        var leafHashes = disclosures.Select(d => d.MerkleProof.LeafHash).ToList();
        return PresentationChallenge.Compute(
            _document.Id, verifier, sessionNonce, asOfRevocationEpoch, chain, createdAt, leafHashes);
    }

    /// <summary>
    /// Build a verifiable presentation disclosing the attestations at <paramref name="indices"/>, by
    /// signing the canonical challenge with the holder's controller key via <paramref name="signChallenge"/>.
    /// This is the recommended path: it stamps a fresh <c>CreatedAt</c>, builds the challenge, signs it,
    /// and assembles the presentation so the signed bytes and the binding can never drift apart.
    /// </summary>
    /// <param name="signChallenge">
    /// Signs the challenge bytes with the holder's Ed25519 controller private key. The matching public
    /// key (taken from this holder's DID document) is embedded in the binding so a verifier can
    /// re-derive the DID and check the signature without any store lookup.
    /// </param>
    public Presentation BuildSignedPresentation(
        DidId verifier,
        IEnumerable<int> indices,
        byte[] sessionNonce,
        ulong asOfRevocationEpoch,
        string chain,
        Func<ReadOnlyMemory<byte>, byte[]> signChallenge)
    {
        ArgumentNullException.ThrowIfNull(signChallenge);
        var createdAt = (_options.Clock ?? TimeProvider.System).GetUtcNow();
        var challenge = BuildPresentationChallenge(verifier, indices, sessionNonce, asOfRevocationEpoch, chain, createdAt);
        var holderSignature = signChallenge(challenge)
            ?? throw new InvalidOperationException("Presentation signer returned null.");
        return BuildPresentation(verifier, indices, sessionNonce, asOfRevocationEpoch, chain, holderSignature, createdAt);
    }

    /// <summary>Type-name convenience overload of <see cref="BuildSignedPresentation(DidId, IEnumerable{int}, byte[], ulong, string, Func{ReadOnlyMemory{byte}, byte[]})"/>.</summary>
    public Presentation BuildSignedPresentation(
        DidId verifier,
        IEnumerable<string> attestationTypes,
        byte[] sessionNonce,
        ulong asOfRevocationEpoch,
        string chain,
        Func<ReadOnlyMemory<byte>, byte[]> signChallenge)
        => BuildSignedPresentation(verifier, IndicesForTypes(attestationTypes), sessionNonce, asOfRevocationEpoch, chain, signChallenge);

    /// <summary>
    /// Build a presentation from a pre-computed <paramref name="holderSignature"/> over the challenge
    /// returned by <see cref="BuildPresentationChallenge"/>. The <paramref name="createdAt"/> MUST equal
    /// the value used to build that challenge, otherwise verification fails. Use this for out-of-band /
    /// hardware signers; otherwise prefer <see cref="BuildSignedPresentation(DidId, IEnumerable{int}, byte[], ulong, string, Func{ReadOnlyMemory{byte}, byte[]})"/>.
    /// </summary>
    public Presentation BuildPresentation(
        DidId verifier,
        IEnumerable<int> indices,
        byte[] sessionNonce,
        ulong asOfRevocationEpoch,
        string chain,
        byte[] holderSignature,
        DateTimeOffset createdAt)
    {
        ArgumentNullException.ThrowIfNull(sessionNonce);
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(holderSignature);

        var disclosures = ResolveDisclosures(indices);

        return new Presentation
        {
            Holder = _document.Id,
            Disclosures = disclosures,
            Binding = new PresentationBinding
            {
                Verifier = verifier,
                SessionNonce = sessionNonce,
                AsOfRevocationEpoch = asOfRevocationEpoch,
                Chain = chain,
                HolderSignature = holderSignature,
                HolderPublicKey = DidService.ResolveControllerKey(_document),
                CreatedAt = createdAt,
            },
        };
    }

    /// <summary>Type-name convenience overload of the pre-signed <see cref="BuildPresentation(DidId, IEnumerable{int}, byte[], ulong, string, byte[], DateTimeOffset)"/>.</summary>
    public Presentation BuildPresentation(
        DidId verifier,
        IEnumerable<string> attestationTypes,
        byte[] sessionNonce,
        ulong asOfRevocationEpoch,
        string chain,
        byte[] holderSignature,
        DateTimeOffset createdAt)
        => BuildPresentation(verifier, IndicesForTypes(attestationTypes), sessionNonce, asOfRevocationEpoch, chain, holderSignature, createdAt);

    private int[] IndicesForTypes(IEnumerable<string> attestationTypes)
    {
        ArgumentNullException.ThrowIfNull(attestationTypes);
        var typeSet = new HashSet<string>(attestationTypes, StringComparer.Ordinal);
        var matchingIndices = _attestations
            .Select((a, i) => (a, i))
            .Where(x => typeSet.Contains(x.a.Type))
            .Select(x => x.i)
            .ToArray();

        if (matchingIndices.Length == 0)
            throw new InvalidOperationException(
                $"Holder has no attestations matching the requested types: {string.Join(", ", typeSet)}.");
        return matchingIndices;
    }

    private AttestationDisclosure[] ResolveDisclosures(IEnumerable<int> indices)
    {
        ArgumentNullException.ThrowIfNull(indices);
        if (_attestations.Count == 0)
            throw new InvalidOperationException("Holder has no attestations; cannot build a presentation.");

        var bundle = new AttestationBundle(_attestations);
        var disclosures = indices
            .Select(i =>
            {
                if (i < 0 || i >= _attestations.Count)
                    throw new ArgumentOutOfRangeException(nameof(indices), $"Index {i} out of range [0, {_attestations.Count}).");
                return bundle.DisclosureFor(i);
            })
            .ToArray();

        if (disclosures.Length == 0)
            throw new ArgumentException("At least one disclosure index is required.", nameof(indices));
        return disclosures;
    }

    // ── revocation ────────────────────────────────────────────────────────

    /// <summary>
    /// Revoke the DID. The controller must produce a signature over the canonical revoke
    /// challenge (see <see cref="DidService.BuildRevokeChallenge"/>).
    /// </summary>
    public async Task RevokeAsync(ReadOnlyMemory<byte> controllerSignature, CancellationToken ct = default)
    {
        _document = await _didService.RevokeAsync(_document.Id, controllerSignature, ct).ConfigureAwait(false);
    }
}
