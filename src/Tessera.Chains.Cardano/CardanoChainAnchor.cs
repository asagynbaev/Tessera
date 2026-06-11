using System.Text.Json;
using Tessera.Chains.Cardano.Internal;
using Tessera.Chains.Cardano.Providers;
using Tessera.Core;

namespace Tessera.Chains.Cardano;

/// <summary>
/// Cardano implementation of <see cref="IChainAnchor"/>. Anchors Merkle attestation roots and
/// revocation epochs on Cardano via the Aiken <c>identity_anchor</c> validator (Plutus V3,
/// <see cref="AnchorMode.Validator"/>) or transaction metadata (<see cref="AnchorMode.Metadata"/>).
/// </summary>
/// <remarks>
/// <para>
/// Owner semantics mirror the Solana/EVM adapters: the controller key behind
/// <see cref="CardanoAnchorOptions.SigningKey"/> becomes the on-chain <c>controller</c> of any DID
/// anchor it registers, and the validator enforces its signature on every subsequent update/bump.
/// </para>
/// <para>
/// <see cref="AnchorRootAsync"/> auto-detects whether to register (no anchor UTxO yet) or update
/// (anchor exists). Reads are retried; writes are submitted once (re-broadcasting could double-spend).
/// </para>
/// </remarks>
public sealed class CardanoChainAnchor : IChainAnchor, IDisposable
{
    private readonly CardanoAnchorOptions _options;
    private readonly ICardanoProvider _provider;
    private readonly bool _ownsProvider;
    private readonly ControllerKey _key;
    private readonly byte[] _anchorScript;
    private readonly byte[] _policyId;
    private readonly string _scriptAddress;
    private readonly TimeProvider _clock;

    public CardanoChainAnchor(CardanoAnchorOptions options, TimeProvider? clock = null)
        : this(options, provider: null, clock) { }

    /// <summary>Testing/composition-root constructor: inject a provider (mock or self-hosted node).</summary>
    internal CardanoChainAnchor(CardanoAnchorOptions options, ICardanoProvider? provider, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.BlockfrostProjectId))
            throw new ArgumentException("BlockfrostProjectId required.", nameof(options));
        if (string.IsNullOrWhiteSpace(options.SigningKey))
            throw new ArgumentException("SigningKey required.", nameof(options));

        _options = options;
        _key = KeyLoader.Load(options.SigningKey, options.Network);
        _anchorScript = options.ScriptRefs?.IdentityAnchorScript ?? Blueprint.LoadIdentityAnchorScript();
        _policyId = ScriptAddress.PolicyId(_anchorScript);
        _scriptAddress = ScriptAddress.EnterpriseAddress(_policyId, options.Network);
        _ownsProvider = provider is null;
        _provider = provider ?? new BlockfrostCardanoProvider(options.Network, options.BlockfrostProjectId);
        _clock = clock ?? TimeProvider.System;
    }

    public string ChainId => _options.EffectiveChainTag;

    public async Task<AnchorTxResult> AnchorRootAsync(DidId did, byte[] attestationRoot, CancellationToken ct = default)
    {
        if (attestationRoot is null || attestationRoot.Length != 32)
            throw new ArgumentException("attestationRoot must be exactly 32 bytes.", nameof(attestationRoot));

        return _options.AnchorMode == AnchorMode.Metadata
            ? await MetadataAnchorAsync(did, attestationRoot, ct).ConfigureAwait(false)
            : await ValidatorAnchorAsync(did, attestationRoot, ct).ConfigureAwait(false);
    }

    public async Task<AnchorState?> GetAnchorAsync(DidId did, CancellationToken ct = default)
    {
        var didHash = DidHash.Compute(did);
        return _options.AnchorMode == AnchorMode.Metadata
            ? await ReadMetadataAsync(did, didHash, ct).ConfigureAwait(false)
            : await ReadValidatorAsync(did, didHash, ct).ConfigureAwait(false);
    }

    public async Task<AnchorTxResult> BumpRevocationAsync(DidId did, RevocationReason reason, CancellationToken ct = default)
    {
        var didHash = DidHash.Compute(did);
        if (_options.AnchorMode == AnchorMode.Metadata)
        {
            var current = await ReadMetadataAsync(did, didHash, ct).ConfigureAwait(false);
            var epoch = (current?.RevocationEpoch ?? 0) + 1;
            var root = current?.AttestationRoot ?? new byte[32];
            return await SubmitAndConfirmAsync(await MetadataBuilder().BuildAsync(didHash, root, epoch, ct).ConfigureAwait(false), ct).ConfigureAwait(false);
        }

        var utxo = await FindAnchorUtxoAsync(didHash, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"No anchor exists for {did} — register a root before bumping revocation.");
        var state = DatumCodec.DecodeAnchorDatum(utxo.InlineDatumCbor
            ?? throw new InvalidOperationException("Anchor UTxO is missing its inline datum."));
        var next = state with { RevocationEpoch = state.RevocationEpoch + 1 };
        var built = await AnchorBuilder().BuildSpendAsync(utxo, DatumCodec.BumpRevocationRedeemer((int)reason), next, didHash, ct).ConfigureAwait(false);
        return await SubmitAndConfirmAsync(built, ct).ConfigureAwait(false);
    }

    public async Task<bool> IsRevokedSinceAsync(DidId did, ulong asOfEpoch, CancellationToken ct = default)
    {
        var state = await GetAnchorAsync(did, ct).ConfigureAwait(false);
        return state is not null && AnchorStateMapper.IsRevokedSince(state.RevocationEpoch, asOfEpoch);
    }

    /// <summary>
    /// Register an issuer in the on-chain issuer registry (parity with the contract's
    /// <c>register_issuer</c>; not part of <see cref="IChainAnchor"/>). The issuer's schema URI is
    /// hashed before it goes on-chain. Requires <see cref="CardanoScriptRefs.IssuerRegistryScript"/>
    /// or the embedded blueprint, and (Validator mode) the issuer to sign with <paramref name="signingKey"/>.
    /// </summary>
    public async Task<AnchorTxResult> RegisterIssuerAsync(DidId issuerDid, byte[] signingKey, string schemaUri, CancellationToken ct = default)
    {
        if (signingKey is null || signingKey.Length != 32)
            throw new ArgumentException("signingKey must be a 32-byte Ed25519 public key.", nameof(signingKey));
        ArgumentException.ThrowIfNullOrEmpty(schemaUri);
        if (_options.AnchorMode != AnchorMode.Validator)
            throw new InvalidOperationException("RegisterIssuerAsync requires AnchorMode.Validator.");

        var issuerHash = DidHash.Compute(issuerDid);
        var schemaUriHash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(schemaUri));
        var script = _options.ScriptRefs?.IssuerRegistryScript ?? Blueprint.LoadIssuerRegistryScript();
        var builder = new CardanoTxBuilder(_provider, _key, _options.Network, script);
        var datum = DatumCodec.EncodeIssuerDatum(issuerHash, schemaUriHash, signingKey);
        var built = await builder.BuildMintRegisterAsync(issuerHash, datum, DatumCodec.RegisterIssuerRedeemer(), ct).ConfigureAwait(false);
        return await SubmitAndConfirmAsync(built, ct).ConfigureAwait(false);
    }

    // ── Validator mode ───────────────────────────────────────────────────────────

    private async Task<AnchorTxResult> ValidatorAnchorAsync(DidId did, byte[] root, CancellationToken ct)
    {
        var didHash = DidHash.Compute(did);
        var existing = await FindAnchorUtxoAsync(didHash, ct).ConfigureAwait(false);
        var builder = AnchorBuilder();

        BuiltTx built;
        if (existing is null)
        {
            built = await builder.BuildRegisterAsync(didHash, root, ct).ConfigureAwait(false);
        }
        else
        {
            var state = DatumCodec.DecodeAnchorDatum(existing.InlineDatumCbor
                ?? throw new InvalidOperationException("Anchor UTxO is missing its inline datum."));
            var next = state with { AttestationRoot = root };
            built = await builder.BuildSpendAsync(existing, DatumCodec.UpdateRootRedeemer(root), next, didHash, ct).ConfigureAwait(false);
        }
        return await SubmitAndConfirmAsync(built, ct).ConfigureAwait(false);
    }

    private async Task<AnchorState?> ReadValidatorAsync(DidId did, byte[] didHash, CancellationToken ct)
    {
        var utxo = await FindAnchorUtxoAsync(didHash, ct).ConfigureAwait(false);
        if (utxo?.InlineDatumCbor is null) return null;
        var datum = DatumCodec.DecodeAnchorDatum(utxo.InlineDatumCbor);
        var updatedAt = await ResolveBlockTimeAsync(utxo.TxHash, ct).ConfigureAwait(false);
        return AnchorStateMapper.ToAnchorState(did, datum, updatedAt);
    }

    private async Task<CardanoUtxo?> FindAnchorUtxoAsync(byte[] didHash, CancellationToken ct)
    {
        var unit = Convert.ToHexString(_policyId).ToLowerInvariant() + Convert.ToHexString(didHash).ToLowerInvariant();
        var utxos = await CardanoRetry.RunAsync(_options.Retry,
            () => _provider.GetAssetUtxosAsync(_scriptAddress, unit, ct), ct).ConfigureAwait(false);
        return utxos.Count > 0 ? utxos[0] : null;
    }

    private CardanoTxBuilder AnchorBuilder() => new(_provider, _key, _options.Network, _anchorScript);

    // ── Metadata mode ────────────────────────────────────────────────────────────

    private async Task<AnchorTxResult> MetadataAnchorAsync(DidId did, byte[] root, CancellationToken ct)
    {
        var didHash = DidHash.Compute(did);
        var current = await ReadMetadataAsync(did, didHash, ct).ConfigureAwait(false);
        var epoch = current?.RevocationEpoch ?? 0;
        var built = await MetadataBuilder().BuildAsync(didHash, root, epoch, ct).ConfigureAwait(false);
        return await SubmitAndConfirmAsync(built, ct).ConfigureAwait(false);
    }

    private async Task<AnchorState?> ReadMetadataAsync(DidId did, byte[] didHash, CancellationToken ct)
    {
        var didHex = Convert.ToHexString(didHash).ToLowerInvariant();
        var txs = await CardanoRetry.RunAsync(_options.Retry,
            () => _provider.GetMetadataTxsAsync(_options.MetadataLabel, ct), ct).ConfigureAwait(false);

        // GetMetadataTxsAsync returns newest-first; take the first entry for this DID.
        foreach (var tx in txs)
        {
            if (!tx.Json.TryGetProperty("did", out var didProp) || didProp.GetString() != didHex) continue;
            var root = Convert.FromHexString(tx.Json.GetProperty("root").GetString()!);
            var epoch = tx.Json.GetProperty("epoch").ValueKind == JsonValueKind.String
                ? ulong.Parse(tx.Json.GetProperty("epoch").GetString()!)
                : tx.Json.GetProperty("epoch").GetUInt64();
            var updatedAt = await ResolveBlockTimeAsync(tx.TxHash, ct).ConfigureAwait(false);
            return AnchorStateMapper.ToAnchorState(did, root, epoch, updatedAt);
        }
        return null;
    }

    private MetadataTxBuilder MetadataBuilder() => new(_provider, _key, _options.Network, _options.MetadataLabel);

    // ── submit + confirm ───────────────────────────────────────────────────────────

    private async Task<AnchorTxResult> SubmitAndConfirmAsync(BuiltTx built, CancellationToken ct)
    {
        // Single-shot submit (never auto-retried).
        var txHash = await _provider.SubmitAsync(built.Cbor, ct).ConfigureAwait(false);
        var submittedAt = _clock.GetUtcNow();

        var deadline = submittedAt + _options.ConfirmationTimeout;
        ulong? blockHeight = null;
        while (_clock.GetUtcNow() < deadline)
        {
            var info = await _provider.GetTxAsync(txHash, ct).ConfigureAwait(false);
            if (info is not null) { blockHeight = info.BlockHeight; break; }
            await Task.Delay(_options.ConfirmationPollInterval, ct).ConfigureAwait(false);
        }
        return new AnchorTxResult(txHash, blockHeight, submittedAt);
    }

    private async Task<DateTimeOffset> ResolveBlockTimeAsync(string txHash, CancellationToken ct)
    {
        var info = await CardanoRetry.RunAsync(_options.Retry, () => _provider.GetTxAsync(txHash, ct), ct).ConfigureAwait(false);
        return info is not null
            ? DateTimeOffset.FromUnixTimeSeconds(info.BlockTimeUnix)
            : _clock.GetUtcNow();
    }

    public void Dispose()
    {
        if (_ownsProvider && _provider is IDisposable d) d.Dispose();
    }
}
