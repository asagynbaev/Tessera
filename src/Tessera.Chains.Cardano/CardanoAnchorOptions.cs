namespace Tessera.Chains.Cardano;

/// <summary>
/// Composition-root configuration for <see cref="CardanoChainAnchor"/>. The adapter is
/// network-agnostic: <see cref="Network"/> selects the Blockfrost endpoint and address
/// tags, and the validator script + address are derived from the blueprint shipped with
/// the package, so the common case needs only a network, a Blockfrost key, and a signing key.
/// </summary>
public sealed record CardanoAnchorOptions
{
    /// <summary>Target Cardano network. Defaults to <see cref="CardanoNetwork.Preprod"/>.</summary>
    public CardanoNetwork Network { get; init; } = CardanoNetwork.Preprod;

    /// <summary>Blockfrost project id for <see cref="Network"/> (does reads and tx submission). Never logged.</summary>
    public required string BlockfrostProjectId { get; init; }

    /// <summary>
    /// The controller payment signing key. Accepts either a BIP-39 mnemonic phrase
    /// (CIP-1852 <c>m/1852'/1815'/0'/0/0</c> is derived) or a cardano <c>.skey</c>
    /// cborHex / raw extended-key hex. This key signs writes and becomes the on-chain
    /// <c>controller</c> of any DID anchor it registers — owner parity with the Solana/EVM
    /// adapters. Never logged.
    /// </summary>
    public required string SigningKey { get; init; }

    /// <summary>
    /// Validator script references. Null (the default) derives the script, policy id, and
    /// script address from the blueprint embedded in the package. Set this only to point at
    /// a different deployment or to use on-chain reference scripts.
    /// </summary>
    public CardanoScriptRefs? ScriptRefs { get; init; }

    /// <summary>How anchor state is recorded. Defaults to <see cref="AnchorMode.Validator"/>.</summary>
    public AnchorMode AnchorMode { get; init; } = AnchorMode.Validator;

    /// <summary>Retry policy for transient provider failures (reads only). Defaults to 3 attempts with backoff.</summary>
    public CardanoRetryPolicy Retry { get; init; } = CardanoRetryPolicy.Default;

    /// <summary>How long to await on-chain confirmation of a submitted write. Default 3 minutes.</summary>
    public TimeSpan ConfirmationTimeout { get; init; } = TimeSpan.FromMinutes(3);

    /// <summary>Poll interval while awaiting confirmation. Default 10 seconds.</summary>
    public TimeSpan ConfirmationPollInterval { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Transaction-metadata label used by <see cref="AnchorMode.Metadata"/>. The default
    /// (<c>5446</c>, ASCII "TF") is an unregistered CIP-10 label; override only to coexist
    /// with another schema on the same label.
    /// </summary>
    public ulong MetadataLabel { get; init; } = 5446;

    /// <summary>Logical chain tag surfaced as <see cref="CardanoChainAnchor.ChainId"/> and bound into presentations.</summary>
    public string EffectiveChainTag => $"cardano:{Network.ToString().ToLowerInvariant()}";
}

/// <summary>
/// References to the compiled validators. When null on <see cref="CardanoAnchorOptions"/>,
/// the adapter loads the blueprint embedded in the package.
/// </summary>
public sealed record CardanoScriptRefs
{
    /// <summary>Compiled <c>identity_anchor</c> validator (raw Plutus V3 script bytes from the blueprint <c>compiledCode</c>).</summary>
    public required byte[] IdentityAnchorScript { get; init; }

    /// <summary>Compiled <c>issuer_registry</c> validator, if issuer registration is used.</summary>
    public byte[]? IssuerRegistryScript { get; init; }
}

/// <summary>Best-effort retry policy for transient Blockfrost / network failures (reads only; writes are single-shot).</summary>
public sealed record CardanoRetryPolicy
{
    /// <summary>Total attempts including the first. 1 = no retry.</summary>
    public int MaxAttempts { get; init; } = 3;

    /// <summary>Base delay; attempt N waits <c>BaseDelay * 2^(N-1)</c>.</summary>
    public TimeSpan BaseDelay { get; init; } = TimeSpan.FromMilliseconds(500);

    public static CardanoRetryPolicy Default { get; } = new();
    public static CardanoRetryPolicy None { get; } = new() { MaxAttempts = 1 };
}
