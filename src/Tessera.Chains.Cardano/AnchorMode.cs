namespace Tessera.Chains.Cardano;

/// <summary>
/// Selects how <see cref="CardanoChainAnchor"/> records anchor state on Cardano.
/// </summary>
public enum AnchorMode
{
    /// <summary>
    /// Full Plutus flow against the Aiken <c>identity_anchor</c> validator: state lives
    /// in a script-locked UTxO carrying a thread token, and the validator enforces
    /// controller signatures, monotonic revocation epochs, immutable fields, and token
    /// continuity. Trust-minimised; requires a controller wallet funded with test ADA.
    /// </summary>
    Validator = 0,

    /// <summary>
    /// Demo fallback: writes <c>{ did_hash, root, epoch }</c> as transaction metadata
    /// under a fixed label; reads scan that label via the provider. No script enforces
    /// anything — a verifier trusts the controller key that signed the metadata tx, not
    /// the chain. Cheaper and simpler, but without the validator's tamper-evidence.
    /// </summary>
    Metadata = 1,
}
