namespace Tessera.Did;

using Tessera.Core;

/// <summary>
/// Proves that a wallet <c>address</c> on a given <c>chain</c> is genuinely controlled by the
/// supplied Ed25519 <c>walletPublicKey</c>.
/// </summary>
/// <remarks>
/// <para>
/// A wallet-binding signature only proves control of the <em>public key</em>; it says nothing
/// about whether the caller-chosen <c>Address</c> string actually belongs to that key. Without an
/// independent check, a holder could bind any address (e.g. someone else's) to their DID. This
/// abstraction closes that gap: the verifier confirms the address is derivable from / consistent
/// with the public key for the named chain.
/// </para>
/// <para>
/// Implementations MUST fail closed: for any chain whose address scheme they do not understand,
/// return <c>false</c> rather than optimistically accepting the binding. Exotic chains (smart-contract
/// wallets, multisig, non-Ed25519 address derivations) require a custom verifier.
/// </para>
/// </remarks>
public interface IWalletControlVerifier
{
    /// <summary>
    /// Return <c>true</c> only if <paramref name="address"/> on <paramref name="chain"/> is
    /// provably controlled by <paramref name="walletPublicKey"/> (a 32-byte Ed25519 public key).
    /// Unknown chains and malformed inputs MUST return <c>false</c>.
    /// </summary>
    bool VerifiesControl(string chain, string address, ReadOnlySpan<byte> walletPublicKey);
}

/// <summary>
/// Default <see cref="IWalletControlVerifier"/> for chains where the address is a direct encoding
/// of the Ed25519 public key.
/// </summary>
/// <remarks>
/// <para>Handled chains (case-insensitive):</para>
/// <list type="bullet">
///   <item>
///     <c>solana</c> — the address is the Base58 encoding of the 32-byte public key. The verifier
///     re-derives <c>Base58(walletPublicKey)</c> and compares it (ordinal) to the supplied address.
///   </item>
/// </list>
/// <para>
/// Any other chain returns <c>false</c> (fail closed). Supply a custom <see cref="IWalletControlVerifier"/>
/// to <see cref="DidService"/> for chains with different address derivations (EVM keccak addresses,
/// Bitcoin script hashes, smart-contract / multisig wallets, etc.).
/// </para>
/// </remarks>
public sealed class DefaultWalletControlVerifier : IWalletControlVerifier
{
    /// <inheritdoc/>
    public bool VerifiesControl(string chain, string address, ReadOnlySpan<byte> walletPublicKey)
    {
        if (string.IsNullOrEmpty(chain) || string.IsNullOrEmpty(address))
            return false;
        if (walletPublicKey.Length != 32)
            return false;

        // Normalise the chain name; only chains we explicitly understand are accepted.
        switch (chain.Trim().ToLowerInvariant())
        {
            case "solana":
                // A Solana address IS the Base58 of the 32-byte Ed25519 public key.
                var derived = Base58.Encode(walletPublicKey);
                return string.Equals(derived, address, StringComparison.Ordinal);

            default:
                // Fail closed: we cannot prove control on a chain we do not understand.
                return false;
        }
    }
}
