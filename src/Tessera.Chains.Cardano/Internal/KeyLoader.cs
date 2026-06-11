using CardanoSharp.Wallet;
using CardanoSharp.Wallet.Enums;
using CardanoSharp.Wallet.Extensions.Models;
using CardanoSharp.Wallet.Models.Keys;
using CardanoSharp.Wallet.Utilities;

namespace Tessera.Chains.Cardano.Internal;

/// <summary>
/// The controller key material: the derived payment signing/verification key, its key hash
/// (the on-chain <c>controller</c>), and the enterprise address that pays fees / holds funds.
/// </summary>
internal sealed class ControllerKey
{
    public required PrivateKey PrivateKey { get; init; }
    public required PublicKey PublicKey { get; init; }

    /// <summary>28-byte payment key hash — the datum <c>controller</c> and the required signer.</summary>
    public required byte[] KeyHash { get; init; }

    /// <summary>Bech32 enterprise address of the controller wallet (pays fees, supplies collateral).</summary>
    public required string Address { get; init; }

    /// <summary>Sign a 32-byte transaction-body hash, producing the 64-byte Ed25519 signature.</summary>
    public byte[] Sign(byte[] txBodyHash) => PrivateKey.Sign(txBodyHash);
}

/// <summary>
/// Parses <see cref="CardanoAnchorOptions.SigningKey"/> into a <see cref="ControllerKey"/>.
/// Accepts a BIP-39 mnemonic (CIP-1852 <c>m/1852'/1815'/0'/0/0</c> is derived) or a raw
/// 96-byte extended-key hex (64-byte key ‖ 32-byte chaincode). The key never touches logs.
/// </summary>
internal static class KeyLoader
{
    private const string PaymentDerivationPath = "m/1852'/1815'/0'/0/0";

    public static ControllerKey Load(string signingKey, CardanoNetwork network)
    {
        if (string.IsNullOrWhiteSpace(signingKey))
            throw new ArgumentException("SigningKey required.", nameof(signingKey));

        var trimmed = signingKey.Trim();
        var payment = trimmed.Contains(' ', StringComparison.Ordinal)
            ? FromMnemonic(trimmed)
            : FromExtendedHex(trimmed);

        var publicKey = payment.GetPublicKey(false);
        var networkType = ToNetworkType(network);
        var address = AddressUtility.GetEnterpriseAddress(publicKey, networkType);
        var keyHash = HashUtility.Blake2b224(publicKey.Key);

        return new ControllerKey
        {
            PrivateKey = payment,
            PublicKey = publicKey,
            KeyHash = keyHash,
            Address = address.ToString(),
        };
    }

    private static PrivateKey FromMnemonic(string mnemonic)
    {
        try
        {
            return new MnemonicService().Restore(mnemonic).GetRootKey("").Derive(PaymentDerivationPath);
        }
        catch (Exception ex)
        {
            throw new ArgumentException("SigningKey looked like a mnemonic but could not be parsed.", nameof(mnemonic), ex);
        }
    }

    private static PrivateKey FromExtendedHex(string hex)
    {
        byte[] bytes;
        try { bytes = Convert.FromHexString(hex); }
        catch (FormatException ex) { throw new ArgumentException("SigningKey is neither a mnemonic nor valid hex.", nameof(hex), ex); }

        // Tolerate a single CBOR bytestring wrapper (e.g. a cardano-cli .skey cborHex).
        if (bytes.Length is > 96 && bytes[0] is 0x58)
            bytes = bytes[^96..];

        if (bytes.Length != 96)
            throw new ArgumentException("SigningKey hex must decode to a 96-byte extended key (64-byte key + 32-byte chaincode).", nameof(hex));

        return new PrivateKey(bytes[..64], bytes[64..]);
    }

    private static NetworkType ToNetworkType(CardanoNetwork network) => network switch
    {
        CardanoNetwork.Mainnet => NetworkType.Mainnet,
        CardanoNetwork.Preview => NetworkType.Preview,
        _ => NetworkType.Preprod,
    };
}
