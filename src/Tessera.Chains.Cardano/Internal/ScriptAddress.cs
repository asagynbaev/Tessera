using CardanoSharp.Wallet.Encoding;
using CardanoSharp.Wallet.Utilities;

namespace Tessera.Chains.Cardano.Internal;

/// <summary>
/// Derives the Plutus V3 policy id (== script hash) and the bech32 enterprise script address
/// from a compiled validator. Cross-checked against <c>aiken blueprint policy/address</c>:
/// for <c>identity_anchor</c> the policy id is <c>73f81b6b…111fdd60</c> and the preprod
/// address is <c>addr_test1wpels…cu2k9g</c>.
/// </summary>
internal static class ScriptAddress
{
    /// <summary>Plutus V3 language tag, prefixed before the script bytes when hashing.</summary>
    private const byte PlutusV3LanguageTag = 0x03;

    /// <summary>Shelley enterprise-script address header (top nibble 0b0111); low nibble is the network id.</summary>
    private const byte EnterpriseScriptHeaderBase = 0x70;

    /// <summary>Policy id / script hash = blake2b-224( 0x03 ‖ compiledCode ).</summary>
    public static byte[] PolicyId(byte[] compiledScript)
    {
        ArgumentNullException.ThrowIfNull(compiledScript);
        var prefixed = new byte[compiledScript.Length + 1];
        prefixed[0] = PlutusV3LanguageTag;
        Buffer.BlockCopy(compiledScript, 0, prefixed, 1, compiledScript.Length);
        return HashUtility.Blake2b224(prefixed);
    }

    /// <summary>Hex policy id, lower-case.</summary>
    public static string PolicyIdHex(byte[] compiledScript) => Convert.ToHexString(PolicyId(compiledScript)).ToLowerInvariant();

    /// <summary>Bech32 enterprise (no-stake) script address for the network.</summary>
    public static string EnterpriseAddress(byte[] scriptHash, CardanoNetwork network)
    {
        ArgumentNullException.ThrowIfNull(scriptHash);
        var header = (byte)(EnterpriseScriptHeaderBase | CardanoNetworkInfo.NetworkId(network));
        var payload = new byte[1 + scriptHash.Length];
        payload[0] = header;
        Buffer.BlockCopy(scriptHash, 0, payload, 1, scriptHash.Length);
        return Bech32.Encode(payload, CardanoNetworkInfo.AddressHrp(network));
    }

    /// <summary>Convenience: policy id and script address from compiled bytes in one call.</summary>
    public static (byte[] PolicyId, string Address) Derive(byte[] compiledScript, CardanoNetwork network)
    {
        var policy = PolicyId(compiledScript);
        return (policy, EnterpriseAddress(policy, network));
    }

    /// <summary>Raw enterprise-script address bytes (header ‖ scriptHash) for use inside transaction outputs.</summary>
    public static byte[] EnterpriseScriptAddressBytes(byte[] scriptHash, CardanoNetwork network)
        => AddressBytes(EnterpriseScriptHeaderBase, scriptHash, network);

    /// <summary>Raw enterprise-key address bytes (header ‖ keyHash) — the controller's wallet address.</summary>
    public static byte[] EnterpriseKeyAddressBytes(byte[] keyHash, CardanoNetwork network)
        => AddressBytes(0x60, keyHash, network);

    private static byte[] AddressBytes(byte headerBase, byte[] credential, CardanoNetwork network)
    {
        var payload = new byte[1 + credential.Length];
        payload[0] = (byte)(headerBase | CardanoNetworkInfo.NetworkId(network));
        Buffer.BlockCopy(credential, 0, payload, 1, credential.Length);
        return payload;
    }
}
