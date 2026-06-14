using System.Linq;
using System.Numerics;
using System.Text;
using Nethereum.ABI;
using Nethereum.Signer;
using Nethereum.Util;

namespace Tessera.Chains.Evm.Internal;

/// <summary>
/// Produces the controller proof required by <c>IdentityRegistry.registerDid</c>. The DID controller
/// signs the registration so that — even though <c>didHash</c> is public — only the controller can
/// create the anchor (no front-running / squatting). The signature may then be relayed by any sender.
/// </summary>
/// <remarks>
/// The signed payload mirrors the contract exactly:
/// <code>
/// structHash = keccak256(abi.encode(didHash, attestationRoot, chainId, contractAddress));
/// digest     = keccak256(0x19 ++ "Ethereum Signed Message:\n32" ++ structHash);   // EIP-191 personal sign
/// signature  = ECDSA_sign(digest, controllerKey);                                  // 65 bytes, r‖s‖v
/// </code>
/// Binding <c>chainId</c> and <c>contractAddress</c> into the struct hash prevents replaying the
/// signature on another chain or another registry deployment.
/// </remarks>
internal static class EvmRegistrationSigner
{
    private static readonly ABIEncode Abi = new();

    // EIP-191 personal-sign prefix for a fixed 32-byte message (the struct hash is always 32 bytes):
    // the 0x19 control byte followed by "Ethereum Signed Message:\n32". Built as explicit bytes so no
    // control char or \x escape lives in a string literal — a literal "\x19Ethereum…" is a trap, since
    // C#'s variable-length \x greedily consumes the following 'E' (\x19E -> U+019E) and corrupts the
    // prefix, yielding a digest the contract's ecrecover does not match (-> InvalidSignature).
    private static readonly byte[] Eip191Prefix32 =
        new byte[] { 0x19 }.Concat(Encoding.ASCII.GetBytes("Ethereum Signed Message:\n32")).ToArray();

    /// <summary>The address that controls the DID, derived from the signing key.</summary>
    public static string DeriveController(string privateKey) => new EthECKey(privateKey).GetPublicAddress();

    /// <summary>
    /// keccak256(abi.encode(didHash, attestationRoot, chainId, contractAddress)) — the struct hash
    /// the contract reconstructs before applying the EIP-191 prefix.
    /// </summary>
    public static byte[] StructHash(byte[] didHash, byte[] attestationRoot, BigInteger chainId, string contractAddress)
    {
        var encoded = Abi.GetABIEncoded(
            new ABIValue("bytes32", didHash),
            new ABIValue("bytes32", attestationRoot),
            new ABIValue("uint256", chainId),
            new ABIValue("address", contractAddress));
        return Sha3Keccack.Current.CalculateHash(encoded);
    }

    /// <summary>
    /// keccak256(0x19 ++ "Ethereum Signed Message:\n32" ++ structHash) — the exact digest the contract
    /// signs over (EIP-191 personal-sign of the 32-byte struct hash).
    /// </summary>
    public static byte[] Digest(byte[] structHash)
    {
        var buffer = new byte[Eip191Prefix32.Length + structHash.Length];
        Buffer.BlockCopy(Eip191Prefix32, 0, buffer, 0, Eip191Prefix32.Length);
        Buffer.BlockCopy(structHash, 0, buffer, Eip191Prefix32.Length, structHash.Length);
        return Sha3Keccack.Current.CalculateHash(buffer);
    }

    /// <summary>
    /// Sign the registration with <paramref name="privateKey"/>. Returns the 65-byte (r‖s‖v) ECDSA
    /// signature over the EIP-191 personal-sign digest of <see cref="StructHash"/>, exactly as the
    /// contract's <c>_recover</c> expects (canonical low-S, v ∈ {27,28}).
    /// </summary>
    public static byte[] Sign(string privateKey, byte[] didHash, byte[] attestationRoot, BigInteger chainId, string contractAddress)
    {
        var structHash = StructHash(didHash, attestationRoot, chainId, contractAddress);
        var digest = Digest(structHash);
        var signature = new EthECKey(privateKey).SignAndCalculateV(digest);

        // r (32) ‖ s (32) ‖ v (1); v is 27/28 as the contract requires.
        var sig = new byte[65];
        Buffer.BlockCopy(signature.R, 0, sig, 32 - signature.R.Length, signature.R.Length);
        Buffer.BlockCopy(signature.S, 0, sig, 64 - signature.S.Length, signature.S.Length);
        sig[64] = signature.V[0];
        return sig;
    }
}
