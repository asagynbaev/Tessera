using System.Numerics;
using Nethereum.Signer;
using Tessera.Chains.Evm.Internal;

namespace Tessera.Chains.Evm.Tests;

/// <summary>
/// C6/H7: registerDid now requires a controller signature so a public didHash cannot be squatted.
/// These tests verify the C# adapter produces a signature that recovers to the controller over the
/// exact digest the contract reconstructs — keccak256(abi.encode(didHash, attestationRoot, chainId,
/// contract)) under the EIP-191 personal-sign prefix — and that the binding fields actually bind
/// (changing chainId or contract invalidates the recovery to a different/expected signer).
/// </summary>
public class EvmRegistrationSignerTests
{
    private const string Key = "0x4646464646464646464646464646464646464646464646464646464646464646";
    private const string Contract = "0x000000000000000000000000000000000000c0de";

    private static byte[] DidHash => Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static byte[] Root => Enumerable.Range(0, 32).Select(i => (byte)(0xff - i)).ToArray();

    /// <summary>
    /// Recover the signer exactly as the contract's <c>ecrecover</c> does: split the 65-byte signature
    /// into r‖s‖v and recover over the EIP-191 personal-sign digest of the 32-byte struct hash.
    /// </summary>
    private static string Recover(byte[] structHash, byte[] signature)
    {
        var digest = EvmRegistrationSigner.Digest(structHash);
        var r = signature[..32];
        var s = signature[32..64];
        var v = signature[64];
        var sig = EthECDSASignatureFactory.FromComponents(r, s, v);
        return EthECKey.RecoverFromSignature(sig, digest).GetPublicAddress();
    }

    [Fact]
    public void Controller_IsDerivedFromSigningKey()
    {
        var expected = new EthECKey(Key).GetPublicAddress();
        Assert.Equal(expected, EvmRegistrationSigner.DeriveController(Key));
    }

    [Fact]
    public void Signature_RecoversToController()
    {
        BigInteger chainId = 97;
        var controller = EvmRegistrationSigner.DeriveController(Key);

        var structHash = EvmRegistrationSigner.StructHash(DidHash, Root, chainId, Contract);
        var sig = EvmRegistrationSigner.Sign(Key, DidHash, Root, chainId, Contract);

        Assert.Equal(65, sig.Length); // r(32) + s(32) + v(1)
        Assert.Equal(controller.ToLowerInvariant(), Recover(structHash, sig).ToLowerInvariant());
    }

    [Fact]
    public void Signature_IsBoundToChainId()
    {
        var controller = EvmRegistrationSigner.DeriveController(Key);
        var sig = EvmRegistrationSigner.Sign(Key, DidHash, Root, 97, Contract);

        // Verifying against a different chainId's struct hash must NOT recover the controller.
        var otherChainHash = EvmRegistrationSigner.StructHash(DidHash, Root, 56, Contract);
        Assert.NotEqual(controller.ToLowerInvariant(), Recover(otherChainHash, sig).ToLowerInvariant());
    }

    [Fact]
    public void Signature_IsBoundToContractAddress()
    {
        var controller = EvmRegistrationSigner.DeriveController(Key);
        var sig = EvmRegistrationSigner.Sign(Key, DidHash, Root, 97, Contract);

        var otherContractHash = EvmRegistrationSigner.StructHash(DidHash, Root, 97, "0x000000000000000000000000000000000000dEaD");
        Assert.NotEqual(controller.ToLowerInvariant(), Recover(otherContractHash, sig).ToLowerInvariant());
    }
}
