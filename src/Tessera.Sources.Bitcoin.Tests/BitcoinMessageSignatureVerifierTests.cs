namespace Tessera.Sources.Bitcoin.Tests;

public class BitcoinMessageSignatureVerifierTests
{
    private readonly BitcoinMessageSignatureVerifier _verifier = new();

    public static IEnumerable<object[]> SupportedVectors() =>
        BitcoinTestVectors.All.Select(v => new object[] { v });

    [Theory]
    [MemberData(nameof(SupportedVectors))]
    public void ValidVector_Verifies_AndReportsType(BitcoinTestVectors.Vector v)
    {
        var result = _verifier.Verify(v.Address, BitcoinTestVectors.Message, v.Signature, v.Network);

        Assert.True(result.IsValid, result.Reason);
        Assert.Equal(v.Type, result.AddressType);
        Assert.Null(result.Reason);
    }

    [Fact]
    public void TamperedSignature_Rejected()
    {
        var v = BitcoinTestVectors.TestnetP2wpkh;
        // Flip the last base64 group → different r/s bytes, same header.
        var bytes = Convert.FromBase64String(v.Signature);
        bytes[10] ^= 0xFF;
        var tampered = Convert.ToBase64String(bytes);

        var result = _verifier.Verify(v.Address, BitcoinTestVectors.Message, tampered, v.Network);
        Assert.False(result.IsValid);
    }

    [Fact]
    public void TamperedMessage_Rejected()
    {
        var v = BitcoinTestVectors.TestnetP2pkh;
        var result = _verifier.Verify(v.Address, BitcoinTestVectors.Message + "x", v.Signature, v.Network);
        Assert.False(result.IsValid);
        Assert.Equal("address_mismatch", result.Reason);
    }

    [Fact]
    public void WrongAddress_SameKeyDifferentType_Rejected()
    {
        // The P2WPKH signature recovers the right key, but presented against a *different* address
        // of a different person it must fail. Use a hand-picked address that is not derived from the key.
        var v = BitcoinTestVectors.TestnetP2wpkh;
        const string otherAddress = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"; // BIP-173 example addr
        var result = _verifier.Verify(otherAddress, BitcoinTestVectors.Message, v.Signature, v.Network);
        Assert.False(result.IsValid);
        Assert.Equal("address_mismatch", result.Reason);
    }

    [Fact]
    public void Taproot_ReportedUnsupported_NotSilentlyFailed()
    {
        var result = _verifier.Verify(
            BitcoinTestVectors.TestnetTaproot, BitcoinTestVectors.Message,
            BitcoinTestVectors.TestnetP2wpkh.Signature, BitcoinNetwork.Testnet);

        Assert.False(result.IsValid);
        Assert.Equal(BitcoinAddressType.P2tr, result.AddressType);
        Assert.Equal("taproot_bip322_unsupported", result.Reason);
    }

    [Fact]
    public void MalformedSignature_Rejected_NeverThrows()
    {
        var v = BitcoinTestVectors.TestnetP2pkh;
        Assert.Equal("signature_base64_invalid", _verifier.Verify(v.Address, BitcoinTestVectors.Message, "not base64!!", v.Network).Reason);
        Assert.Equal("signature_length_invalid", _verifier.Verify(v.Address, BitcoinTestVectors.Message, Convert.ToBase64String(new byte[10]), v.Network).Reason);
        Assert.Equal("address_parse_failed", _verifier.Verify("not-an-address", BitcoinTestVectors.Message, v.Signature, v.Network).Reason);
    }

    [Fact]
    public void BadHeaderByte_Rejected()
    {
        var v = BitcoinTestVectors.TestnetP2pkh;
        var bytes = Convert.FromBase64String(v.Signature);
        bytes[0] = 26; // below the valid 27..42 range
        var result = _verifier.Verify(v.Address, BitcoinTestVectors.Message, Convert.ToBase64String(bytes), v.Network);
        Assert.False(result.IsValid);
        Assert.Equal("signature_header_invalid", result.Reason);
    }

    [Fact]
    public void TestnetSignature_AgainstMainnetNetwork_DoesNotCrossVerify()
    {
        // The testnet bech32 address string does not parse under Network.Main, so verification fails
        // at the address-parse step (before recovery). Pin the reason so the behaviour is locked.
        var v = BitcoinTestVectors.TestnetP2wpkh;
        var result = _verifier.Verify(v.Address, BitcoinTestVectors.Message, v.Signature, BitcoinNetwork.Mainnet);
        Assert.False(result.IsValid);
        Assert.Equal("address_parse_failed", result.Reason);
    }

    [Fact]
    public void HeaderTolerance_LegacyRangeHeader_ForSegwitAddress_StillVerifies()
    {
        // Rewrite the P2WPKH signature's header from the P2WPKH range (39–42) into the P2PKH range
        // (27–34) keeping the same recovery id. The verifier reads recId from the header and matches
        // the recovered key against the claimed script regardless of the header's type hint.
        var v = BitcoinTestVectors.TestnetP2wpkh;
        var bytes = Convert.FromBase64String(v.Signature);
        var recId = (bytes[0] - 27) & 0x03;
        bytes[0] = (byte)(27 + recId + 4); // compressed-P2PKH-range header, same recId
        var rehomed = Convert.ToBase64String(bytes);

        var result = _verifier.Verify(v.Address, BitcoinTestVectors.Message, rehomed, v.Network);
        Assert.True(result.IsValid, result.Reason);
        Assert.Equal(BitcoinAddressType.P2wpkh, result.AddressType);
    }

    [Fact]
    public void UncompressedKeyP2pkh_Verifies()
    {
        // Same key, same signature, but the address is the UNCOMPRESSED-key P2PKH form — matched via
        // the verifier's decompress branch (the BIP-137 "P2PKH uncompressed" variant).
        var v = BitcoinTestVectors.TestnetP2pkhUncompressed;
        var result = _verifier.Verify(v.Address, BitcoinTestVectors.Message, v.Signature, v.Network);
        Assert.True(result.IsValid, result.Reason);
        Assert.Equal(BitcoinAddressType.P2pkh, result.AddressType);
    }

    [Fact]
    public void P2wsh_ReportedUnsupported()
    {
        var result = _verifier.Verify(
            BitcoinTestVectors.TestnetP2wsh, BitcoinTestVectors.Message,
            BitcoinTestVectors.TestnetP2wpkh.Signature, BitcoinNetwork.Testnet);
        Assert.False(result.IsValid);
        Assert.Equal("unsupported_address_type", result.Reason);
    }

    [Fact]
    public void MissingAddressOrMessage_Rejected()
    {
        var v = BitcoinTestVectors.TestnetP2pkh;
        Assert.Equal("address_missing", _verifier.Verify("", BitcoinTestVectors.Message, v.Signature, v.Network).Reason);
        Assert.Equal("message_missing", _verifier.Verify(v.Address, null!, v.Signature, v.Network).Reason);
        Assert.Equal("signature_missing", _verifier.Verify(v.Address, BitcoinTestVectors.Message, "", v.Network).Reason);
    }
}
