using System.Text;
using NBitcoin;
using NBitcoin.Crypto;

namespace Tessera.Sources.Bitcoin;

/// <summary>Bitcoin address type, as far as control can be proven from a signed message.</summary>
public enum BitcoinAddressType
{
    /// <summary>Legacy pay-to-pubkey-hash (addresses starting <c>1</c> / <c>m</c> / <c>n</c>). Supported.</summary>
    P2pkh,

    /// <summary>Pay-to-witness-pubkey-hash nested in P2SH (addresses starting <c>3</c> / <c>2</c>). Supported.</summary>
    P2shP2wpkh,

    /// <summary>Native segwit pay-to-witness-pubkey-hash (<c>bc1q…</c> / <c>tb1q…</c>). Supported.</summary>
    P2wpkh,

    /// <summary>Taproot (<c>bc1p…</c> / <c>tb1p…</c>). NOT supported — requires BIP-322 (see remarks).</summary>
    P2tr,

    /// <summary>Anything else (P2WSH, bare multisig, non-standard). Not supported.</summary>
    Unknown,
}

/// <summary>Outcome of verifying a signed message against a claimed address.</summary>
public sealed record BitcoinSignatureVerification(bool IsValid, BitcoinAddressType AddressType, string? Reason)
{
    /// <summary>A valid signature for the given address type.</summary>
    public static BitcoinSignatureVerification Ok(BitcoinAddressType type) => new(true, type, null);

    /// <summary>An invalid signature with a reason code.</summary>
    public static BitcoinSignatureVerification Fail(BitcoinAddressType type, string reason) => new(false, type, reason);
}

/// <summary>
/// Verifies a Bitcoin <c>signmessage</c> signature against a claimed address using NBitcoin's
/// secp256k1 message recovery. The signed payload is the challenge canonical string; verification
/// recovers the public key from the (BIP-137 header, 64-byte) compact signature and checks that it
/// produces the claimed address's output script.
/// </summary>
/// <remarks>
/// <para><b>Supported (BIP-137 signmessage):</b> P2PKH, P2SH-P2WPKH, and P2WPKH. Recovery is
/// header-tolerant: the recovery id is read from the header byte and the recovered key is matched
/// against the claimed script regardless of the header's address-type hint, so signatures from
/// wallets that emit a legacy header for a segwit key still verify.</para>
/// <para><b>Not supported:</b> Taproot / P2TR. Taproot key-path control is proven with BIP-322,
/// which NBitcoin does not expose a clean "simple" verification API for; a P2TR address therefore
/// returns <see cref="BitcoinSignatureVerification.IsValid"/> = <c>false</c> with reason
/// <c>taproot_bip322_unsupported</c> rather than silently failing. P2WSH and other script types are
/// likewise unsupported. See the package README for the full address-type matrix.</para>
/// </remarks>
public sealed class BitcoinMessageSignatureVerifier
{
    private const string SignedMessageHeader = "Bitcoin Signed Message:\n";

    /// <summary>
    /// Verify <paramref name="signatureBase64"/> over <paramref name="message"/> for
    /// <paramref name="address"/> on <paramref name="network"/>. Never throws — malformed inputs
    /// return <see cref="BitcoinSignatureVerification.IsValid"/> = <c>false</c> with a reason.
    /// </summary>
    public BitcoinSignatureVerification Verify(string address, string message, string signatureBase64, BitcoinNetwork network)
    {
        if (string.IsNullOrWhiteSpace(address))
            return BitcoinSignatureVerification.Fail(BitcoinAddressType.Unknown, "address_missing");
        if (message is null)
            return BitcoinSignatureVerification.Fail(BitcoinAddressType.Unknown, "message_missing");
        if (string.IsNullOrWhiteSpace(signatureBase64))
            return BitcoinSignatureVerification.Fail(BitcoinAddressType.Unknown, "signature_missing");

        var net = BitcoinNetworkInfo.ToNBitcoin(network);

        BitcoinAddress claimed;
        try { claimed = BitcoinAddress.Create(address.Trim(), net); }
        catch { return BitcoinSignatureVerification.Fail(BitcoinAddressType.Unknown, "address_parse_failed"); }

        var type = Classify(claimed.ScriptPubKey);
        if (type == BitcoinAddressType.P2tr)
            return BitcoinSignatureVerification.Fail(BitcoinAddressType.P2tr, "taproot_bip322_unsupported");
        if (type == BitcoinAddressType.Unknown)
            return BitcoinSignatureVerification.Fail(BitcoinAddressType.Unknown, "unsupported_address_type");

        byte[] sig;
        try { sig = Convert.FromBase64String(signatureBase64.Trim()); }
        catch { return BitcoinSignatureVerification.Fail(type, "signature_base64_invalid"); }
        if (sig.Length != 65)
            return BitcoinSignatureVerification.Fail(type, "signature_length_invalid");

        int header = sig[0];
        if (header < 27 || header > 42)
            return BitcoinSignatureVerification.Fail(type, "signature_header_invalid");
        int recId = (header - 27) & 0x03;

        var sig64 = sig[1..]; // 64 bytes (r || s)
        var hash = HashSignedMessage(message);

        PubKey recovered;
        try { recovered = PubKey.RecoverCompact(hash, new CompactSignature(recId, sig64)); }
        catch { return BitcoinSignatureVerification.Fail(type, "recovery_failed"); }

        var claimedSpk = claimed.ScriptPubKey;
        bool ok = type switch
        {
            // P2PKH may have signed with either a compressed or uncompressed key — accept both forms.
            BitcoinAddressType.P2pkh =>
                Matches(EnsureCompressed(recovered), ScriptPubKeyType.Legacy, net, claimedSpk) ||
                Matches(SafeDecompress(recovered), ScriptPubKeyType.Legacy, net, claimedSpk),
            // Segwit (incl. nested) requires a compressed key.
            BitcoinAddressType.P2shP2wpkh =>
                Matches(EnsureCompressed(recovered), ScriptPubKeyType.SegwitP2SH, net, claimedSpk),
            BitcoinAddressType.P2wpkh =>
                Matches(EnsureCompressed(recovered), ScriptPubKeyType.Segwit, net, claimedSpk),
            _ => false,
        };

        return ok
            ? BitcoinSignatureVerification.Ok(type)
            : BitcoinSignatureVerification.Fail(type, "address_mismatch");
    }

    private static BitcoinAddressType Classify(Script spk)
    {
        if (spk.IsScriptType(ScriptType.P2PKH)) return BitcoinAddressType.P2pkh;
        if (spk.IsScriptType(ScriptType.P2WPKH)) return BitcoinAddressType.P2wpkh;
        if (spk.IsScriptType(ScriptType.P2SH)) return BitcoinAddressType.P2shP2wpkh;
        if (spk.IsScriptType(ScriptType.Taproot)) return BitcoinAddressType.P2tr;
        return BitcoinAddressType.Unknown;
    }

    private static bool Matches(PubKey? pk, ScriptPubKeyType type, Network net, Script claimedSpk)
    {
        if (pk is null) return false;
        try
        {
            var spk = pk.GetAddress(type, net).ScriptPubKey;
            return spk.ToBytes().AsSpan().SequenceEqual(claimedSpk.ToBytes());
        }
        catch { return false; }
    }

    private static PubKey EnsureCompressed(PubKey pk) => pk.IsCompressed ? pk : pk.Compress();

    private static PubKey? SafeDecompress(PubKey pk)
    {
        try { return pk.IsCompressed ? pk.Decompress() : pk; }
        catch { return null; }
    }

    /// <summary>
    /// The Bitcoin signed-message digest: <c>dSHA256( varint(len(magic)) ‖ magic ‖ varint(len(msg)) ‖ msg )</c>
    /// where <c>magic = "Bitcoin Signed Message:\n"</c>. Identical on every network.
    /// </summary>
    private static uint256 HashSignedMessage(string message)
    {
        var headerBytes = Encoding.UTF8.GetBytes(SignedMessageHeader);
        var msgBytes = Encoding.UTF8.GetBytes(message);
        using var ms = new MemoryStream();
        WriteVarInt(ms, (ulong)headerBytes.Length);
        ms.Write(headerBytes, 0, headerBytes.Length);
        WriteVarInt(ms, (ulong)msgBytes.Length);
        ms.Write(msgBytes, 0, msgBytes.Length);
        return Hashes.DoubleSHA256(ms.ToArray());
    }

    /// <summary>Bitcoin CompactSize (varint) encoding.</summary>
    private static void WriteVarInt(Stream s, ulong value)
    {
        if (value < 0xFD)
        {
            s.WriteByte((byte)value);
        }
        else if (value <= 0xFFFF)
        {
            s.WriteByte(0xFD);
            s.WriteByte((byte)value);
            s.WriteByte((byte)(value >> 8));
        }
        else if (value <= 0xFFFFFFFF)
        {
            s.WriteByte(0xFE);
            for (int i = 0; i < 4; i++) s.WriteByte((byte)(value >> (8 * i)));
        }
        else
        {
            s.WriteByte(0xFF);
            for (int i = 0; i < 8; i++) s.WriteByte((byte)(value >> (8 * i)));
        }
    }
}
