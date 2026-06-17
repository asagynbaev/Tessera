namespace Tessera.Core;

using System.Numerics;
using System.Text;

/// <summary>
/// Base58 encoding (Bitcoin alphabet). Used for DID identifier serialization and
/// multibase encoding of public keys. Pure managed; no native deps.
/// </summary>
public static class Base58
{
    private const string Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return string.Empty;

        int leadingZeros = 0;
        while (leadingZeros < data.Length && data[leadingZeros] == 0) leadingZeros++;

        var bi = new BigInteger(data, isUnsigned: true, isBigEndian: true);
        var sb = new StringBuilder();
        var fiftyEight = new BigInteger(58);
        while (bi > 0)
        {
            bi = BigInteger.DivRem(bi, fiftyEight, out var rem);
            sb.Insert(0, Alphabet[(int)rem]);
        }
        for (int i = 0; i < leadingZeros; i++) sb.Insert(0, Alphabet[0]);
        return sb.ToString();
    }

    /// <summary>
    /// Maximum accepted input length. Legitimate Tessera values (32-byte hashes, public keys) encode
    /// to ~50 chars; the cap bounds the O(n²) BigInteger decode against an unbounded-input DoS.
    /// </summary>
    private const int MaxEncodedLength = 512;

    public static byte[] Decode(ReadOnlySpan<char> s)
    {
        if (s.IsEmpty) return Array.Empty<byte>();
        if (s.Length > MaxEncodedLength)
            throw new FormatException($"Base58 input too long ({s.Length} > {MaxEncodedLength}).");

        int leadingZeros = 0;
        while (leadingZeros < s.Length && s[leadingZeros] == Alphabet[0]) leadingZeros++;

        BigInteger bi = 0;
        var fiftyEight = new BigInteger(58);
        for (int i = 0; i < s.Length; i++)
        {
            int idx = Alphabet.IndexOf(s[i]);
            if (idx < 0) throw new FormatException($"Invalid Base58 character: '{s[i]}'.");
            bi = bi * fiftyEight + idx;
        }

        // A zero value (all-'1' input) must contribute no value bytes: ToByteArray would emit a
        // spurious 0x00 that double-counts with the leading-zero prefix added below.
        var bytes = bi.IsZero ? Array.Empty<byte>() : bi.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (leadingZeros == 0) return bytes;

        var result = new byte[leadingZeros + bytes.Length];
        Buffer.BlockCopy(bytes, 0, result, leadingZeros, bytes.Length);
        return result;
    }
}
