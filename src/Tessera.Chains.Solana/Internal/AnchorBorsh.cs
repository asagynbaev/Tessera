using System.Buffers.Binary;
using System.Text;

namespace Tessera.Chains.Solana.Internal;

/// <summary>
/// Minimal Borsh writer covering the subset of types the identity-registry program needs:
/// <c>u8</c>, <c>bool</c>, <c>u64</c>, <c>i64</c>, fixed-size byte arrays, <c>Pubkey ([u8; 32])</c>,
/// and length-prefixed UTF-8 strings.
/// </summary>
/// <remarks>
/// Borsh encodes integers as little-endian, strings as <c>(u32 length) || utf8 bytes</c>,
/// bools as single bytes (0 or 1). No sentinels, no padding, no version tags.
/// </remarks>
internal sealed class AnchorBorshWriter
{
    private readonly MemoryStream _stream = new();

    public byte[] ToArray() => _stream.ToArray();

    public AnchorBorshWriter WriteU8(byte v)
    {
        _stream.WriteByte(v);
        return this;
    }

    public AnchorBorshWriter WriteBool(bool v)
    {
        _stream.WriteByte(v ? (byte)1 : (byte)0);
        return this;
    }

    public AnchorBorshWriter WriteU32(uint v)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(buf, v);
        _stream.Write(buf);
        return this;
    }

    public AnchorBorshWriter WriteU64(ulong v)
    {
        Span<byte> buf = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(buf, v);
        _stream.Write(buf);
        return this;
    }

    public AnchorBorshWriter WriteI64(long v)
    {
        Span<byte> buf = stackalloc byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(buf, v);
        _stream.Write(buf);
        return this;
    }

    /// <summary>Write a fixed-size byte array verbatim (e.g. [u8; 32]).</summary>
    public AnchorBorshWriter WriteFixedBytes(ReadOnlySpan<byte> bytes, int expectedLength)
    {
        if (bytes.Length != expectedLength)
            throw new ArgumentException($"Expected {expectedLength} bytes, got {bytes.Length}.", nameof(bytes));
        _stream.Write(bytes);
        return this;
    }

    /// <summary>Write a Pubkey (32 raw bytes).</summary>
    public AnchorBorshWriter WritePubkey(ReadOnlySpan<byte> pubkey)
        => WriteFixedBytes(pubkey, 32);

    /// <summary>Write a Borsh string: u32 length prefix + UTF-8 payload.</summary>
    public AnchorBorshWriter WriteString(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        WriteU32((uint)bytes.Length);
        _stream.Write(bytes);
        return this;
    }
}

/// <summary>Companion reader for Borsh-encoded payloads.</summary>
internal ref struct AnchorBorshReader
{
    private ReadOnlySpan<byte> _buf;

    public AnchorBorshReader(ReadOnlySpan<byte> buf) { _buf = buf; }

    public int Remaining => _buf.Length;

    public byte ReadU8()
    {
        var v = _buf[0];
        _buf = _buf[1..];
        return v;
    }

    public bool ReadBool() => ReadU8() != 0;

    public ulong ReadU64()
    {
        var v = BinaryPrimitives.ReadUInt64LittleEndian(_buf);
        _buf = _buf[8..];
        return v;
    }

    public long ReadI64()
    {
        var v = BinaryPrimitives.ReadInt64LittleEndian(_buf);
        _buf = _buf[8..];
        return v;
    }

    public uint ReadU32()
    {
        var v = BinaryPrimitives.ReadUInt32LittleEndian(_buf);
        _buf = _buf[4..];
        return v;
    }

    public byte[] ReadFixedBytes(int length)
    {
        if (length < 0 || length > _buf.Length)
            throw new FormatException($"Borsh: cannot read {length} bytes ({_buf.Length} remaining).");
        var result = _buf[..length].ToArray();
        _buf = _buf[length..];
        return result;
    }

    public byte[] ReadPubkey() => ReadFixedBytes(32);

    public string ReadString()
    {
        // The u32 length is attacker-controlled (raw on-chain account bytes); reject anything that
        // overruns the buffer before slicing. The (int) cast also turns lengths >= 2^31 negative.
        var len = (int)ReadU32();
        if (len < 0 || len > _buf.Length)
            throw new FormatException($"Borsh: string length {len} exceeds {_buf.Length} remaining bytes.");
        var bytes = _buf[..len];
        var s = Encoding.UTF8.GetString(bytes);
        _buf = _buf[len..];
        return s;
    }

    /// <summary>Skip n bytes (used to skip the 8-byte Anchor account discriminator).</summary>
    public void Skip(int n) => _buf = _buf[n..];
}
