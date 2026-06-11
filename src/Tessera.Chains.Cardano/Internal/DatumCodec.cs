using System.Formats.Cbor;
using System.Numerics;

namespace Tessera.Chains.Cardano.Internal;

/// <summary>Value form of the on-chain <c>DidAnchorDatum</c> (mirrors the Aiken type).</summary>
internal sealed record DidAnchorDatumValue(
    byte[] DidHash,
    byte[] AttestationRoot,
    ulong RevocationEpoch,
    byte[] Controller);

/// <summary>
/// Encodes datums and redeemers to Plutus-data CBOR, and decodes inline datums read back from
/// the chain — all via the BCL <see cref="CborWriter"/>/<see cref="CborReader"/>. Constructor
/// indices match the Aiken declaration order exactly (Constr 0 = first variant).
/// </summary>
internal static class DatumCodec
{
    private const ulong ConstrTagBase = 121; // CBOR tag for Plutus constructor index 0 (0..6 → 121..127)

    // ── encode ───────────────────────────────────────────────────────────────

    /// <summary>DidAnchorDatum = Constr 0 [bytes did_hash, bytes attestation_root, int epoch, bytes controller].</summary>
    public static byte[] EncodeAnchorDatum(DidAnchorDatumValue d)
    {
        var w = NewWriter();
        WriteConstrHeader(w, 0, 4);
        w.WriteByteString(d.DidHash);
        w.WriteByteString(d.AttestationRoot);
        w.WriteUInt64(d.RevocationEpoch);
        w.WriteByteString(d.Controller);
        w.WriteEndArray();
        return w.Encode();
    }

    /// <summary>IssuerDatum = Constr 0 [bytes issuer_did_hash, bytes schema_uri_hash, bytes issuer_pubkey].</summary>
    public static byte[] EncodeIssuerDatum(byte[] issuerDidHash, byte[] schemaUriHash, byte[] issuerPubkey)
    {
        var w = NewWriter();
        WriteConstrHeader(w, 0, 3);
        w.WriteByteString(issuerDidHash);
        w.WriteByteString(schemaUriHash);
        w.WriteByteString(issuerPubkey);
        w.WriteEndArray();
        return w.Encode();
    }

    /// <summary>AnchorMintRedeemer.RegisterDid = Constr 0 [].</summary>
    public static byte[] RegisterDidRedeemer() => UnitConstr(0);

    /// <summary>IssuerMintRedeemer.RegisterIssuer = Constr 0 [].</summary>
    public static byte[] RegisterIssuerRedeemer() => UnitConstr(0);

    /// <summary>DidRedeemer.UpdateRoot { new_root } = Constr 0 [bytes new_root].</summary>
    public static byte[] UpdateRootRedeemer(byte[] newRoot)
    {
        var w = NewWriter();
        WriteConstrHeader(w, 0, 1);
        w.WriteByteString(newRoot);
        w.WriteEndArray();
        return w.Encode();
    }

    /// <summary>DidRedeemer.BumpRevocation { reason } = Constr 1 [int reason].</summary>
    public static byte[] BumpRevocationRedeemer(int reason)
    {
        var w = NewWriter();
        WriteConstrHeader(w, 1, 1);
        w.WriteInt32(reason);
        w.WriteEndArray();
        return w.Encode();
    }

    private static byte[] UnitConstr(ulong alternative)
    {
        var w = NewWriter();
        WriteConstrHeader(w, alternative, 0);
        w.WriteEndArray();
        return w.Encode();
    }

    private static CborWriter NewWriter() => new(CborConformanceMode.Canonical);

    private static void WriteConstrHeader(CborWriter w, ulong alternative, int fieldCount)
    {
        // Compact tag form for constructors 0..6 (121..127). The validators only use 0 and 1.
        w.WriteTag((CborTag)(ConstrTagBase + alternative));
        w.WriteStartArray(fieldCount);
    }

    // ── decode ───────────────────────────────────────────────────────────────

    /// <summary>Parse the CBOR of an inline <c>DidAnchorDatum</c> (as returned by the provider).</summary>
    public static DidAnchorDatumValue DecodeAnchorDatum(byte[] datumCbor)
    {
        ArgumentNullException.ThrowIfNull(datumCbor);
        var reader = new CborReader(datumCbor, CborConformanceMode.Lax);
        var tag = (ulong)reader.ReadTag();
        if (tag != ConstrTagBase)
            throw new InvalidOperationException($"Expected DidAnchorDatum constructor tag {ConstrTagBase}, got {tag}.");
        reader.ReadStartArray();
        var didHash = reader.ReadByteString();
        var root = reader.ReadByteString();
        var epoch = ReadUnsignedInteger(reader);
        var controller = reader.ReadByteString();
        reader.ReadEndArray();
        return new DidAnchorDatumValue(didHash, root, epoch, controller);
    }

    private static ulong ReadUnsignedInteger(CborReader reader)
    {
        var state = reader.PeekState();
        switch (state)
        {
            case CborReaderState.UnsignedInteger:
                return reader.ReadUInt64();
            case CborReaderState.Tag:
                _ = reader.ReadTag(); // Plutus encodes integers > 64 bits as a CBOR bignum (tag 2 / 3).
                var magnitude = reader.ReadByteString();
                return (ulong)new BigInteger(magnitude, isUnsigned: true, isBigEndian: true);
            default:
                throw new InvalidOperationException($"Unexpected CBOR state for an unsigned integer: {state}.");
        }
    }
}
