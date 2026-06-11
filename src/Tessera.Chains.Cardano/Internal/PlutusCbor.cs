using System.Formats.Cbor;
using CardanoSharp.Wallet.Utilities;

namespace Tessera.Chains.Cardano.Internal;

/// <summary>A redeemer ready to serialise: purpose tag, input index, its Plutus data, and execution units.</summary>
internal sealed record RedeemerEntry(int Tag, uint Index, byte[] PlutusDataCbor, ulong Mem, ulong Steps)
{
    public const int SpendTag = 0;
    public const int MintTag = 1;
}

/// <summary>
/// The Conway / Plutus V3 CBOR pieces that CardanoSharp 5.1.0 (Babbage-era) does not emit:
/// the language-views encoding, the map-form redeemers, the script-data hash, and a witness set
/// carrying the V3 script under map key 7. Built with the BCL <see cref="CborWriter"/>.
/// </summary>
internal static class PlutusCbor
{
    private const int PlutusV3LanguageId = 2;

    // Transaction witness-set map keys (Conway CDDL).
    private const int WitnessVKeys = 0;
    private const int WitnessRedeemers = 5;
    private const int WitnessPlutusV3Scripts = 7;

    /// <summary>
    /// <c>language_views = { 2 : [ v3 cost model ] }</c>, canonically encoded — the exact bytes
    /// the ledger folds into the script-data hash for a Plutus V3 transaction.
    /// </summary>
    public static byte[] LanguageViews(long[] plutusV3CostModel)
    {
        var w = new CborWriter(CborConformanceMode.Canonical);
        w.WriteStartMap(1);
        w.WriteInt32(PlutusV3LanguageId);
        w.WriteStartArray(plutusV3CostModel.Length);
        foreach (var c in plutusV3CostModel) w.WriteInt64(c);
        w.WriteEndArray();
        w.WriteEndMap();
        return w.Encode();
    }

    /// <summary>
    /// Conway map-form redeemers: <c>{ [tag, index] => [data, [mem, steps]] }</c>. The same bytes
    /// go into both the witness set and the script-data-hash preimage, so they are computed once.
    /// </summary>
    public static byte[] Redeemers(IReadOnlyList<RedeemerEntry> redeemers)
    {
        var w = new CborWriter(CborConformanceMode.Canonical);
        w.WriteStartMap(redeemers.Count);
        foreach (var r in redeemers)
        {
            w.WriteStartArray(2);          // key: [tag, index]
            w.WriteInt32(r.Tag);
            w.WriteUInt32(r.Index);
            w.WriteEndArray();
            w.WriteStartArray(2);          // value: [data, [mem, steps]]
            w.WriteEncodedValue(r.PlutusDataCbor);
            w.WriteStartArray(2);
            w.WriteUInt64(r.Mem);
            w.WriteUInt64(r.Steps);
            w.WriteEndArray();
            w.WriteEndArray();
        }
        w.WriteEndMap();
        return w.Encode();
    }

    /// <summary>
    /// Script-data hash = blake2b-256( redeemers ‖ language_views ). Datums are omitted because
    /// the adapter only uses inline datums (no witness datums), matching the ledger rule.
    /// </summary>
    public static byte[] ScriptDataHash(byte[] redeemersCbor, byte[] languageViews)
    {
        var buffer = new byte[redeemersCbor.Length + languageViews.Length];
        Buffer.BlockCopy(redeemersCbor, 0, buffer, 0, redeemersCbor.Length);
        Buffer.BlockCopy(languageViews, 0, buffer, redeemersCbor.Length, languageViews.Length);
        return HashUtility.Blake2b256(buffer);
    }

    /// <summary>
    /// Witness set CBOR: vkey witnesses (key 0), the map-form redeemers (key 5), and the V3 script
    /// (key 7). The script bytes are the raw blueprint <c>compiledCode</c>.
    /// </summary>
    public static byte[] WitnessSet(IReadOnlyList<(byte[] VKey, byte[] Signature)> vkeyWitnesses, byte[] redeemersCbor, byte[] scriptBytes)
    {
        var w = new CborWriter(CborConformanceMode.Canonical);
        w.WriteStartMap(3);

        w.WriteInt32(WitnessVKeys);
        w.WriteStartArray(vkeyWitnesses.Count);
        foreach (var (vkey, sig) in vkeyWitnesses)
        {
            w.WriteStartArray(2);
            w.WriteByteString(vkey);
            w.WriteByteString(sig);
            w.WriteEndArray();
        }
        w.WriteEndArray();

        w.WriteInt32(WitnessRedeemers);
        w.WriteEncodedValue(redeemersCbor);

        w.WriteInt32(WitnessPlutusV3Scripts);
        w.WriteStartArray(1);
        w.WriteByteString(scriptBytes);
        w.WriteEndArray();

        w.WriteEndMap();
        return w.Encode();
    }

    /// <summary>Witness set with only vkey witnesses (key 0) — for the Metadata-mode payment tx.</summary>
    public static byte[] VKeyWitnessSet(IReadOnlyList<(byte[] VKey, byte[] Signature)> vkeyWitnesses)
    {
        var w = new CborWriter(CborConformanceMode.Canonical);
        w.WriteStartMap(1);
        w.WriteInt32(WitnessVKeys);
        w.WriteStartArray(vkeyWitnesses.Count);
        foreach (var (vkey, sig) in vkeyWitnesses)
        {
            w.WriteStartArray(2);
            w.WriteByteString(vkey);
            w.WriteByteString(sig);
            w.WriteEndArray();
        }
        w.WriteEndArray();
        w.WriteEndMap();
        return w.Encode();
    }

    /// <summary>Final transaction CBOR: <c>[ body, witness_set, is_valid, auxiliary_data ]</c>.</summary>
    public static byte[] Transaction(byte[] bodyCbor, byte[] witnessSetCbor, byte[]? auxiliaryDataCbor)
    {
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartArray(4);
        w.WriteEncodedValue(bodyCbor);
        w.WriteEncodedValue(witnessSetCbor);
        w.WriteBoolean(true); // is_valid
        if (auxiliaryDataCbor is null) w.WriteNull();
        else w.WriteEncodedValue(auxiliaryDataCbor);
        w.WriteEndArray();
        return w.Encode();
    }

    /// <summary>blake2b-256 of the transaction body — the message the controller signs and the tx id.</summary>
    public static byte[] TransactionBodyHash(byte[] bodyCbor) => HashUtility.Blake2b256(bodyCbor);
}
