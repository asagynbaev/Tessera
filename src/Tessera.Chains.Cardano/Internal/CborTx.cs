using System.Formats.Cbor;
using CardanoSharp.Wallet.Utilities;

namespace Tessera.Chains.Cardano.Internal;

/// <summary>A native asset held in or minted by an output (policy id, asset name, quantity).</summary>
internal sealed record AssetAmount(byte[] Policy, byte[] AssetName, long Quantity);

/// <summary>A transaction output: address, ADA, optional native assets, optional inline datum.</summary>
internal sealed record OutputSpec(
    byte[] AddressBytes,
    ulong Coin,
    IReadOnlyList<AssetAmount> Assets,
    byte[]? InlineDatumCbor);

/// <summary>A UTxO reference being spent / used as collateral.</summary>
internal sealed record InputRef(byte[] TxHash, ulong Index);

/// <summary>
/// Hand-builds the Conway transaction body and the metadata auxiliary data with the BCL
/// <see cref="CborWriter"/>. Keys are written in ascending order as canonical CBOR requires.
/// CardanoSharp 5.1.0 cannot emit the Plutus V3 / Conway shapes, so the body is built here.
/// </summary>
internal static class CborTx
{
    /// <summary>
    /// Build the transaction body. Plutus fields (mint, script_data_hash, collateral,
    /// required_signers, collateral_return, total_collateral) and the metadata
    /// auxiliary_data_hash are all optional, so this serves both anchor modes.
    /// </summary>
    public static byte[] BuildBody(
        IReadOnlyList<InputRef> inputs,
        IReadOnlyList<OutputSpec> outputs,
        ulong fee,
        ulong ttl,
        byte networkId,
        byte[]? auxiliaryDataHash = null,
        IReadOnlyList<AssetAmount>? mint = null,
        byte[]? scriptDataHash = null,
        IReadOnlyList<InputRef>? collateral = null,
        IReadOnlyList<byte[]>? requiredSigners = null,
        OutputSpec? collateralReturn = null,
        ulong? totalCollateral = null)
    {
        // Count the keys we will emit (body is a CBOR map with integer keys).
        var keys = 5; // 0 inputs, 1 outputs, 2 fee, 3 ttl, 15 network_id
        if (auxiliaryDataHash is not null) keys++;
        if (mint is { Count: > 0 }) keys++;
        if (scriptDataHash is not null) keys++;
        if (collateral is { Count: > 0 }) keys++;
        if (requiredSigners is { Count: > 0 }) keys++;
        if (collateralReturn is not null) keys++;
        if (totalCollateral is not null) keys++;

        var w = new CborWriter(CborConformanceMode.Canonical);
        w.WriteStartMap(keys);

        // 0: inputs
        w.WriteInt32(0);
        WriteInputs(w, inputs);

        // 1: outputs
        w.WriteInt32(1);
        w.WriteStartArray(outputs.Count);
        foreach (var o in outputs) WriteOutput(w, o);
        w.WriteEndArray();

        // 2: fee
        w.WriteInt32(2);
        w.WriteUInt64(fee);

        // 3: ttl
        w.WriteInt32(3);
        w.WriteUInt64(ttl);

        // 7: auxiliary_data_hash
        if (auxiliaryDataHash is not null)
        {
            w.WriteInt32(7);
            w.WriteByteString(auxiliaryDataHash);
        }

        // 9: mint
        if (mint is { Count: > 0 })
        {
            w.WriteInt32(9);
            WriteMultiAsset(w, mint, m => m.Quantity);
        }

        // 11: script_data_hash
        if (scriptDataHash is not null)
        {
            w.WriteInt32(11);
            w.WriteByteString(scriptDataHash);
        }

        // 13: collateral inputs
        if (collateral is { Count: > 0 })
        {
            w.WriteInt32(13);
            WriteInputs(w, collateral);
        }

        // 14: required signers
        if (requiredSigners is { Count: > 0 })
        {
            w.WriteInt32(14);
            w.WriteStartArray(requiredSigners.Count);
            foreach (var s in requiredSigners) w.WriteByteString(s);
            w.WriteEndArray();
        }

        // 15: network id
        w.WriteInt32(15);
        w.WriteUInt32(networkId);

        // 16: collateral return
        if (collateralReturn is not null)
        {
            w.WriteInt32(16);
            WriteOutput(w, collateralReturn);
        }

        // 17: total collateral
        if (totalCollateral is not null)
        {
            w.WriteInt32(17);
            w.WriteUInt64(totalCollateral.Value);
        }

        w.WriteEndMap();
        return w.Encode();
    }

    private static void WriteInputs(CborWriter w, IReadOnlyList<InputRef> inputs)
    {
        w.WriteStartArray(inputs.Count);
        foreach (var i in inputs)
        {
            w.WriteStartArray(2);
            w.WriteByteString(i.TxHash);
            w.WriteUInt64(i.Index);
            w.WriteEndArray();
        }
        w.WriteEndArray();
    }

    private static void WriteOutput(CborWriter w, OutputSpec o)
    {
        var fields = 2 + (o.InlineDatumCbor is not null ? 1 : 0);
        w.WriteStartMap(fields);

        w.WriteInt32(0); // address
        w.WriteByteString(o.AddressBytes);

        w.WriteInt32(1); // value
        if (o.Assets.Count == 0)
        {
            w.WriteUInt64(o.Coin);
        }
        else
        {
            w.WriteStartArray(2);
            w.WriteUInt64(o.Coin);
            WriteMultiAsset(w, o.Assets, a => (long)a.Quantity);
            w.WriteEndArray();
        }

        if (o.InlineDatumCbor is not null)
        {
            w.WriteInt32(2); // datum_option = [1, data]
            w.WriteStartArray(2);
            w.WriteInt32(1);
            w.WriteEncodedValue(o.InlineDatumCbor);
            w.WriteEndArray();
        }

        w.WriteEndMap();
    }

    /// <summary>Write a multiasset map { policy : { asset_name : qty } } in canonical order.</summary>
    private static void WriteMultiAsset(CborWriter w, IReadOnlyList<AssetAmount> assets, Func<AssetAmount, long> qty)
    {
        var byPolicy = assets
            .GroupBy(a => a.Policy, ByteArrayComparer.Instance)
            .OrderBy(g => g.Key, ByteArrayComparer.Instance)
            .ToList();

        w.WriteStartMap(byPolicy.Count);
        foreach (var policyGroup in byPolicy)
        {
            w.WriteByteString(policyGroup.Key);
            var names = policyGroup.OrderBy(a => a.AssetName, ByteArrayComparer.Instance).ToList();
            w.WriteStartMap(names.Count);
            foreach (var a in names)
            {
                w.WriteByteString(a.AssetName);
                var q = qty(a);
                if (q < 0) w.WriteInt64(q); else w.WriteUInt64((ulong)q);
            }
            w.WriteEndMap();
        }
        w.WriteEndMap();
    }

    // ── metadata auxiliary data ────────────────────────────────────────────────

    /// <summary>
    /// Build Conway auxiliary data <c>#6.259({ 0 : metadata })</c> where metadata is
    /// <c>{ label : { "did": h, "root": h, "epoch": n } }</c>, and return it with its blake2b-256 hash.
    /// </summary>
    public static (byte[] AuxData, byte[] Hash) BuildMetadataAuxData(ulong label, string didHashHex, string rootHex, ulong epoch)
    {
        var w = new CborWriter(CborConformanceMode.Canonical);
        w.WriteTag((CborTag)259); // Conway alonzo-style auxiliary data
        w.WriteStartMap(1);
        w.WriteInt32(0); // transaction_metadata
        w.WriteStartMap(1);
        w.WriteUInt64(label);
        w.WriteStartMap(3);
        w.WriteTextString("did");
        w.WriteTextString(didHashHex);
        w.WriteTextString("epoch");
        w.WriteUInt64(epoch);
        w.WriteTextString("root");
        w.WriteTextString(rootHex);
        w.WriteEndMap();
        w.WriteEndMap();
        w.WriteEndMap();
        var aux = w.Encode();
        return (aux, HashUtility.Blake2b256(aux));
    }
}

/// <summary>Lexicographic byte-array comparer for canonical CBOR key ordering.</summary>
internal sealed class ByteArrayComparer : IComparer<byte[]>, IEqualityComparer<byte[]>
{
    public static readonly ByteArrayComparer Instance = new();

    public int Compare(byte[]? x, byte[]? y)
    {
        if (x is null || y is null) return (x is null ? 0 : 1) - (y is null ? 0 : 1);
        var min = Math.Min(x.Length, y.Length);
        for (var i = 0; i < min; i++)
        {
            var c = x[i].CompareTo(y[i]);
            if (c != 0) return c;
        }
        return x.Length.CompareTo(y.Length);
    }

    public bool Equals(byte[]? x, byte[]? y) => Compare(x, y) == 0;

    public int GetHashCode(byte[] obj)
    {
        var hash = new HashCode();
        hash.AddBytes(obj);
        return hash.ToHashCode();
    }
}
