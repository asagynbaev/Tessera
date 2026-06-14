using System.Formats.Cbor;
using Tessera.Chains.Cardano.Internal;

namespace Tessera.Chains.Cardano.Tests;

/// <summary>
/// Regression for the Conway inline-datum decode bug: the output's <c>datum_option</c> inline arm is
/// <c>[1, data]</c> where <c>data = #6.24(bytes .cbor plutus_data)</c> — the plutus_data CBOR must be
/// wrapped in a tag-24 byte string. Emitting the raw data item makes the post_alonzo output
/// undecodable (the node rejects the validator tx before phase-1). No prior test covered this path.
/// </summary>
public class InlineDatumCborTests
{
    [Fact]
    public void InlineDatum_IsTag24WrappedByteString()
    {
        var datum = new byte[] { 0xd8, 0x79, 0x80 }; // a real plutus_data item (constr 0, no fields)
        var output = new OutputSpec(new byte[29], 2_000_000, Array.Empty<AssetAmount>(), datum);
        var body = CborTx.BuildBody(
            inputs: new[] { new InputRef(new byte[32], 0) },
            outputs: new[] { output },
            fee: 0, ttl: 0, networkId: 0);

        var (optionTag, isInlineArm, inner) = ReadFirstOutputDatumOption(body);
        Assert.Equal(1, optionTag);                                  // inline-datum arm
        Assert.True(isInlineArm, "datum_option must be [1, #6.24(bstr)]");
        Assert.Equal(datum, inner);                                  // the byte string content is the raw plutus_data
    }

    /// <summary>Walk body → outputs[0] → key 2 (datum_option) and decode [tag, isTag24, innerBytes].</summary>
    private static (int Tag, bool Tag24, byte[] Inner) ReadFirstOutputDatumOption(byte[] body)
    {
        var r = new CborReader(body);
        var n = r.ReadStartMap();
        for (int i = 0; i < n; i++)
        {
            var key = r.ReadInt32();
            if (key != 1) { r.SkipValue(); continue; }

            r.ReadStartArray();          // outputs
            var fields = r.ReadStartMap(); // first output
            int tag = -1; bool tag24 = false; byte[] inner = Array.Empty<byte>();
            for (int j = 0; j < fields; j++)
            {
                var ok = r.ReadInt32();
                if (ok != 2) { r.SkipValue(); continue; }
                r.ReadStartArray();      // datum_option [arm, data]
                tag = r.ReadInt32();     // 0 = hash, 1 = inline
                if (r.PeekState() == CborReaderState.Tag)
                {
                    tag24 = r.ReadTag() == CborTag.EncodedCborDataItem;
                    inner = r.ReadByteString();
                }
                r.ReadEndArray();
            }
            return (tag, tag24, inner);
        }
        throw new Xunit.Sdk.XunitException("no outputs (body key 1) found");
    }
}
