using System.Formats.Cbor;
using System.Text;
using System.Text.Json;
using Tessera.Chains.Cardano.Internal;

namespace Tessera.Chains.Cardano.Tests;

/// <summary>
/// Regression for the Metadata-mode <c>InvalidMetadata</c> bug: Cardano transaction metadata caps
/// every text string at 64 bytes, but the 128-char Ed25519 signature hex was written as one string,
/// so the node rejected the tx (<c>ConwayUtxowFailure InvalidMetadata</c>). The signature is now
/// written as a list of ≤64-char chunks and rejoined on read.
/// </summary>
public class MetadataStringLimitTests
{
    private static readonly string Did64 = new('a', 64);
    private static readonly string Root64 = new('b', 64);
    private static readonly string Pk64 = new('c', 64);
    private static readonly string Sig128 = new('d', 128);

    [Fact]
    public void EveryMetadataString_IsWithin64Bytes_AndSigRoundTrips()
    {
        var (aux, _) = CborTx.BuildMetadataAuxData(5446, Did64, Root64, 0, Pk64, Sig128);

        var r = new CborReader(aux);
        Assert.Equal((CborTag)259, r.ReadTag());     // Conway aux data wrapper
        r.ReadStartMap();                            // { 0 : metadata }
        Assert.Equal(0, r.ReadInt32());
        r.ReadStartMap();                            // { label : body }
        r.ReadUInt64();                              // label
        var fields = r.ReadStartMap();               // body { did, epoch, pk, root, sig }

        string? sigJoined = null;
        for (int i = 0; i < fields; i++)
        {
            var key = r.ReadTextString();
            switch (r.PeekState())
            {
                case CborReaderState.TextString:
                    var s = r.ReadTextString();
                    Assert.True(s.Length <= 64, $"metadata string '{key}' exceeds 64 bytes ({s.Length})");
                    if (key == "sig") sigJoined = s;
                    break;
                case CborReaderState.StartArray:
                    var n = r.ReadStartArray();
                    var sb = new StringBuilder();
                    for (int j = 0; j < n; j++)
                    {
                        var chunk = r.ReadTextString();
                        Assert.True(chunk.Length <= 64, $"metadata chunk of '{key}' exceeds 64 bytes ({chunk.Length})");
                        sb.Append(chunk);
                    }
                    r.ReadEndArray();
                    if (key == "sig") sigJoined = sb.ToString();
                    break;
                default:
                    r.SkipValue(); // epoch (uint)
                    break;
            }
        }

        Assert.Equal(Sig128, sigJoined); // chunks rejoin to the full 128-char signature hex
    }

    [Fact]
    public void ReadChunkedString_JoinsArray_AndAcceptsSingleString()
    {
        var arr = JsonDocument.Parse($$"""{"sig":["{{Sig128[..64]}}","{{Sig128[64..]}}"]}""").RootElement;
        Assert.Equal(Sig128, MetadataAttestation.ReadChunkedString(arr, "sig"));

        var str = JsonDocument.Parse("""{"sig":"abcd"}""").RootElement;
        Assert.Equal("abcd", MetadataAttestation.ReadChunkedString(str, "sig"));

        var missing = JsonDocument.Parse("""{}""").RootElement;
        Assert.Null(MetadataAttestation.ReadChunkedString(missing, "sig"));
    }
}
