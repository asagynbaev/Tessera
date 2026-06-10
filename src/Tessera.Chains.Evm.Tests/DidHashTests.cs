using System.Security.Cryptography;
using System.Text;
using Tessera.Chains;
using Tessera.Core;

namespace Tessera.Chains.Evm.Tests;

public class DidHashTests
{
    [Fact]
    public void Compute_Is32Bytes_AndEqualsSha256OfUtf8()
    {
        var hash = DidHash.Compute(new DidId("did:tessera:alice"));
        Assert.Equal(32, hash.Length);
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes("did:tessera:alice")), hash);
    }

    [Fact]
    public void Compute_IsDeterministic()
    {
        var did = new DidId("did:tessera:bob");
        Assert.Equal(DidHash.Compute(did), DidHash.Compute(did));
    }

    [Fact]
    public void Compute_DistinctDids_ProduceDistinctHashes()
    {
        Assert.NotEqual(
            DidHash.Compute(new DidId("did:tessera:alice")),
            DidHash.Compute(new DidId("did:tessera:bob")));
    }

    [Fact]
    public void Compute_Throws_OnEmptyDid()
        => Assert.Throws<ArgumentException>(() => DidHash.Compute(default));
}
