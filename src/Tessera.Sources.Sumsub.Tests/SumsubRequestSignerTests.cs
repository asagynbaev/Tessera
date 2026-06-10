using Tessera.Sources.Sumsub;

namespace Tessera.Sources.Sumsub.Tests;

public class SumsubRequestSignerTests
{
    [Fact]
    public void Sign_IsDeterministic_AndHex64()
    {
        var a = SumsubRequestSigner.Sign("secret", 1_700_000_000, "GET", "/resources/applicants/x/one", "");
        var b = SumsubRequestSigner.Sign("secret", 1_700_000_000, "GET", "/resources/applicants/x/one", "");
        Assert.Equal(a, b);
        Assert.Equal(64, a.Length);                    // SHA-256 hex
        Assert.Matches("^[0-9a-f]{64}$", a);
    }

    [Fact]
    public void Sign_IsSensitiveTo_EveryInput()
    {
        var baseSig = SumsubRequestSigner.Sign("secret", 1_700_000_000, "GET", "/p", "");
        Assert.NotEqual(baseSig, SumsubRequestSigner.Sign("other", 1_700_000_000, "GET", "/p", ""));
        Assert.NotEqual(baseSig, SumsubRequestSigner.Sign("secret", 1_700_000_001, "GET", "/p", ""));
        Assert.NotEqual(baseSig, SumsubRequestSigner.Sign("secret", 1_700_000_000, "POST", "/p", ""));
        Assert.NotEqual(baseSig, SumsubRequestSigner.Sign("secret", 1_700_000_000, "GET", "/q", ""));
        Assert.NotEqual(baseSig, SumsubRequestSigner.Sign("secret", 1_700_000_000, "GET", "/p", "{}"));
    }

    [Fact]
    public void Sign_MethodCaseInsensitive()
        => Assert.Equal(
            SumsubRequestSigner.Sign("k", 1, "GET", "/p", ""),
            SumsubRequestSigner.Sign("k", 1, "get", "/p", ""));
}
