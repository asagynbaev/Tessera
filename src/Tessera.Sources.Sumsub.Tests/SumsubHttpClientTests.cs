using System.Text.Json;
using Tessera.Sources.Sumsub;

namespace Tessera.Sources.Sumsub.Tests;

public class SumsubHttpClientTests
{
    private static SumsubHttpClientOptions Options(string baseUrl) => new()
    {
        BaseUrl = baseUrl,
        AppToken = "app-token",
        SecretKey = "secret-key",
    };

    [Fact]
    public void Ctor_DefaultHttpsBaseUrl_Succeeds()
    {
        // The default https://api.sumsub.com must keep working.
        var ex = Record.Exception(() => new SumsubHttpClient(new HttpClient(), new SumsubHttpClientOptions
        {
            AppToken = "app-token",
            SecretKey = "secret-key",
        }));
        Assert.Null(ex);
    }

    [Fact]
    public void Ctor_RejectsHttpBaseUrl()
    {
        // Never send the long-lived X-App-Token over cleartext http.
        Assert.Throws<ArgumentException>(() =>
            new SumsubHttpClient(new HttpClient(), Options("http://api.sumsub.com")));
    }

    [Fact]
    public void Ctor_RejectsNonAbsoluteOrHostlessBaseUrl()
    {
        Assert.Throws<ArgumentException>(() =>
            new SumsubHttpClient(new HttpClient(), Options("/relative/path")));
        Assert.Throws<ArgumentException>(() =>
            new SumsubHttpClient(new HttpClient(), Options("https:///no-host")));
    }

    [Fact]
    public void MapApplicant_SurfacesExternalUserId()
    {
        using var doc = JsonDocument.Parse(
            """
            {
              "externalUserId": "did:tessera:subject",
              "review": { "reviewStatus": "completed", "reviewResult": { "reviewAnswer": "GREEN" } },
              "levelName": "basic-kyc",
              "info": { "country": "KAZ" }
            }
            """);
        var review = SumsubHttpClient.MapApplicant("app-1", doc.RootElement);

        Assert.Equal("did:tessera:subject", review.ExternalUserId);
        Assert.True(review.Approved);
        Assert.Equal("basic-kyc", review.LevelName);
        Assert.Equal("KAZ", review.Country);
    }

    [Fact]
    public void MapApplicant_AbsentExternalUserId_IsNull()
    {
        using var doc = JsonDocument.Parse(
            """
            { "review": { "reviewStatus": "completed", "reviewResult": { "reviewAnswer": "GREEN" } } }
            """);
        var review = SumsubHttpClient.MapApplicant("app-1", doc.RootElement);
        Assert.Null(review.ExternalUserId);
    }
}
