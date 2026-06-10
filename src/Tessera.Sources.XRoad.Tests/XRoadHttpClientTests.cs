using Tessera.Sources.XRoad;

namespace Tessera.Sources.XRoad.Tests;

public class XRoadHttpClientTests
{
    private static XRoadHttpClient NewClient() => new(
        new HttpClient(),
        new XRoadHttpClientOptions
        {
            SecurityServerUrl = "https://ss.example.gov",
            ClientId = "KZ/GOV/1234/tessera",
            ServiceId = "PROP-REGISTRY",
        });

    [Fact]
    public void BuildRequest_SetsXRoadClientHeader_AndServicePath()
    {
        var req = NewClient().BuildRequest(new XRoadQuery { NationalId = "123456", ParcelId = "09-1" });

        Assert.True(req.Headers.Contains("X-Road-Client"));
        Assert.Equal("KZ/GOV/1234/tessera", req.Headers.GetValues("X-Road-Client").Single());
        Assert.Contains("/r1/PROP-REGISTRY/persons/123456", req.RequestUri!.AbsoluteUri);
        Assert.Contains("parcel=09-1", req.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public void BuildRequest_WithoutParcel_OmitsQuery()
    {
        var req = NewClient().BuildRequest(new XRoadQuery { NationalId = "123456" });
        Assert.DoesNotContain("parcel=", req.RequestUri!.AbsoluteUri);
    }

    [Fact]
    public void Ctor_Validates_RequiredOptions()
    {
        Assert.Throws<ArgumentException>(() => new XRoadHttpClient(new HttpClient(),
            new XRoadHttpClientOptions { SecurityServerUrl = "", ClientId = "c", ServiceId = "s" }));
    }
}
