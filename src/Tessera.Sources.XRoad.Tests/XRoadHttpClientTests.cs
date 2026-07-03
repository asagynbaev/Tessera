using System.Text.Json;
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

    [Fact]
    public void Ctor_RejectsHttpSecurityServerUrl()
    {
        // X-Road requires mutually-authenticated TLS; refuse cleartext http.
        Assert.Throws<ArgumentException>(() => new XRoadHttpClient(new HttpClient(),
            new XRoadHttpClientOptions { SecurityServerUrl = "http://ss.example.gov", ClientId = "c", ServiceId = "s" }));
    }

    [Fact]
    public void Ctor_RejectsNonAbsoluteSecurityServerUrl()
    {
        Assert.Throws<ArgumentException>(() => new XRoadHttpClient(new HttpClient(),
            new XRoadHttpClientOptions { SecurityServerUrl = "ss.example.gov", ClientId = "c", ServiceId = "s" }));
    }

    [Fact]
    public void CreateHardenedHandler_DisablesAutoRedirect()
    {
        // L-2: following a redirect would replay the X-Road-Client subsystem header to the target.
        using var handler = XRoadHttpClient.CreateHardenedHandler();
        Assert.False(handler.AllowAutoRedirect);
    }

    [Fact]
    public void MapRecord_UsesServerAssertedNationalIdAndParcel()
    {
        using var doc = JsonDocument.Parse(
            """
            {
              "personFound": true,
              "nationalId": "123456",
              "residencyCountry": "KZ",
              "property": { "ownershipConfirmed": true, "parcelId": "SERVER-09-1", "encumbrance": "none" }
            }
            """);
        // Caller passed a DIFFERENT parcel id in the query; the server-asserted one must win.
        var record = XRoadHttpClient.MapRecord(new XRoadQuery { NationalId = "123456", ParcelId = "CALLER-99" }, doc.RootElement);

        Assert.True(record.PersonFound);
        Assert.Equal("123456", record.AssertedNationalId);
        Assert.Equal("SERVER-09-1", record.ParcelId);
        Assert.Equal("none", record.EncumbranceStatus);
    }

    [Fact]
    public void MapRecord_FallsBackToQueryParcel_WhenResponseOmitsIt()
    {
        using var doc = JsonDocument.Parse(
            """
            { "personFound": true, "property": { "ownershipConfirmed": true } }
            """);
        var record = XRoadHttpClient.MapRecord(new XRoadQuery { NationalId = "123456", ParcelId = "CALLER-99" }, doc.RootElement);

        Assert.Null(record.AssertedNationalId);
        Assert.Equal("CALLER-99", record.ParcelId);
    }
}
