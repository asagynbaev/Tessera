using Tessera.Attestations;
using Tessera.Core;
using Tessera.Sources.XRoad;

namespace Tessera.Sources.XRoad.Tests;

public class XRoadAttestationSourceTests
{
    private sealed class FakeClient : IXRoadClient
    {
        private readonly XRoadRegistryRecord? _record;
        public XRoadQuery? LastQuery { get; private set; }
        public FakeClient(XRoadRegistryRecord? record) => _record = record;
        public Task<XRoadRegistryRecord?> LookupAsync(XRoadQuery query, CancellationToken ct = default)
        {
            LastQuery = query;
            return Task.FromResult(_record);
        }
    }

    private static SubjectContext Subject(string? nationalId, string? parcelId = null)
    {
        var p = new Dictionary<string, string>();
        if (nationalId is not null) p[XRoadAttestationSource.NationalIdKey] = nationalId;
        if (parcelId is not null) p[XRoadAttestationSource.ParcelIdKey] = parcelId;
        return new SubjectContext { Subject = new DidId("did:tessera:subject"), Parameters = p };
    }

    [Fact]
    public async Task FullRecord_EmitsResidencyPropertyAndEncumbrance()
    {
        var client = new FakeClient(new XRoadRegistryRecord
        {
            PersonFound = true,
            ResidencyCountry = "KZ",
            PropertyOwnershipConfirmed = true,
            ParcelId = "09-123-456",
            EncumbranceStatus = "none",
        });
        var source = new XRoadAttestationSource(client);

        var drafts = await source.ResolveAsync(Subject("123456", "09-123-456"));

        Assert.Equal(3, drafts.Count);
        Assert.Equal("KZ", drafts.Single(d => d.Type == AttestationTypes.Jurisdiction).Payload.Claims!["country"]);
        var prop = drafts.Single(d => d.Type == XRoadAttestationTypes.PropertyRight);
        Assert.Equal("09-123-456", prop.Payload.Claims!["parcel_id"]);
        var enc = drafts.Single(d => d.Type == XRoadAttestationTypes.Encumbrance);
        Assert.Equal("none", enc.Payload.Claims!["status"]);

        // The query forwarded the national id + parcel id.
        Assert.Equal("123456", client.LastQuery!.NationalId);
        Assert.Equal("09-123-456", client.LastQuery!.ParcelId);
    }

    [Fact]
    public async Task PersonNotFound_EmitsNothing()
    {
        var source = new XRoadAttestationSource(new FakeClient(new XRoadRegistryRecord { PersonFound = false }));
        Assert.Empty(await source.ResolveAsync(Subject("123456")));
    }

    [Fact]
    public async Task MissingNationalId_EmitsNothing()
    {
        var source = new XRoadAttestationSource(new FakeClient(null));
        Assert.Empty(await source.ResolveAsync(Subject(null)));
    }

    [Fact]
    public async Task ResidencyOnly_EmitsSingleJurisdiction()
    {
        var source = new XRoadAttestationSource(new FakeClient(new XRoadRegistryRecord
        {
            PersonFound = true, ResidencyCountry = "KZ",
        }));
        var drafts = await source.ResolveAsync(Subject("123456"));
        Assert.Single(drafts);
        Assert.Equal(AttestationTypes.Jurisdiction, drafts[0].Type);
    }

    [Fact]
    public void SourceId_IsStableAndScoped()
        => Assert.Equal("registry.xroad", new XRoadAttestationSource(new FakeClient(null)).SourceId);
}
