using Tessera.Attestations;
using Tessera.Core;
using Tessera.Sources.Sumsub;

namespace Tessera.Sources.Sumsub.Tests;

public class SumsubAttestationSourceTests
{
    private sealed class FakeClient : ISumsubClient
    {
        private readonly SumsubApplicantReview? _review;
        public FakeClient(SumsubApplicantReview? review) => _review = review;
        public Task<SumsubApplicantReview?> GetApplicantReviewAsync(string applicantId, CancellationToken ct = default)
            => Task.FromResult(_review);
    }

    private static SubjectContext Subject(string? applicantId) => new()
    {
        Subject = new DidId("did:tessera:subject"),
        Parameters = applicantId is null
            ? new Dictionary<string, string>()
            : new Dictionary<string, string> { [SumsubAttestationSource.ApplicantIdKey] = applicantId },
    };

    [Fact]
    public async Task ApprovedApplicant_EmitsKycAndJurisdiction()
    {
        var source = new SumsubAttestationSource(new FakeClient(new SumsubApplicantReview
        {
            ApplicantId = "app-1",
            Approved = true,
            ReviewAnswer = "GREEN",
            LevelName = "basic-kyc",
            Country = "KAZ",
        }));

        var drafts = await source.ResolveAsync(Subject("app-1"));

        Assert.Equal(2, drafts.Count);
        var kyc = drafts.Single(d => d.Type == AttestationTypes.KycVerified);
        Assert.Equal("sumsub", kyc.Payload.Method);
        Assert.Equal("basic-kyc", kyc.Payload.Claims!["level"]);

        var jur = drafts.Single(d => d.Type == AttestationTypes.Jurisdiction);
        Assert.Equal("KAZ", jur.Payload.Claims!["country"]);
    }

    [Fact]
    public async Task NotApproved_EmitsNothing()
    {
        var source = new SumsubAttestationSource(new FakeClient(new SumsubApplicantReview
        {
            ApplicantId = "app-1", Approved = false, ReviewAnswer = "RED",
        }));
        Assert.Empty(await source.ResolveAsync(Subject("app-1")));
    }

    [Fact]
    public async Task MissingApplicantId_EmitsNothing()
    {
        var source = new SumsubAttestationSource(new FakeClient(null));
        Assert.Empty(await source.ResolveAsync(Subject(null)));
    }

    [Fact]
    public async Task ApprovedWithoutCountry_EmitsOnlyKyc()
    {
        var source = new SumsubAttestationSource(new FakeClient(new SumsubApplicantReview
        {
            ApplicantId = "app-1", Approved = true, ReviewAnswer = "GREEN", LevelName = "basic",
        }));

        var drafts = await source.ResolveAsync(Subject("app-1"));
        Assert.Single(drafts);
        Assert.Equal(AttestationTypes.KycVerified, drafts[0].Type);
    }

    [Fact]
    public void SourceId_IsStableAndVendorScoped()
        => Assert.Equal("kyc.sumsub", new SumsubAttestationSource(new FakeClient(null)).SourceId);
}
