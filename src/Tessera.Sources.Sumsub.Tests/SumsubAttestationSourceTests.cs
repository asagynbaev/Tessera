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

    private const string SubjectDid = "did:tessera:subject";

    private static SubjectContext Subject(string? applicantId) => new()
    {
        Subject = new DidId(SubjectDid),
        Parameters = applicantId is null
            ? new Dictionary<string, string>()
            : new Dictionary<string, string> { [SumsubAttestationSource.ApplicantIdKey] = applicantId },
    };

    [Fact]
    public async Task ApprovedApplicant_BoundToDid_EmitsKycAndJurisdiction()
    {
        var source = new SumsubAttestationSource(new FakeClient(new SumsubApplicantReview
        {
            ApplicantId = "app-1",
            Approved = true,
            ReviewAnswer = "GREEN",
            ExternalUserId = SubjectDid,
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
    public async Task ApprovedApplicant_ExternalUserIdMismatch_EmitsNothing()
    {
        // GREEN applicant, but bound to a DIFFERENT DID: the identity-transplant guard must refuse.
        var source = new SumsubAttestationSource(new FakeClient(new SumsubApplicantReview
        {
            ApplicantId = "app-1",
            Approved = true,
            ReviewAnswer = "GREEN",
            ExternalUserId = "did:tessera:someone-else",
            LevelName = "basic-kyc",
            Country = "KAZ",
        }));

        Assert.Empty(await source.ResolveAsync(Subject("app-1")));
    }

    [Fact]
    public async Task ApprovedApplicant_MissingExternalUserId_EmitsNothing()
    {
        // GREEN applicant with no externalUserId binding at all: refuse — we cannot prove it is the DID's.
        var source = new SumsubAttestationSource(new FakeClient(new SumsubApplicantReview
        {
            ApplicantId = "app-1",
            Approved = true,
            ReviewAnswer = "GREEN",
            ExternalUserId = null,
            LevelName = "basic-kyc",
            Country = "KAZ",
        }));

        Assert.Empty(await source.ResolveAsync(Subject("app-1")));
    }

    [Fact]
    public async Task NotApproved_EmitsNothing()
    {
        var source = new SumsubAttestationSource(new FakeClient(new SumsubApplicantReview
        {
            ApplicantId = "app-1", Approved = false, ReviewAnswer = "RED", ExternalUserId = SubjectDid,
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
            ApplicantId = "app-1", Approved = true, ReviewAnswer = "GREEN", ExternalUserId = SubjectDid, LevelName = "basic",
        }));

        var drafts = await source.ResolveAsync(Subject("app-1"));
        Assert.Single(drafts);
        Assert.Equal(AttestationTypes.KycVerified, drafts[0].Type);
    }

    [Fact]
    public void SourceId_IsStableAndVendorScoped()
        => Assert.Equal("kyc.sumsub", new SumsubAttestationSource(new FakeClient(null)).SourceId);
}
