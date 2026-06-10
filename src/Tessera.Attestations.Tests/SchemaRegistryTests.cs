using Tessera.Attestations;
using Tessera.Core;

namespace Tessera.Attestations.Tests;

public class SchemaRegistryTests
{
    private static Attestation Att(string type, AttestationPayload payload) => new()
    {
        Schema = "https://schemas.tessera/std/v1/x",
        Type = type,
        Issuer = new DidId("did:tessera:issuer"),
        Subject = new DidId("did:tessera:subject"),
        IssuedAt = DateTimeOffset.UnixEpoch,
        Nonce = new byte[16],
        Payload = payload,
        Signature = new AttestationSignature { Algorithm = "ed25519", Value = new byte[64] },
    };

    [Fact]
    public void CreateStandard_Resolves_TheThreeStandardTypes()
    {
        var reg = SchemaRegistry.CreateStandard();

        Assert.NotNull(reg.Resolve(AttestationTypes.KycVerified));
        Assert.NotNull(reg.Resolve(AttestationTypes.Jurisdiction));

        var accredited = reg.Resolve(AttestationTypes.Accredited);
        Assert.NotNull(accredited);
        Assert.True(accredited!.CarriesCommitment);
        Assert.StartsWith("https://schemas.tessera/std/v1/", accredited.SchemaUri);
    }

    [Fact]
    public void Validate_Accredited_RequiresCommitment()
    {
        var reg = SchemaRegistry.CreateStandard();

        var noCommit = reg.Validate(Att(AttestationTypes.Accredited, new AttestationPayload { Method = "x" }));
        Assert.False(noCommit.Valid);
        Assert.Contains("missing_commitment", noCommit.Reason);

        var withCommit = reg.Validate(Att(AttestationTypes.Accredited, new AttestationPayload { Method = "x", Commitment = new byte[33] }));
        Assert.True(withCommit.Valid);
    }

    [Fact]
    public void Validate_Jurisdiction_RequiresCountryClaim()
    {
        var reg = SchemaRegistry.CreateStandard();

        var missing = reg.Validate(Att(AttestationTypes.Jurisdiction, new AttestationPayload { Method = "x" }));
        Assert.False(missing.Valid);
        Assert.Contains("missing_claim:country", missing.Reason);

        var present = reg.Validate(Att(AttestationTypes.Jurisdiction, new AttestationPayload
        {
            Method = "x",
            Claims = new Dictionary<string, object> { ["country"] = "KZ" },
        }));
        Assert.True(present.Valid);
    }

    [Fact]
    public void Validate_UnknownType_IsOpenWorld_Ok()
    {
        var reg = SchemaRegistry.CreateStandard();
        Assert.True(reg.Validate(Att("totally_unregistered", new AttestationPayload { Method = "x" })).Valid);
    }

    [Fact]
    public void CustomSchema_Registers_AndValidates_WithoutCoreChanges()
    {
        // DoD: a user-defined schema registers and validates through the same registry.
        var reg = SchemaRegistry.CreateStandard();
        reg.Register(new AttestationSchema
        {
            Type = "property_right",
            SchemaUri = "https://registry.example.kz/schemas/property_right/v1",
            RequiredClaimKeys = new[] { "parcel_id" },
        });

        var bad = reg.Validate(Att("property_right", new AttestationPayload { Method = "xroad" }));
        Assert.False(bad.Valid);

        var good = reg.Validate(Att("property_right", new AttestationPayload
        {
            Method = "xroad",
            Claims = new Dictionary<string, object> { ["parcel_id"] = "09-123-456" },
        }));
        Assert.True(good.Valid);
    }

    [Fact]
    public void Register_RejectsInvalidSchema()
    {
        var reg = new SchemaRegistry();
        Assert.Throws<ArgumentException>(() => reg.Register(new AttestationSchema { Type = "", SchemaUri = "x" }));
    }
}
