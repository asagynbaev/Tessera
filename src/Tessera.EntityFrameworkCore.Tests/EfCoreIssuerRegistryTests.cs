using System.Security.Cryptography;
using Tessera.Attestations;
using Tessera.Core;
using Tessera.EntityFrameworkCore;

namespace Tessera.EntityFrameworkCore.Tests;

public class EfCoreIssuerRegistryTests
{
    private static IssuerRecord SampleIssuer(string did = "did:tessera:issuer-1", bool active = true) => new()
    {
        Did = new DidId(did),
        PublicKey = RandomNumberGenerator.GetBytes(32),
        Algorithm = "ed25519",
        SchemaUri = "https://schemas.tessera/attestation/v1",
        Active = active,
    };

    [Fact]
    public async Task Register_ThenResolve_ReturnsRecord()
    {
        using var fx = new SqliteFixture();
        var record = SampleIssuer();

        await using (var db = fx.CreateContext())
        {
            var reg = new EfCoreIssuerRegistry(db);
            await reg.RegisterAsync(record);
        }

        await using (var db = fx.CreateContext())
        {
            var reg = new EfCoreIssuerRegistry(db);
            var loaded = await reg.ResolveAsync(record.Did);

            Assert.NotNull(loaded);
            Assert.Equal(record.Did, loaded.Did);
            Assert.Equal(record.PublicKey, loaded.PublicKey);
            Assert.Equal(record.SchemaUri, loaded.SchemaUri);
            Assert.True(loaded.Active);
        }
    }

    [Fact]
    public async Task Resolve_UnknownIssuer_ReturnsNull()
    {
        using var fx = new SqliteFixture();
        await using var db = fx.CreateContext();
        var reg = new EfCoreIssuerRegistry(db);

        var loaded = await reg.ResolveAsync(new DidId("did:tessera:nobody"));
        Assert.Null(loaded);
    }

    [Fact]
    public async Task Register_TwiceWithDifferentSchema_UpdatesInPlace()
    {
        using var fx = new SqliteFixture();
        var first = SampleIssuer();
        var second = first with { SchemaUri = "https://schemas.tessera/attestation/v2" };

        await using (var db = fx.CreateContext())
            await new EfCoreIssuerRegistry(db).RegisterAsync(first);

        await using (var db = fx.CreateContext())
            await new EfCoreIssuerRegistry(db).RegisterAsync(second);

        await using (var db = fx.CreateContext())
        {
            var reg = new EfCoreIssuerRegistry(db);
            var loaded = await reg.ResolveAsync(first.Did);
            Assert.NotNull(loaded);
            Assert.Equal("https://schemas.tessera/attestation/v2", loaded.SchemaUri);
        }
    }

    [Fact]
    public async Task Register_TwiceWithDifferentPublicKey_IsRejected()
    {
        using var fx = new SqliteFixture();
        var first = SampleIssuer("did:tessera:trust-root");
        var keyRotation = first with { PublicKey = RandomNumberGenerator.GetBytes(32) };

        await using (var db = fx.CreateContext())
            await new EfCoreIssuerRegistry(db).RegisterAsync(first);

        await using (var db = fx.CreateContext())
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => new EfCoreIssuerRegistry(db).RegisterAsync(keyRotation));

        // The original trust-anchor key is unchanged — no silent issuer-key takeover via upsert.
        await using (var verifyDb = fx.CreateContext())
        {
            var loaded = await new EfCoreIssuerRegistry(verifyDb).ResolveAsync(first.Did);
            Assert.NotNull(loaded);
            Assert.Equal(first.PublicKey, loaded.PublicKey);
        }
    }

    [Fact]
    public async Task Deactivate_RemovesFromResolveResults()
    {
        using var fx = new SqliteFixture();
        var record = SampleIssuer("did:tessera:deactivate-me");

        await using (var db = fx.CreateContext())
            await new EfCoreIssuerRegistry(db).RegisterAsync(record);

        await using (var db = fx.CreateContext())
        {
            var reg = new EfCoreIssuerRegistry(db);
            var removed = await reg.DeactivateAsync(record.Did);
            Assert.True(removed);
        }

        await using (var db = fx.CreateContext())
        {
            var reg = new EfCoreIssuerRegistry(db);
            var resolved = await reg.ResolveAsync(record.Did);
            Assert.Null(resolved);
        }
    }

    [Fact]
    public async Task Deactivate_UnknownIssuer_ReturnsFalse()
    {
        using var fx = new SqliteFixture();
        await using var db = fx.CreateContext();
        var reg = new EfCoreIssuerRegistry(db);

        var result = await reg.DeactivateAsync(new DidId("did:tessera:never-registered"));
        Assert.False(result);
    }

    [Fact]
    public async Task Register_InactiveRecord_NotResolvable()
    {
        using var fx = new SqliteFixture();
        var record = SampleIssuer("did:tessera:born-inactive", active: false);

        await using (var db = fx.CreateContext())
            await new EfCoreIssuerRegistry(db).RegisterAsync(record);

        await using (var db = fx.CreateContext())
        {
            var reg = new EfCoreIssuerRegistry(db);
            var resolved = await reg.ResolveAsync(record.Did);
            Assert.Null(resolved);
        }
    }
}
