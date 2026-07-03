using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
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

    // L-1: without an optimistic-concurrency token on `issuers`, a DeactivateAsync could be silently
    // lost to a racing RegisterAsync (last write wins, no signal). The Version concurrency token turns
    // the stale write into a detectable conflict.
    [Fact]
    public async Task IssuerVersion_IsConcurrencyToken_StaleWriteThrows()
    {
        using var fx = new SqliteFixture();
        var record = SampleIssuer("did:tessera:issuer-token");

        await using (var db = fx.CreateContext())
            await new EfCoreIssuerRegistry(db).RegisterAsync(record);

        // Two contexts read the SAME row (Version 1) directly (bypassing the auto-retrying registry,
        // to observe the token itself).
        await using var dbA = fx.CreateContext();
        await using var dbB = fx.CreateContext();
        var a = await dbA.Issuers.FirstAsync(i => i.Did == record.Did.Value);
        var b = await dbB.Issuers.FirstAsync(i => i.Did == record.Did.Value);
        Assert.Equal(1, a.Version);
        Assert.Equal(1, b.Version);

        // Writer A commits first (deactivates).
        a.Active = false;
        a.Version++;
        await dbA.SaveChangesAsync();

        // Writer B, off the now-stale snapshot, must be rejected by the concurrency token.
        b.SchemaUri = "https://schemas.tessera/attestation/v2";
        b.Version++;
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => dbB.SaveChangesAsync());
    }

    [Fact]
    public async Task Register_RacingWithDeactivate_RetriesOntoCommittedRow()
    {
        using var fx = new SqliteFixture();
        var record = SampleIssuer("did:tessera:issuer-race");

        await using (var seed = fx.CreateContext())
            await new EfCoreIssuerRegistry(seed).RegisterAsync(record); // Version 1

        // Context B loads the issuer (Version 1) into its change tracker — a stale snapshot the
        // registry will reuse on its first save attempt.
        await using var dbB = fx.CreateContext();
        _ = await dbB.Issuers.FirstAsync(i => i.Did == record.Did.Value);

        // Meanwhile a separate context deactivates the issuer (row → Version 2, Active=false).
        await using (var dbA = fx.CreateContext())
            Assert.True(await new EfCoreIssuerRegistry(dbA).DeactivateAsync(record.Did));

        // Registry B updates the issuer through the stale context. Its first SaveChanges trips a
        // DbUpdateConcurrencyException on the token; the registry re-reads the committed row and
        // retries, so the call SUCCEEDS rather than silently clobbering (or throwing).
        var regB = new EfCoreIssuerRegistry(dbB);
        var updated = record with { SchemaUri = "https://schemas.tessera/attestation/v2" };
        await regB.RegisterAsync(updated);

        await using (var verify = fx.CreateContext())
        {
            var loaded = await verify.Issuers.FirstAsync(i => i.Did == record.Did.Value);
            Assert.Equal("https://schemas.tessera/attestation/v2", loaded.SchemaUri);
            // 1 (insert) → 2 (deactivate) → 3 (retried update): proves the retry re-applied onto the
            // committed row rather than losing the deactivate's version bump.
            Assert.Equal(3, loaded.Version);
        }
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
