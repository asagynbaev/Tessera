using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Tessera.Core;
using Tessera.Did;
using Tessera.EntityFrameworkCore;

namespace Tessera.EntityFrameworkCore.Tests;

public class EfCoreDidStoreTests
{
    private static DidDocument SampleDocument(string id = "did:tessera:store-test-1")
    {
        var now = DateTimeOffset.UtcNow;
        return new DidDocument
        {
            Id = new DidId(id),
            Controller = new DidId(id),
            VerificationMethods = new[]
            {
                new VerificationMethod
                {
                    Id = $"{id}#keys-1",
                    Type = "Ed25519VerificationKey2020",
                    PublicKeyMultibase = "z6Mk" + id.GetHashCode().ToString("X8"),
                },
            },
            CreatedAt = now,
            UpdatedAt = now,
        };
    }

    [Fact]
    public async Task Save_ThenGet_ReturnsEqualDocument()
    {
        using var fx = new SqliteFixture();
        var doc = SampleDocument();

        await using (var db = fx.CreateContext())
        {
            var store = new EfCoreDidStore(db);
            await store.SaveAsync(doc);
        }

        await using (var db = fx.CreateContext())
        {
            var store = new EfCoreDidStore(db);
            var loaded = await store.GetAsync(doc.Id);

            Assert.NotNull(loaded);
            Assert.Equal(doc.Id, loaded.Id);
            Assert.Equal(doc.Controller, loaded.Controller);
            Assert.Single(loaded.VerificationMethods);
            Assert.Equal(doc.VerificationMethods[0].PublicKeyMultibase, loaded.VerificationMethods[0].PublicKeyMultibase);
        }
    }

    [Fact]
    public async Task Get_MissingDid_ReturnsNull()
    {
        using var fx = new SqliteFixture();
        await using var db = fx.CreateContext();
        var store = new EfCoreDidStore(db);

        var loaded = await store.GetAsync(new DidId("did:tessera:does-not-exist"));
        Assert.Null(loaded);
    }

    [Fact]
    public async Task Exists_TracksLifecycle()
    {
        using var fx = new SqliteFixture();
        var doc = SampleDocument("did:tessera:exists-check");

        await using var db = fx.CreateContext();
        var store = new EfCoreDidStore(db);

        Assert.False(await store.ExistsAsync(doc.Id));
        await store.SaveAsync(doc);
        Assert.True(await store.ExistsAsync(doc.Id));
    }

    [Fact]
    public async Task Save_UpdateExisting_ReplacesWallets()
    {
        using var fx = new SqliteFixture();
        var doc = SampleDocument("did:tessera:wallet-update");

        await using (var db = fx.CreateContext())
        {
            var store = new EfCoreDidStore(db);
            var withWallets = doc with
            {
                Wallets = new[]
                {
                    new WalletBinding
                    {
                        Chain = "solana",
                        Address = "SoLana11111111111",
                        ProofSignature = RandomNumberGenerator.GetBytes(64),
                        BoundAt = DateTimeOffset.UtcNow,
                    },
                    new WalletBinding
                    {
                        Chain = "stellar",
                        Address = "GABC",
                        ProofSignature = RandomNumberGenerator.GetBytes(64),
                        BoundAt = DateTimeOffset.UtcNow,
                    },
                },
            };
            await store.SaveAsync(withWallets);
        }

        // Replace with a single wallet — old rows must not linger.
        await using (var db = fx.CreateContext())
        {
            var store = new EfCoreDidStore(db);
            var current = await store.GetAsync(doc.Id);
            Assert.NotNull(current);
            Assert.Equal(2, current.Wallets.Count);

            var trimmed = current with
            {
                Wallets = new[]
                {
                    new WalletBinding
                    {
                        Chain = "solana",
                        Address = "SoLanaReplacement",
                        ProofSignature = RandomNumberGenerator.GetBytes(64),
                        BoundAt = DateTimeOffset.UtcNow,
                    },
                },
                Version = current.Version + 1,
            };
            await store.SaveAsync(trimmed);
        }

        await using (var db = fx.CreateContext())
        {
            var store = new EfCoreDidStore(db);
            var loaded = await store.GetAsync(doc.Id);

            Assert.NotNull(loaded);
            Assert.Single(loaded.Wallets);
            Assert.Equal("SoLanaReplacement", loaded.Wallets[0].Address);
        }
    }

    [Fact]
    public async Task Save_PersistsAttestationRootAndRevocation()
    {
        using var fx = new SqliteFixture();
        var doc = SampleDocument("did:tessera:root-test");
        var root = RandomNumberGenerator.GetBytes(32);

        await using (var db = fx.CreateContext())
        {
            var store = new EfCoreDidStore(db);
            var anchored = doc with { AttestationRoot = root, Revoked = false, Version = 2 };
            await store.SaveAsync(anchored);
        }

        await using (var db = fx.CreateContext())
        {
            var store = new EfCoreDidStore(db);
            var loaded = await store.GetAsync(doc.Id);

            Assert.NotNull(loaded);
            Assert.Equal(root, loaded.AttestationRoot);
            Assert.False(loaded.Revoked);
            Assert.Equal(2, loaded.Version);
        }
    }

    // Regression for finding H10: without an optimistic-concurrency token, two writers that
    // both read the same snapshot could each commit a mutation, with the last writer silently
    // clobbering the other — e.g. a BindWallet resurrecting a DID a concurrent Revoke just set.
    // SQLite (a relational provider) is used here deliberately: EF InMemory does NOT enforce
    // concurrency tokens, so it cannot exercise this guard.
    [Fact]
    public async Task Save_ConcurrentStaleWrite_ThrowsAndDoesNotResurrectRevocation()
    {
        using var fx = new SqliteFixture();
        var doc = SampleDocument("did:tessera:concurrency-h10");

        // Seed version 1.
        await using (var db = fx.CreateContext())
            await new EfCoreDidStore(db).SaveAsync(doc);

        // Two callers read the SAME snapshot (version 1).
        DidDocument snapshotA, snapshotB;
        await using (var db = fx.CreateContext())
            snapshotA = (await new EfCoreDidStore(db).GetAsync(doc.Id))!;
        await using (var db = fx.CreateContext())
            snapshotB = (await new EfCoreDidStore(db).GetAsync(doc.Id))!;

        Assert.Equal(1, snapshotA.Version);
        Assert.Equal(1, snapshotB.Version);

        // Writer A revokes (the mutation DidService would produce: Revoked + bumped version).
        var revoked = snapshotA with { Revoked = true, Version = snapshotA.Version + 1 };
        await using (var db = fx.CreateContext())
            await new EfCoreDidStore(db).SaveAsync(revoked);

        // Writer B, working off the now-stale snapshot, binds a wallet (Revoked still false).
        var rebound = snapshotB with
        {
            Wallets = new[]
            {
                new WalletBinding
                {
                    Chain = "solana",
                    Address = "SoLanaLateWriter",
                    ProofSignature = RandomNumberGenerator.GetBytes(64),
                    BoundAt = DateTimeOffset.UtcNow,
                },
            },
            Version = snapshotB.Version + 1,
        };

        await using (var db = fx.CreateContext())
        {
            var store = new EfCoreDidStore(db);
            // The stale write must be rejected, not silently applied.
            await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => store.SaveAsync(rebound));
        }

        // The revocation survived — it was not resurrected by the losing writer.
        await using (var db = fx.CreateContext())
        {
            var loaded = await new EfCoreDidStore(db).GetAsync(doc.Id);
            Assert.NotNull(loaded);
            Assert.True(loaded.Revoked);
            Assert.Equal(2, loaded.Version);
            Assert.Empty(loaded.Wallets);
        }
    }

    [Fact]
    public async Task Save_PersistsChannelBindings()
    {
        using var fx = new SqliteFixture();
        var doc = SampleDocument("did:tessera:channels");
        var withChannels = doc with
        {
            Bindings = new[]
            {
                new ChannelBinding
                {
                    Type = "phone",
                    Commitment = RandomNumberGenerator.GetBytes(32),
                    Issuer = new DidId("did:tessera:phone-issuer"),
                    IssuedAt = DateTimeOffset.UtcNow,
                    ExpiresAt = DateTimeOffset.UtcNow.AddYears(1),
                },
            },
        };

        await using (var db = fx.CreateContext())
            await new EfCoreDidStore(db).SaveAsync(withChannels);

        await using (var db = fx.CreateContext())
        {
            var loaded = await new EfCoreDidStore(db).GetAsync(doc.Id);
            Assert.NotNull(loaded);
            Assert.Single(loaded.Bindings);
            Assert.Equal("phone", loaded.Bindings[0].Type);
            Assert.Equal(withChannels.Bindings[0].Commitment, loaded.Bindings[0].Commitment);
            Assert.Equal("did:tessera:phone-issuer", loaded.Bindings[0].Issuer.Value);
        }
    }
}
