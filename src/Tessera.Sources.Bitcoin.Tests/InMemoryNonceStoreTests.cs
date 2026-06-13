using Tessera.Core;

namespace Tessera.Sources.Bitcoin.Tests;

public class InMemoryNonceStoreTests
{
    private static readonly DidId Subject = new("did:tessera:nonce");

    [Fact]
    public async Task FirstConsume_Fresh_SecondConsume_Replay()
    {
        var store = new InMemoryNonceStore();
        var nonce = new byte[] { 1, 2, 3, 4 };
        var exp = DateTimeOffset.UtcNow.AddMinutes(10);

        Assert.True(await store.TryConsumeAsync(Subject, nonce, exp));
        Assert.False(await store.TryConsumeAsync(Subject, nonce, exp));
    }

    [Fact]
    public async Task DifferentSubjects_DoNotCollide()
    {
        var store = new InMemoryNonceStore();
        var nonce = new byte[] { 9, 9, 9 };
        var exp = DateTimeOffset.UtcNow.AddMinutes(10);

        Assert.True(await store.TryConsumeAsync(new DidId("did:tessera:a"), nonce, exp));
        Assert.True(await store.TryConsumeAsync(new DidId("did:tessera:b"), nonce, exp));
    }

    [Fact]
    public async Task ExpiredEntry_IsEvicted_AllowingReuseAfterExpiry()
    {
        var clock = new FakeClock(DateTimeOffset.FromUnixTimeSeconds(1_000_000));
        var store = new InMemoryNonceStore(clock);
        var nonce = new byte[] { 7, 7, 7, 7 };
        var exp = clock.GetUtcNow().AddMinutes(5);

        Assert.True(await store.TryConsumeAsync(Subject, nonce, exp));
        clock.Advance(TimeSpan.FromMinutes(6)); // past expiry → entry evicted on next call
        Assert.True(await store.TryConsumeAsync(Subject, nonce, clock.GetUtcNow().AddMinutes(5)));
    }
}
