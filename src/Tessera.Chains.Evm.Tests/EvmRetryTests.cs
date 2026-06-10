using Tessera.Chains.Evm.Internal;

namespace Tessera.Chains.Evm.Tests;

public class EvmRetryTests
{
    private static readonly EvmRetryPolicy Fast3 = new() { MaxAttempts = 3, BaseDelay = TimeSpan.FromMilliseconds(1) };

    [Fact]
    public async Task Succeeds_FirstTry_RunsOnce()
    {
        var calls = 0;
        var result = await EvmRetry.RunAsync(Fast3, () => { calls++; return Task.FromResult(42); }, CancellationToken.None);
        Assert.Equal(42, result);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task TransientError_RetriesUpToMaxAttempts_ThenSucceeds()
    {
        var calls = 0;
        var result = await EvmRetry.RunAsync(Fast3, () =>
        {
            calls++;
            if (calls < 3) throw new HttpRequestException("network blip");
            return Task.FromResult("ok");
        }, CancellationToken.None);

        Assert.Equal("ok", result);
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task TransientError_ExhaustsAttempts_Throws()
    {
        var calls = 0;
        await Assert.ThrowsAsync<HttpRequestException>(() => EvmRetry.RunAsync<int>(Fast3, () =>
        {
            calls++;
            throw new HttpRequestException("always down");
        }, CancellationToken.None));

        Assert.Equal(3, calls); // all attempts used
    }

    [Fact]
    public async Task DeterministicError_NotRetried_FailsImmediately()
    {
        var calls = 0;
        await Assert.ThrowsAsync<InvalidOperationException>(() => EvmRetry.RunAsync<int>(Fast3, () =>
        {
            calls++;
            throw new InvalidOperationException("contract revert: NotOwner");
        }, CancellationToken.None));

        Assert.Equal(1, calls); // non-transient → no retry
    }

    [Fact]
    public async Task MaxAttemptsZero_ClampsToSingleAttempt()
    {
        var policy = new EvmRetryPolicy { MaxAttempts = 0, BaseDelay = TimeSpan.FromMilliseconds(1) };
        var calls = 0;
        await Assert.ThrowsAsync<HttpRequestException>(() => EvmRetry.RunAsync<int>(policy, () =>
        {
            calls++;
            throw new HttpRequestException("down");
        }, CancellationToken.None));

        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task CancelledToken_ThrowsBeforeRunning()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var calls = 0;

        await Assert.ThrowsAsync<OperationCanceledException>(() => EvmRetry.RunAsync(Fast3, () =>
        {
            calls++;
            return Task.FromResult(1);
        }, cts.Token));

        Assert.Equal(0, calls);
    }
}
