using Tessera.Chains.Cardano;
using Tessera.Chains.Cardano.Internal;

namespace Tessera.Chains.Cardano.Tests;

/// <summary>
/// Transient vs deterministic classification, mirroring the EVM EvmRetryTests: transient errors
/// are retried up to MaxAttempts; deterministic ones fail immediately.
/// </summary>
public class CardanoRetryTests
{
    private static readonly CardanoRetryPolicy Fast = new() { MaxAttempts = 3, BaseDelay = TimeSpan.FromMilliseconds(1) };

    [Fact]
    public async Task HttpRequestException_IsTransient_RetriedToMax()
    {
        var calls = 0;
        await Assert.ThrowsAsync<HttpRequestException>(() =>
            CardanoRetry.RunAsync<int>(Fast, () => { calls++; return Task.FromException<int>(new HttpRequestException("503")); }, default));
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task TransientProviderException_IsTransient_RetriedToMax()
    {
        var calls = 0;
        await Assert.ThrowsAsync<TransientProviderException>(() =>
            CardanoRetry.RunAsync<int>(Fast, () => { calls++; return Task.FromException<int>(new TransientProviderException("429")); }, default));
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task InvalidOperationException_IsDeterministic_NotRetried()
    {
        var calls = 0;
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            CardanoRetry.RunAsync<int>(Fast, () => { calls++; return Task.FromException<int>(new InvalidOperationException("script revert")); }, default));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Succeeds_OnFirstAttempt()
    {
        var calls = 0;
        var result = await CardanoRetry.RunAsync(Fast, () => { calls++; return Task.FromResult(7); }, default);
        Assert.Equal(7, result);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task PreCancelled_DoesNotRun()
    {
        var calls = 0;
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            CardanoRetry.RunAsync(Fast, () => { calls++; return Task.FromResult(1); }, cts.Token));
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task MaxAttemptsZero_ClampsToSingleAttempt()
    {
        var calls = 0;
        var policy = new CardanoRetryPolicy { MaxAttempts = 0, BaseDelay = TimeSpan.FromMilliseconds(1) };
        await Assert.ThrowsAsync<HttpRequestException>(() =>
            CardanoRetry.RunAsync<int>(policy, () => { calls++; return Task.FromException<int>(new HttpRequestException("x")); }, default));
        Assert.Equal(1, calls);
    }
}
