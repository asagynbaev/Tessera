namespace Tessera.Sources.Bitcoin;

/// <summary>
/// Marks a provider failure as transient (HTTP 5xx / 429 / network), so reads may be retried.
/// Derives from <see cref="InvalidOperationException"/> to keep the source's exception taxonomy
/// aligned with the chain adapters (validation → <see cref="ArgumentException"/>, provider
/// failures → <see cref="InvalidOperationException"/>).
/// </summary>
public sealed class TransientBitcoinProviderException : InvalidOperationException
{
    /// <summary>Create the exception with a message.</summary>
    public TransientBitcoinProviderException(string message) : base(message) { }

    /// <summary>Create the exception with a message and an inner cause.</summary>
    public TransientBitcoinProviderException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>Best-effort retry policy for transient Esplora / network failures (reads only).</summary>
public sealed record BitcoinRetryPolicy
{
    /// <summary>Total attempts including the first. 1 = no retry.</summary>
    public int MaxAttempts { get; init; } = 3;

    /// <summary>Base delay; attempt N waits <c>BaseDelay * 2^(N-1)</c>.</summary>
    public TimeSpan BaseDelay { get; init; } = TimeSpan.FromMilliseconds(500);

    /// <summary>3 attempts with 500 ms base backoff.</summary>
    public static BitcoinRetryPolicy Default { get; } = new();

    /// <summary>No retry (a single attempt).</summary>
    public static BitcoinRetryPolicy None { get; } = new() { MaxAttempts = 1 };
}

/// <summary>
/// Best-effort retry for transient provider failures. Mirrors the Cardano/EVM adapters' policy:
/// reads are retried with exponential backoff; this source never writes.
/// </summary>
internal static class BitcoinRetry
{
    public static async Task<T> RunAsync<T>(BitcoinRetryPolicy policy, Func<Task<T>> operation, CancellationToken ct)
    {
        var attempts = Math.Max(1, policy.MaxAttempts);
        for (var attempt = 1; ; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                return await operation().ConfigureAwait(false);
            }
            catch (Exception ex) when (attempt < attempts && IsTransient(ex, ct))
            {
                var delayMs = policy.BaseDelay.TotalMilliseconds * Math.Pow(2, attempt - 1);
                await Task.Delay(TimeSpan.FromMilliseconds(delayMs), ct).ConfigureAwait(false);
            }
        }
    }

    internal static bool IsTransient(Exception ex, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return false;
        return ex switch
        {
            TransientBitcoinProviderException => true,
            HttpRequestException => true,
            TaskCanceledException => true,
            TimeoutException => true,
            _ => false,
        };
    }
}
