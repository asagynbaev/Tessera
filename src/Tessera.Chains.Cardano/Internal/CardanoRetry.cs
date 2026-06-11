namespace Tessera.Chains.Cardano.Internal;

/// <summary>
/// Marks a provider failure as transient (HTTP 5xx / 429 / network), so reads may be retried.
/// Derives from <see cref="InvalidOperationException"/> to keep the adapter's exception taxonomy
/// aligned with the Solana/EVM adapters (validation → <see cref="ArgumentException"/>, provider/
/// submit failures → <see cref="InvalidOperationException"/>).
/// </summary>
internal sealed class TransientProviderException : InvalidOperationException
{
    public TransientProviderException(string message) : base(message) { }
    public TransientProviderException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Best-effort retry for transient provider failures. Mirrors the EVM adapter's policy:
/// reads are retried with exponential backoff; writes are single-shot and never auto-retried
/// (re-broadcasting a submitted tx could double-spend inputs under a different fee).
/// </summary>
internal static class CardanoRetry
{
    public static async Task<T> RunAsync<T>(CardanoRetryPolicy policy, Func<Task<T>> operation, CancellationToken ct)
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
            TransientProviderException => true,
            HttpRequestException => true,
            TaskCanceledException => true,
            TimeoutException => true,
            _ => false,
        };
    }
}
