using Nethereum.JsonRpc.Client;

namespace Tessera.Chains.Evm.Internal;

/// <summary>
/// Minimal exponential-backoff retry for transient RPC/network failures. Deliberately
/// conservative: only retries errors that are safe to re-attempt (transport faults, rate
/// limits, transient node errors). Application-level reverts (NotOwner, AlreadyRegistered,
/// ...) are never retried — they are deterministic and re-sending changes nothing.
/// </summary>
internal static class EvmRetry
{
    public static async Task<T> RunAsync<T>(
        EvmRetryPolicy policy,
        Func<Task<T>> operation,
        CancellationToken ct)
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

    private static bool IsTransient(Exception ex, CancellationToken ct)
    {
        // A cancellation requested by the caller is never "transient" — surface it.
        if (ct.IsCancellationRequested) return false;

        return ex switch
        {
            HttpRequestException => true,
            TimeoutException => true,
            TaskCanceledException => true, // RPC client timeout (not caller cancellation, handled above)
            RpcClientTimeoutException => true,
            RpcClientUnknownException => true,
            RpcResponseException rre => IsTransientRpc(rre),
            _ => false,
        };
    }

    private static bool IsTransientRpc(RpcResponseException ex)
    {
        // Prefer the structured JSON-RPC error code (reliable across providers) over message text.
        var code = ex.RpcError?.Code;
        if (code is -32000  // generic server error
                 or -32002  // resource unavailable / limit
                 or -32005  // limit exceeded (common with hosted providers)
                 or -32603) // internal error
            return true;

        // Fallback heuristic for providers that only convey transience in the message.
        var msg = ex.Message?.ToLowerInvariant() ?? string.Empty;
        return msg.Contains("rate limit")
            || msg.Contains("too many requests")
            || msg.Contains("service unavailable")
            || msg.Contains("temporarily")
            || msg.Contains("timeout");
    }
}
