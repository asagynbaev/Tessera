namespace Tessera.Channels;

using System.Security.Cryptography;

/// <summary>
/// Source of the secret pepper used by <see cref="ChannelBindingService"/>.
/// The pepper is the only thing standing between a low-entropy identifier (phone, email,
/// Telegram handle) and a brute-force preimage attack on the commitment. Treat it as
/// equivalent to a database master key: never log it, never check it into source, store
/// it in a KMS / Key Vault / Secrets Manager and fetch it at startup.
/// </summary>
/// <remarks>
/// Implementations must return at least 32 bytes of cryptographically random data.
/// The same pepper must be used across all instances that need to compute or compare
/// commitments; rotating the pepper invalidates every previously stored commitment.
/// </remarks>
public interface IPepperProvider
{
    /// <summary>
    /// Return the pepper bytes. Async because production providers typically fetch from
    /// a remote secret store. Implementations should cache aggressively in-memory.
    /// </summary>
    ValueTask<ReadOnlyMemory<byte>> GetPepperAsync(CancellationToken ct = default);
}

/// <summary>
/// Shared validation for pepper material. The pepper MUST come from a CSPRNG
/// (e.g. <see cref="RandomNumberGenerator"/>). Length alone is not enough: an all-zero or
/// otherwise grossly low-entropy buffer of the right length offers no protection against a
/// brute-force preimage attack on a commitment, so it is rejected here.
/// </summary>
internal static class PepperValidation
{
    public const int MinLength = 32;

    /// <summary>
    /// Throws if <paramref name="pepper"/> is shorter than <see cref="MinLength"/>, is all-zero, or
    /// is grossly low-entropy (too few distinct byte values to plausibly be CSPRNG output).
    /// </summary>
    /// <param name="pepper">The candidate pepper bytes to validate.</param>
    /// <param name="throwFactory">
    /// Builds the exception to throw, given a human-readable reason. Lets callers raise the kind of
    /// exception their existing contract documents (e.g. <see cref="ArgumentException"/> at
    /// construction vs. <see cref="InvalidOperationException"/> after an env decode).
    /// </param>
    public static void Validate(ReadOnlySpan<byte> pepper, Func<string, Exception> throwFactory)
    {
        if (pepper.Length < MinLength)
            throw throwFactory($"Pepper must be at least {MinLength} bytes (got {pepper.Length}).");

        // Reject an all-zero buffer outright (the classic "forgot to seed it" mistake).
        var allZero = true;
        Span<bool> seen = stackalloc bool[256];
        var distinct = 0;
        foreach (var b in pepper)
        {
            if (b != 0) allZero = false;
            if (!seen[b]) { seen[b] = true; distinct++; }
        }

        if (allZero)
            throw throwFactory(
                "Pepper is all-zero bytes — this provides no security. Generate it from a CSPRNG " +
                "(e.g. RandomNumberGenerator.GetBytes(32)).");

        // Grossly low entropy: a CSPRNG-generated 32+ byte value will, with overwhelming probability,
        // contain many distinct byte values. A handful of distinct values means the buffer was almost
        // certainly not random (e.g. a repeated pattern). Fail closed.
        if (distinct < 8)
            throw throwFactory(
                $"Pepper has grossly low entropy (only {distinct} distinct byte values). It must come " +
                "from a CSPRNG (e.g. RandomNumberGenerator.GetBytes(32)).");
    }
}

/// <summary>
/// In-memory pepper provider. Suitable for tests and offline development.
/// Do NOT use in production — the pepper lives in process memory at construction time
/// and is never refreshed.
/// </summary>
public sealed class StaticPepperProvider : IPepperProvider
{
    private readonly ReadOnlyMemory<byte> _pepper;

    public StaticPepperProvider(ReadOnlyMemory<byte> pepper)
    {
        PepperValidation.Validate(pepper.Span, reason => new ArgumentException(reason, nameof(pepper)));
        _pepper = pepper;
    }

    public ValueTask<ReadOnlyMemory<byte>> GetPepperAsync(CancellationToken ct = default)
        => ValueTask.FromResult(_pepper);
}

/// <summary>
/// Pepper from an environment variable. The variable value must be Base64-encoded and
/// decode to at least 32 bytes. Useful for containerised deployments where the secret
/// arrives as an env var injected by the orchestrator.
/// </summary>
public sealed class EnvironmentPepperProvider : IPepperProvider
{
    private readonly Lazy<ReadOnlyMemory<byte>> _pepper;

    public EnvironmentPepperProvider(string environmentVariableName)
    {
        if (string.IsNullOrWhiteSpace(environmentVariableName))
            throw new ArgumentException("environment variable name required.", nameof(environmentVariableName));

        _pepper = new Lazy<ReadOnlyMemory<byte>>(() =>
        {
            var b64 = Environment.GetEnvironmentVariable(environmentVariableName);
            if (string.IsNullOrEmpty(b64))
                throw new InvalidOperationException(
                    $"Environment variable {environmentVariableName} is not set or empty.");

            byte[] bytes;
            try { bytes = Convert.FromBase64String(b64); }
            catch (FormatException ex)
            {
                throw new InvalidOperationException(
                    $"Environment variable {environmentVariableName} is not valid Base64.", ex);
            }

            PepperValidation.Validate(
                bytes,
                reason => new InvalidOperationException($"Pepper from {environmentVariableName} is invalid: {reason}"));

            return bytes;
        });
    }

    public ValueTask<ReadOnlyMemory<byte>> GetPepperAsync(CancellationToken ct = default)
        => ValueTask.FromResult(_pepper.Value);
}
