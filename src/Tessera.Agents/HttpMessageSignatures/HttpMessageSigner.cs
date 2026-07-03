using System.Text;
using Tessera.Signing;

namespace Tessera.Agents.HttpMessageSignatures;

/// <summary>Options for signing an outgoing HTTP request (RFC 9421, <c>did:tessera</c> profile).</summary>
public sealed class HttpSignatureSigningOptions
{
    /// <summary>The agent's 32-byte Ed25519 controller private-key seed.</summary>
    public required byte[] PrivateKey { get; init; }

    /// <summary>
    /// The signature <c>keyid</c>. In the <c>did:tessera</c> profile this is the agent's DID
    /// (<c>did:tessera:…</c>), which the verifier re-derives from the public key.
    /// </summary>
    public required string KeyId { get; init; }

    /// <summary>
    /// Covered components, in order. When null, a sensible default is used:
    /// <c>@method</c>, <c>@authority</c>, <c>@path</c>, <c>@query</c> (if the URI has a query), and
    /// <c>content-digest</c> (if the request has a body and <see cref="AddContentDigest"/> is set).
    /// </summary>
    public IReadOnlyList<string>? CoveredComponents { get; init; }

    /// <summary>Signature creation time; defaults to now.</summary>
    public DateTimeOffset? Created { get; init; }

    /// <summary>Optional expiry after which verifiers reject the signature.</summary>
    public DateTimeOffset? Expires { get; init; }

    /// <summary>Optional single-use nonce.</summary>
    public string? Nonce { get; init; }

    /// <summary>Optional application tag. Web Bot Auth uses <c>web-bot-auth</c>.</summary>
    public string? Tag { get; init; }

    /// <summary>Emit <c>alg="ed25519"</c> in the signature parameters. Default true.</summary>
    public bool IncludeAlg { get; init; } = true;

    /// <summary>Compute and set the <c>Content-Digest</c> header from the body before signing. Default true.</summary>
    public bool AddContentDigest { get; init; } = true;

    /// <summary>Structured-field label for the signature. Default <c>sig1</c>.</summary>
    public string Label { get; init; } = "sig1";

    /// <summary>Clock used for the default <see cref="Created"/>. Defaults to the system clock.</summary>
    public TimeProvider? Clock { get; init; }
}

/// <summary>
/// Signs an <see cref="HttpRequestMessage"/> with an agent's <c>did:tessera</c> Ed25519 controller key
/// using RFC 9421 HTTP Message Signatures, adding the <c>Content-Digest</c>, <c>Signature-Input</c>,
/// and <c>Signature</c> headers. Web Bot Auth compatible (Ed25519, structured-field signatures).
/// </summary>
public static class HttpMessageSigner
{
    public static async Task SignAsync(
        HttpRequestMessage request,
        HttpSignatureSigningOptions options,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(options);
        if (options.PrivateKey is not { Length: Ed25519.PrivateKeySize })
            throw new ArgumentException($"PrivateKey must be a {Ed25519.PrivateKeySize}-byte Ed25519 seed.", nameof(options));
        if (string.IsNullOrEmpty(options.KeyId))
            throw new ArgumentException("KeyId is required.", nameof(options));

        var hasBody = request.Content is not null;
        if (options.AddContentDigest && hasBody)
        {
            var body = await request.Content!.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            // Replace any existing content-digest so it always matches the body we sign over.
            request.Content!.Headers.Remove("Content-Digest");
            request.Content!.Headers.TryAddWithoutValidation("Content-Digest", ContentDigest.ForBody(body));
        }

        var components = options.CoveredComponents ?? DefaultComponents(request, options);

        var clock = options.Clock ?? TimeProvider.System;
        var created = (options.Created ?? clock.GetUtcNow()).ToUnixTimeSeconds();
        var parameters = new SignatureParameters
        {
            Created = created,
            Expires = options.Expires?.ToUnixTimeSeconds(),
            Nonce = options.Nonce,
            Alg = options.IncludeAlg ? "ed25519" : null,
            KeyId = options.KeyId,
            Tag = options.Tag,
        };

        var signatureParamsValue = SignatureBase.SignatureParams(components, parameters);
        var baseString = SignatureBase.Build(request, components, signatureParamsValue);
        var signature = Ed25519.Sign(options.PrivateKey, Encoding.UTF8.GetBytes(baseString));

        request.Headers.TryAddWithoutValidation("Signature-Input", $"{options.Label}={signatureParamsValue}");
        request.Headers.TryAddWithoutValidation("Signature", $"{options.Label}=:{Convert.ToBase64String(signature)}:");
    }

    private static List<string> DefaultComponents(HttpRequestMessage request, HttpSignatureSigningOptions options)
    {
        var components = new List<string> { "@method", "@authority", "@path" };
        if (!string.IsNullOrEmpty(request.RequestUri?.Query))
            components.Add("@query");
        if (options.AddContentDigest && request.Content is not null)
            components.Add("content-digest");
        return components;
    }
}
