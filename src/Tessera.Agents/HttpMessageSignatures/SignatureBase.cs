using System.Text;

namespace Tessera.Agents.HttpMessageSignatures;

/// <summary>
/// Thrown when a covered component named in a signature cannot be resolved from the message
/// (a missing header, or an unsupported derived component).
/// </summary>
public sealed class SignatureComponentException(string component, string reason)
    : Exception($"Cannot resolve signature component \"{component}\": {reason}.")
{
    public string Component { get; } = component;
}

/// <summary>
/// RFC 9421 §2 signature-base construction. Shared verbatim by the signer and verifier so the bytes
/// signed and the bytes verified are byte-for-byte identical. Supports the common derived components
/// (<c>@method</c>, <c>@authority</c>, <c>@path</c>, <c>@query</c>, <c>@scheme</c>, <c>@target-uri</c>)
/// and arbitrary HTTP header fields (combined per §2.1). Component parameters are not supported.
/// </summary>
internal static class SignatureBase
{
    /// <summary>
    /// Build the signature base: one line per covered component, then the trailing
    /// <c>"@signature-params"</c> line whose value is <paramref name="signatureParamsValue"/>
    /// (the exact inner-list-plus-parameters string that also appears in the <c>Signature-Input</c>
    /// header). No newline follows the final line.
    /// </summary>
    public static string Build(
        HttpRequestMessage request,
        IReadOnlyList<string> components,
        string signatureParamsValue)
    {
        var sb = new StringBuilder();
        foreach (var component in components)
        {
            sb.Append('"').Append(component).Append("\": ")
              .Append(ResolveComponent(request, component))
              .Append('\n');
        }
        sb.Append("\"@signature-params\": ").Append(signatureParamsValue);
        return sb.ToString();
    }

    /// <summary>Serialize the <c>@signature-params</c> value (also the <c>Signature-Input</c> value after the label).</summary>
    public static string SignatureParams(IReadOnlyList<string> components, SignatureParameters p)
    {
        var sb = new StringBuilder();
        sb.Append('(');
        for (var i = 0; i < components.Count; i++)
        {
            if (i > 0) sb.Append(' ');
            sb.Append('"').Append(components[i]).Append('"');
        }
        sb.Append(')');

        // Fixed order so the signer and any re-serialization agree: created, expires, nonce, alg, keyid, tag.
        if (p.Created is { } c) sb.Append(";created=").Append(c);
        if (p.Expires is { } e) sb.Append(";expires=").Append(e);
        if (p.Nonce is { } n) sb.Append(";nonce=\"").Append(n).Append('"');
        if (p.Alg is { } a) sb.Append(";alg=\"").Append(a).Append('"');
        if (p.KeyId is { } k) sb.Append(";keyid=\"").Append(k).Append('"');
        if (p.Tag is { } t) sb.Append(";tag=\"").Append(t).Append('"');
        return sb.ToString();
    }

    private static string ResolveComponent(HttpRequestMessage request, string name)
    {
        var uri = request.RequestUri
            ?? throw new SignatureComponentException(name, "the request has no RequestUri");

        switch (name)
        {
            case "@method":
                return request.Method.Method; // no case transformation (RFC 9421 §2.2.1)
            case "@authority":
                return uri.Authority.ToLowerInvariant(); // host lowercased, default port omitted
            case "@scheme":
                return uri.Scheme.ToLowerInvariant();
            case "@target-uri":
                return uri.AbsoluteUri;
            case "@path":
                var path = uri.AbsolutePath;
                return string.IsNullOrEmpty(path) ? "/" : path;
            case "@query":
                var query = uri.Query;
                return string.IsNullOrEmpty(query) ? "?" : query;
            default:
                if (name.StartsWith('@'))
                    throw new SignatureComponentException(name, "unsupported derived component");
                return ResolveHeader(request, name);
        }
    }

    private static string ResolveHeader(HttpRequestMessage request, string name)
    {
        // Header names in covered components are lowercase; HttpHeaders lookup is case-insensitive.
        // Message (request) headers take precedence, then content headers (content-type, content-length,
        // content-digest live there in .NET).
        if (request.Headers.TryGetValues(name, out var values) ||
            (request.Content is not null && request.Content.Headers.TryGetValues(name, out values)))
        {
            // §2.1: strip OWS from each field value, then combine with ", ".
            return string.Join(", ", values.Select(v => v.Trim()));
        }

        throw new SignatureComponentException(name, "no such header on the request");
    }
}

/// <summary>Parameters of an HTTP message signature (RFC 9421 §2.3).</summary>
internal sealed record SignatureParameters
{
    public long? Created { get; init; }
    public long? Expires { get; init; }
    public string? Nonce { get; init; }
    public string? Alg { get; init; }
    public string? KeyId { get; init; }
    public string? Tag { get; init; }
}
