namespace Tessera.Agents.HttpMessageSignatures;

/// <summary>One parsed member of a <c>Signature-Input</c> dictionary.</summary>
internal sealed record ParsedSignatureInput
{
    public required string Label { get; init; }

    /// <summary>Covered component names in order, bare (unquoted), e.g. <c>@method</c>, <c>content-digest</c>.</summary>
    public required IReadOnlyList<string> Components { get; init; }

    /// <summary>
    /// The exact value string for this label (<c>(...)</c> plus <c>;params</c>), captured verbatim so it can
    /// be used as the <c>@signature-params</c> line without re-serialization drift.
    /// </summary>
    public required string RawValue { get; init; }

    public required SignatureParameters Parameters { get; init; }
}

/// <summary>
/// Minimal parser for the two RFC 9421 structured-field headers this library needs:
/// <c>Signature-Input</c> (a dictionary of <c>label=(inner-list);params</c>) and <c>Signature</c>
/// (a dictionary of <c>label=:base64-byte-sequence:</c>). It is deliberately scoped to those shapes;
/// it is not a general RFC 8941 implementation.
/// </summary>
internal static class SignatureHeaders
{
    /// <summary>Parse the member with <paramref name="label"/> from a <c>Signature-Input</c> header value.</summary>
    public static ParsedSignatureInput? ParseInput(string header, string label)
    {
        foreach (var (memberLabel, value) in SplitMembers(header))
        {
            if (memberLabel != label) continue;

            var close = value.IndexOf(')');
            if (value.Length == 0 || value[0] != '(' || close < 0)
                return null;

            var inner = value[1..close];
            var components = new List<string>();
            foreach (var token in SplitTopLevel(inner, ' '))
            {
                var t = token.Trim();
                if (t.Length == 0) continue;
                if (t.Length < 2 || t[0] != '"' || t[^1] != '"') return null; // component params not supported
                components.Add(t[1..^1]);
            }

            var parameters = ParseParameters(value[(close + 1)..]);
            return new ParsedSignatureInput
            {
                Label = label,
                Components = components,
                RawValue = value,
                Parameters = parameters,
            };
        }

        return null;
    }

    /// <summary>Parse the signature bytes for <paramref name="label"/> from a <c>Signature</c> header value.</summary>
    public static byte[]? ParseSignature(string header, string label)
    {
        foreach (var (memberLabel, value) in SplitMembers(header))
        {
            if (memberLabel != label) continue;
            if (value.Length < 2 || value[0] != ':' || value[^1] != ':') return null;
            try { return Convert.FromBase64String(value[1..^1]); }
            catch (FormatException) { return null; }
        }

        return null;
    }

    private static SignatureParameters ParseParameters(string paramsPart)
    {
        long? created = null, expires = null;
        string? nonce = null, alg = null, keyid = null, tag = null;

        foreach (var raw in SplitTopLevel(paramsPart, ';'))
        {
            var seg = raw.Trim();
            if (seg.Length == 0) continue;
            var eq = seg.IndexOf('=');
            if (eq <= 0) continue;
            var key = seg[..eq].Trim();
            var val = seg[(eq + 1)..].Trim();
            var str = val.Length >= 2 && val[0] == '"' && val[^1] == '"' ? val[1..^1] : val;

            switch (key)
            {
                case "created": created = ParseLong(val); break;
                case "expires": expires = ParseLong(val); break;
                case "nonce": nonce = str; break;
                case "alg": alg = str; break;
                case "keyid": keyid = str; break;
                case "tag": tag = str; break;
            }
        }

        return new SignatureParameters
        {
            Created = created,
            Expires = expires,
            Nonce = nonce,
            Alg = alg,
            KeyId = keyid,
            Tag = tag,
        };
    }

    private static long? ParseLong(string v) => long.TryParse(v, out var n) ? n : null;

    /// <summary>Split a structured-field dictionary into <c>(label, value)</c> members on top-level commas.</summary>
    private static IEnumerable<(string Label, string Value)> SplitMembers(string header)
    {
        foreach (var member in SplitTopLevel(header, ','))
        {
            var seg = member.Trim();
            if (seg.Length == 0) continue;
            var eq = seg.IndexOf('=');
            if (eq <= 0) continue;
            yield return (seg[..eq].Trim(), seg[(eq + 1)..].Trim());
        }
    }

    /// <summary>Split on <paramref name="separator"/> only where it is not inside quotes or parentheses.</summary>
    private static IEnumerable<string> SplitTopLevel(string s, char separator)
    {
        var start = 0;
        var depth = 0;
        var inQuotes = false;
        for (var i = 0; i < s.Length; i++)
        {
            var ch = s[i];
            if (inQuotes)
            {
                if (ch == '\\') { i++; continue; } // skip escaped char
                if (ch == '"') inQuotes = false;
                continue;
            }
            switch (ch)
            {
                case '"': inQuotes = true; break;
                case '(': depth++; break;
                case ')': if (depth > 0) depth--; break;
                default:
                    if (ch == separator && depth == 0)
                    {
                        yield return s[start..i];
                        start = i + 1;
                    }
                    break;
            }
        }
        yield return s[start..];
    }
}
