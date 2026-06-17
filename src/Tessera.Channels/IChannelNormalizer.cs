namespace Tessera.Channels;

/// <summary>
/// Canonicalises a channel handle before commitment derivation so that visually-equivalent
/// inputs hash to the same commitment ("FOO@bar.com" and "foo@bar.com", "+1 555 0100" and
/// "+15550100").
/// </summary>
/// <remarks>
/// The normaliser is part of the on-disk format: changing it later breaks compatibility
/// with previously stored commitments. Treat it like a database migration.
/// </remarks>
public interface IChannelNormalizer
{
    /// <summary>Return the canonical representation of <paramref name="handle"/> for <paramref name="channelType"/>.</summary>
    /// <exception cref="ArgumentException">If the handle is empty, whitespace, or fails type-specific validation.</exception>
    string Normalize(string channelType, string handle);
}

/// <summary>
/// Default canonicalisation:
/// <list type="bullet">
///   <item><b>phone</b>: trim, strip everything except digits, prepend a leading <c>+</c>. Naive E.164 — does not validate country codes.</item>
///   <item><b>email</b>: trim, lowercase the whole string.</item>
///   <item><b>telegram</b>: trim, strip leading <c>@</c>, lowercase.</item>
///   <item><b>other</b>: trim only.</item>
/// </list>
/// Replace with a domain-specific normaliser (e.g. libphonenumber for proper E.164) when
/// the naive rules are not sufficient.
/// </summary>
public sealed class DefaultChannelNormalizer : IChannelNormalizer
{
    /// <summary>Upper bound on handle length: bounds the work and the phone normaliser's stack buffer.</summary>
    private const int MaxHandleLength = 256;

    public string Normalize(string channelType, string handle)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(handle);
        ArgumentException.ThrowIfNullOrEmpty(channelType);
        if (handle.Length > MaxHandleLength)
            throw new ArgumentException($"Handle exceeds {MaxHandleLength} characters.", nameof(handle));

        // NFKC folds Unicode compatibility/confusable forms so two visually-identical handles cannot
        // derive different commitments (nor a look-alike dodge an existing binding). This participates
        // in the on-disk format, but only changes commitments for non-NFKC (i.e. non-ASCII) handles.
        var trimmed = handle.Normalize(System.Text.NormalizationForm.FormKC).Trim();

        return channelType switch
        {
            ChannelTypes.Phone => NormalizePhone(trimmed),
            ChannelTypes.Email => trimmed.ToLowerInvariant(),
            ChannelTypes.Telegram => NormalizeTelegram(trimmed),
            _ => trimmed,
        };
    }

    private static string NormalizePhone(string s)
    {
        Span<char> buf = stackalloc char[s.Length + 1];
        int i = 0;
        buf[i++] = '+';
        foreach (var c in s)
            if (c is >= '0' and <= '9')
                buf[i++] = c;

        if (i == 1)
            throw new ArgumentException("Phone handle contains no digits.", nameof(s));

        return new string(buf[..i]);
    }

    private static string NormalizeTelegram(string s)
    {
        var stripped = s.StartsWith('@') ? s[1..] : s;
        if (string.IsNullOrEmpty(stripped))
            throw new ArgumentException("Telegram handle is empty after stripping leading '@'.", nameof(s));
        return stripped.ToLowerInvariant();
    }
}
