using Tessera.Channels;

namespace Tessera.Channels.Tests;

/// <summary>
/// Covers the homoglyph/compatibility-collision fix (M-4): the normaliser applies NFKC so two
/// visually-identical handles cannot derive different commitments, and the length cap (Low).
/// </summary>
public class ChannelNormalizerTests
{
    private static readonly DefaultChannelNormalizer Normalizer = new();

    [Fact]
    public void Email_NfkcFoldsFullwidthToAscii()
    {
        // "ＦＯＯ@bar.com" with FULLWIDTH F/O/O (U+FF26, U+FF2F) must canonicalise identically to ASCII.
        var fullwidth = Normalizer.Normalize(ChannelTypes.Email, "ＦＯＯ@bar.com");
        var ascii = Normalizer.Normalize(ChannelTypes.Email, "FOO@bar.com");

        Assert.Equal("foo@bar.com", fullwidth);
        Assert.Equal(ascii, fullwidth);
    }

    [Fact]
    public void Telegram_NfkcFoldsCompatibilityForms()
    {
        // "＠Alice" (fullwidth @) → strip @ → fold → lowercase.
        var a = Normalizer.Normalize(ChannelTypes.Telegram, "＠Alice");
        var b = Normalizer.Normalize(ChannelTypes.Telegram, "@alice");
        Assert.Equal(b, a);
    }

    [Fact]
    public void Normalize_RejectsOverlongHandle()
    {
        var huge = new string('a', 300) + "@bar.com";
        Assert.Throws<ArgumentException>(() => Normalizer.Normalize(ChannelTypes.Email, huge));
    }
}
