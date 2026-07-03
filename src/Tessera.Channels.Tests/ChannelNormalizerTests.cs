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

    [Fact]
    public void Normalize_RejectsHandleThatExceedsCapAfterNfkcExpansion()
    {
        // U+FDFA (ARABIC LIGATURE SALLALLAHOU ALAYHE WASALLAM) expands to 18 chars under NFKC.
        // 20 copies = 20 raw chars (under the 256 cap) but 360 after normalization, so the cap must be
        // re-enforced on the NORMALIZED string, not just the raw input.
        var expanding = new string('ﷺ', 20);
        Assert.True(expanding.Length <= 256);                       // passes the raw-length check
        Assert.True(expanding.Normalize(System.Text.NormalizationForm.FormKC).Length > 256); // but not after NFKC
        Assert.Throws<ArgumentException>(() => Normalizer.Normalize(ChannelTypes.Email, expanding));
    }

    [Fact]
    public void NormalizePhone_MaxLengthDigits_DoesNotOverflow()
    {
        // A 256-char all-digit handle sits exactly at the cap; normalization must succeed (the phone
        // scratch buffer is sized safely) rather than blow the stack.
        var digits = new string('5', 256);
        var normalized = Normalizer.Normalize(ChannelTypes.Phone, digits);
        Assert.Equal("+" + digits, normalized);
    }
}
