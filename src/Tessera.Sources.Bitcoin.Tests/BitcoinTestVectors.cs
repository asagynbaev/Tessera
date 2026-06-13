using Tessera.Core;

namespace Tessera.Sources.Bitcoin.Tests;

/// <summary>
/// Fixed, checked-in signature vectors. Generated once with NBitcoin from a deterministic private
/// key (scalar = bytes 1..32) signing the canonical challenge <see cref="Message"/>, one address
/// per supported type on both testnet and mainnet. Reproducible: re-running the generator yields
/// these exact values. The signatures all recover the same key (a single deterministic compact
/// signature) but carry the BIP-137 header for their address type (P2PKH 27–34, P2SH-P2WPKH 35–38,
/// P2WPKH 39–42), exercising the verifier's header tolerance.
/// </summary>
public static class BitcoinTestVectors
{
    // Canonical challenge fields the fixtures were signed over.
    public const string Subject = "did:tessera:fixturesubject";
    public const string Audience = "tessera-fixtures";
    public const string NonceHex = "000102030405060708090a0b0c0d0e0f10111213"; // 20 bytes
    public const long IssuedAtUnix = 1700000000;
    public const long ExpiresAtUnix = 1700003600;

    /// <summary>The exact UTF-8 string the fixtures were signed over (a Tessera canonical challenge).</summary>
    public const string Message =
        "tessera-btc-v1\n" +
        "sub=did:tessera:fixturesubject\n" +
        "aud=tessera-fixtures\n" +
        "nonce=000102030405060708090a0b0c0d0e0f10111213\n" +
        "iat=1700000000\n" +
        "exp=1700003600";

    public sealed record Vector(string Address, string Signature, BitcoinAddressType Type, BitcoinNetwork Network);

    // ── Testnet ──────────────────────────────────────────────────────────────
    public static readonly Vector TestnetP2pkh = new(
        "moaq2wd69udJAEbhy2dByzcNtUsYivsjpU",
        "IBZDZadgObZ5Jdg2P08OMXW7u1KhTOzJQvDUQEOFiTjXA0pbzdH2ZXIsWmXy9y9Hog+tk02kD2Tc8DZ1Qdxuwmk=",
        BitcoinAddressType.P2pkh, BitcoinNetwork.Testnet);

    public static readonly Vector TestnetP2shP2wpkh = new(
        "2NEyiLhvWx94tUVpgwztKLpM9oEZop8jBZx",
        "JBZDZadgObZ5Jdg2P08OMXW7u1KhTOzJQvDUQEOFiTjXA0pbzdH2ZXIsWmXy9y9Hog+tk02kD2Tc8DZ1Qdxuwmk=",
        BitcoinAddressType.P2shP2wpkh, BitcoinNetwork.Testnet);

    public static readonly Vector TestnetP2wpkh = new(
        "tb1qtp7fhly84qm6q4hhzmp0nh5frtdugmysqkxd0h",
        "KBZDZadgObZ5Jdg2P08OMXW7u1KhTOzJQvDUQEOFiTjXA0pbzdH2ZXIsWmXy9y9Hog+tk02kD2Tc8DZ1Qdxuwmk=",
        BitcoinAddressType.P2wpkh, BitcoinNetwork.Testnet);

    /// <summary>A Taproot (P2TR) address derived from the same key — verification is unsupported.</summary>
    public const string TestnetTaproot = "tb1pf22hwrhley3ah6qjt6234rs00fn84c2396ky4yea305kl02ezynsx7n7sv";

    /// <summary>
    /// The <b>uncompressed</b>-key P2PKH address for the same key. The same compact signature
    /// recovers the key; the uncompressed form is matched via the verifier's decompress branch
    /// (the "P2PKH compressed/uncompressed" BIP-137 variant).
    /// </summary>
    public static readonly Vector TestnetP2pkhUncompressed = new(
        "myx28C8fQQyDDKYe7cqewp28dJaPxnJZnv",
        TestnetP2pkh.Signature,
        BitcoinAddressType.P2pkh, BitcoinNetwork.Testnet);

    /// <summary>A testnet P2WSH address (witness v0, 32-byte program) — an unsupported script type.</summary>
    public const string TestnetP2wsh = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";

    // ── Mainnet ──────────────────────────────────────────────────────────────
    public static readonly Vector MainnetP2pkh = new(
        "194sjtY7LtC3P886FTepA5Q42VGqrwTK86",
        "IBZDZadgObZ5Jdg2P08OMXW7u1KhTOzJQvDUQEOFiTjXA0pbzdH2ZXIsWmXy9y9Hog+tk02kD2Tc8DZ1Qdxuwmk=",
        BitcoinAddressType.P2pkh, BitcoinNetwork.Mainnet);

    public static readonly Vector MainnetP2shP2wpkh = new(
        "3PRWGxzVLgZYGiC9GsGSisMtatMe18mJvh",
        "JBZDZadgObZ5Jdg2P08OMXW7u1KhTOzJQvDUQEOFiTjXA0pbzdH2ZXIsWmXy9y9Hog+tk02kD2Tc8DZ1Qdxuwmk=",
        BitcoinAddressType.P2shP2wpkh, BitcoinNetwork.Mainnet);

    public static readonly Vector MainnetP2wpkh = new(
        "bc1qtp7fhly84qm6q4hhzmp0nh5frtdugmys2sa75y",
        "KBZDZadgObZ5Jdg2P08OMXW7u1KhTOzJQvDUQEOFiTjXA0pbzdH2ZXIsWmXy9y9Hog+tk02kD2Tc8DZ1Qdxuwmk=",
        BitcoinAddressType.P2wpkh, BitcoinNetwork.Mainnet);

    public static readonly Vector[] All =
    {
        TestnetP2pkh, TestnetP2shP2wpkh, TestnetP2wpkh,
        MainnetP2pkh, MainnetP2shP2wpkh, MainnetP2wpkh,
    };

    /// <summary>The exact <see cref="BitcoinChallenge"/> the fixtures were signed over.</summary>
    public static BitcoinChallenge Challenge() => new()
    {
        Subject = new DidId(Subject),
        Audience = Audience,
        Nonce = Convert.FromHexString(NonceHex),
        IssuedAt = DateTimeOffset.FromUnixTimeSeconds(IssuedAtUnix),
        ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(ExpiresAtUnix),
    };
}
