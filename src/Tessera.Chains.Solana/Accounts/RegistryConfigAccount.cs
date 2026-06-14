using Tessera.Chains.Solana.Internal;

namespace Tessera.Chains.Solana.Accounts;

/// <summary>
/// Decoded singleton <c>RegistryConfig</c> account from the identity-registry program.
/// Mirrors the Rust <c>#[account] struct RegistryConfig</c> after the 8-byte discriminator.
/// Holds the admin pubkey that gates issuer registration / deactivation.
/// </summary>
public sealed record RegistryConfigAccount
{
    public required byte AccountVersion { get; init; }
    public required byte[] Admin { get; init; }
    public required byte Bump { get; init; }

    /// <summary>
    /// Decode raw account data (including the 8-byte Anchor discriminator) into a <see cref="RegistryConfigAccount"/>.
    /// </summary>
    /// <exception cref="ArgumentException">If the data is too short or the discriminator does not match <c>RegistryConfig</c>.</exception>
    public static RegistryConfigAccount Decode(ReadOnlySpan<byte> rawAccountData)
    {
        const int expectedLen = 8 + 1 + 32 + 1; // 42
        if (rawAccountData.Length < expectedLen)
            throw new ArgumentException(
                $"RegistryConfig account data must be at least {expectedLen} bytes (got {rawAccountData.Length}).",
                nameof(rawAccountData));

        var disc = rawAccountData[..8];
        if (!disc.SequenceEqual(IdentityRegistryDiscriminators.RegistryConfigAccount))
            throw new ArgumentException("Account discriminator does not match RegistryConfig.", nameof(rawAccountData));

        var reader = new AnchorBorshReader(rawAccountData[8..]);
        return new RegistryConfigAccount
        {
            AccountVersion = reader.ReadU8(),
            Admin = reader.ReadPubkey(),
            Bump = reader.ReadU8(),
        };
    }
}
