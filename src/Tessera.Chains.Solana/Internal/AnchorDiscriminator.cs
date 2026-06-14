using System.Security.Cryptography;
using System.Text;

namespace Tessera.Chains.Solana.Internal;

/// <summary>
/// Anchor framework uses 8-byte discriminators on both instructions and account data.
/// <list type="bullet">
///   <item><b>Instruction</b>: <c>sha256("global:" + snake_case_instr_name)[0..8]</c></item>
///   <item><b>Account</b>: <c>sha256("account:" + PascalCaseAccountName)[0..8]</c></item>
/// </list>
/// These are computed at build time once per program and cached.
/// </summary>
internal static class AnchorDiscriminator
{
    public static byte[] ForInstruction(string snakeCaseName)
        => Hash8("global:" + snakeCaseName);

    public static byte[] ForAccount(string pascalCaseName)
        => Hash8("account:" + pascalCaseName);

    private static byte[] Hash8(string input)
    {
        Span<byte> full = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(input), full);
        return full[..8].ToArray();
    }
}

/// <summary>Pre-computed discriminators for the identity-registry program.</summary>
internal static class IdentityRegistryDiscriminators
{
    public static readonly byte[] Initialize = AnchorDiscriminator.ForInstruction("initialize");
    public static readonly byte[] RegisterDid = AnchorDiscriminator.ForInstruction("register_did");
    public static readonly byte[] UpdateRoot = AnchorDiscriminator.ForInstruction("update_root");
    public static readonly byte[] BumpRevocation = AnchorDiscriminator.ForInstruction("bump_revocation");
    public static readonly byte[] RegisterIssuer = AnchorDiscriminator.ForInstruction("register_issuer");
    public static readonly byte[] DeactivateIssuer = AnchorDiscriminator.ForInstruction("deactivate_issuer");

    public static readonly byte[] RegistryConfigAccount = AnchorDiscriminator.ForAccount("RegistryConfig");
    public static readonly byte[] DidAnchorAccount = AnchorDiscriminator.ForAccount("DidAnchor");
    public static readonly byte[] IssuerAccount = AnchorDiscriminator.ForAccount("Issuer");
}
