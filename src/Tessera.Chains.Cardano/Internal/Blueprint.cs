using System.Text.Json;

namespace Tessera.Chains.Cardano.Internal;

/// <summary>
/// Reads the Aiken <c>plutus.json</c> blueprint embedded in the package and exposes the
/// compiled validator bytes. The compiled code is the raw Plutus V3 script (the bytes that,
/// prefixed with the V3 language tag, hash to the policy id / script hash).
/// </summary>
internal static class Blueprint
{
    private const string ResourceName = "Tessera.Chains.Cardano.plutus.json";

    // Validator titles as emitted by `aiken build` (module.validator.handler).
    public const string IdentityAnchorTitle = "identity_anchor.identity_anchor.mint";
    public const string IssuerRegistryTitle = "issuer_registry.issuer_registry.mint";

    public static byte[] LoadIdentityAnchorScript() => LoadCompiledCode(IdentityAnchorTitle);

    public static byte[] LoadIssuerRegistryScript() => LoadCompiledCode(IssuerRegistryTitle);

    private static byte[] LoadCompiledCode(string title)
    {
        using var stream = typeof(Blueprint).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException($"Embedded blueprint '{ResourceName}' was not found in the assembly.");
        using var doc = JsonDocument.Parse(stream);
        foreach (var validator in doc.RootElement.GetProperty("validators").EnumerateArray())
        {
            if (validator.GetProperty("title").GetString() == title)
            {
                var hex = validator.GetProperty("compiledCode").GetString()
                    ?? throw new InvalidOperationException($"Validator '{title}' has no compiledCode.");
                return Convert.FromHexString(hex);
            }
        }
        throw new InvalidOperationException($"Validator '{title}' not found in the embedded blueprint.");
    }
}
