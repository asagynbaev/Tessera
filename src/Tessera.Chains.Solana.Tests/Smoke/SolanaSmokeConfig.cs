using System.Text.Json;

namespace Tessera.Chains.Solana.Tests.Smoke;

/// <summary>
/// Resolves devnet/testnet smoke test configuration from environment variables.
/// When any required variable is missing, <see cref="TryLoad"/> returns false and
/// <see cref="MissingReason"/> explains which one — surface this in <c>Skip.If</c>.
/// </summary>
/// <remarks>
/// Required env vars:
/// <list type="bullet">
///   <item><c>TESSERA_SOLANA_RPC</c>: RPC URL, e.g. <c>https://api.devnet.solana.com</c></item>
///   <item><c>TESSERA_SOLANA_PROGRAM_ID</c>: base58 program ID of the deployed identity-registry</item>
///   <item><c>TESSERA_SOLANA_PAYER_KEYPAIR</c>: filesystem path to a Solana CLI JSON keypair file (64-byte array)</item>
/// </list>
/// </remarks>
internal sealed class SolanaSmokeConfig
{
    public required string RpcUrl { get; init; }
    public required string ProgramId { get; init; }
    public required byte[] PayerKeypair { get; init; }

    public static bool TryLoad(out SolanaSmokeConfig? config, out string missingReason)
    {
        config = null;

        var rpc = Environment.GetEnvironmentVariable("TESSERA_SOLANA_RPC");
        if (string.IsNullOrWhiteSpace(rpc))
        {
            missingReason = "TESSERA_SOLANA_RPC not set (e.g. https://api.devnet.solana.com).";
            return false;
        }

        var programId = Environment.GetEnvironmentVariable("TESSERA_SOLANA_PROGRAM_ID");
        if (string.IsNullOrWhiteSpace(programId))
        {
            missingReason = "TESSERA_SOLANA_PROGRAM_ID not set (deployed identity-registry pubkey).";
            return false;
        }

        var keypairPath = Environment.GetEnvironmentVariable("TESSERA_SOLANA_PAYER_KEYPAIR");
        if (string.IsNullOrWhiteSpace(keypairPath))
        {
            missingReason = "TESSERA_SOLANA_PAYER_KEYPAIR not set (path to Solana CLI JSON keypair file).";
            return false;
        }

        if (!File.Exists(keypairPath))
        {
            missingReason = $"Keypair file not found at {keypairPath}.";
            return false;
        }

        byte[] keypair;
        try
        {
            keypair = ParseSolanaJsonKeypair(File.ReadAllText(keypairPath));
        }
        catch (Exception ex)
        {
            missingReason = $"Failed to parse keypair at {keypairPath}: {ex.Message}";
            return false;
        }

        config = new SolanaSmokeConfig
        {
            RpcUrl = rpc.Trim(),
            ProgramId = programId.Trim(),
            PayerKeypair = keypair,
        };
        missingReason = "";
        return true;
    }

    /// <summary>
    /// Parse a Solana CLI keypair file (JSON array of 64 unsigned bytes — first 32 are the
    /// private seed, last 32 are the derived public key).
    /// </summary>
    private static byte[] ParseSolanaJsonKeypair(string json)
    {
        // Solana CLI keypair files are a JSON array of 64 byte-valued integers, e.g.
        // [25,24,8,252,...]. System.Text.Json maps `byte[]` to a Base64 *string*, so it cannot
        // read that array form (it throws "could not be converted to System.Byte[]"). Deserialize
        // through List<byte>, which reads each JSON number as a byte.
        var parsed = JsonSerializer.Deserialize<List<byte>>(json)?.ToArray()
            ?? throw new FormatException("Keypair JSON deserialized to null.");
        if (parsed.Length != 64)
            throw new FormatException($"Expected 64 bytes in keypair file (got {parsed.Length}).");
        return parsed;
    }
}
