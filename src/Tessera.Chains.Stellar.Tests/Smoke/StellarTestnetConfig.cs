namespace Tessera.Chains.Stellar.Tests.Smoke;

/// <summary>
/// Loads the Stellar testnet integration config from environment variables. Returns false with a
/// specific reason when any are missing, so the smoke tests skip (rather than fail) on a fresh
/// checkout or in CI without secrets. Mirrors <c>CardanoPreprodConfig</c> / <c>EvmTestnetConfig</c>.
/// </summary>
internal sealed class StellarTestnetConfig
{
    public required string SorobanRpcUrl { get; init; }
    public required string ContractId { get; init; }
    public required string SigningKeySeed { get; init; }
    public required string NetworkPassphrase { get; init; }

    public static bool TryLoad(out StellarTestnetConfig? config, out string missingReason)
    {
        config = null;

        var contractId = Environment.GetEnvironmentVariable("TESSERA_STELLAR_CONTRACT");
        if (string.IsNullOrWhiteSpace(contractId))
        {
            missingReason = "Set TESSERA_STELLAR_CONTRACT to a deployed attestation-anchor contract id (C...).";
            return false;
        }

        var signingKey = Environment.GetEnvironmentVariable("TESSERA_STELLAR_SKEY");
        if (string.IsNullOrWhiteSpace(signingKey))
        {
            missingReason = "Set TESSERA_STELLAR_SKEY to a funded testnet account secret seed (S...).";
            return false;
        }

        var rpc = Environment.GetEnvironmentVariable("TESSERA_STELLAR_RPC");
        if (string.IsNullOrWhiteSpace(rpc))
            rpc = "https://soroban-testnet.stellar.org";

        var passphrase = Environment.GetEnvironmentVariable("TESSERA_STELLAR_PASSPHRASE");
        if (string.IsNullOrWhiteSpace(passphrase))
            passphrase = "Test SDF Network ; September 2015";

        config = new StellarTestnetConfig
        {
            SorobanRpcUrl = rpc.Trim(),
            ContractId = contractId.Trim(),
            SigningKeySeed = signingKey.Trim(),
            NetworkPassphrase = passphrase.Trim(),
        };
        missingReason = "";
        return true;
    }
}
