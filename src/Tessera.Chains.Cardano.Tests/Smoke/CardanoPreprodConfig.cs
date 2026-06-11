using Tessera.Chains.Cardano;

namespace Tessera.Chains.Cardano.Tests.Smoke;

/// <summary>
/// Loads the preprod integration config from environment variables. Returns false with a specific
/// reason when any are missing, so the smoke tests skip (rather than fail) on a fresh checkout.
/// </summary>
internal sealed class CardanoPreprodConfig
{
    public required string BlockfrostProjectId { get; init; }
    public required string SigningKey { get; init; }
    public required CardanoNetwork Network { get; init; }
    public required AnchorMode AnchorMode { get; init; }

    public static bool TryLoad(out CardanoPreprodConfig? config, out string missingReason)
    {
        config = null;

        var projectId = Environment.GetEnvironmentVariable("TESSERA_CARDANO_BLOCKFROST_KEY");
        if (string.IsNullOrWhiteSpace(projectId))
        {
            missingReason = "Set TESSERA_CARDANO_BLOCKFROST_KEY to a Blockfrost preprod project id (e.g. preprod...).";
            return false;
        }

        var signingKey = Environment.GetEnvironmentVariable("TESSERA_CARDANO_SKEY");
        if (string.IsNullOrWhiteSpace(signingKey))
        {
            missingReason = "Set TESSERA_CARDANO_SKEY to a funded preprod payment mnemonic (or extended-key hex).";
            return false;
        }

        var network = (Environment.GetEnvironmentVariable("TESSERA_CARDANO_NETWORK") ?? "preprod").Trim().ToLowerInvariant() switch
        {
            "preview" => CardanoNetwork.Preview,
            "mainnet" => CardanoNetwork.Mainnet,
            _ => CardanoNetwork.Preprod,
        };

        var mode = string.Equals(Environment.GetEnvironmentVariable("TESSERA_CARDANO_MODE"), "metadata", StringComparison.OrdinalIgnoreCase)
            ? AnchorMode.Metadata
            : AnchorMode.Validator;

        config = new CardanoPreprodConfig
        {
            BlockfrostProjectId = projectId.Trim(),
            SigningKey = signingKey.Trim(),
            Network = network,
            AnchorMode = mode,
        };
        missingReason = "";
        return true;
    }
}
