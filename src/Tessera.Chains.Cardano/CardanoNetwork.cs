namespace Tessera.Chains.Cardano;

/// <summary>
/// Cardano network the adapter talks to. Determines the Blockfrost base URL, the
/// address network tag, and the network id placed in transactions.
/// </summary>
public enum CardanoNetwork
{
    /// <summary>The preprod testnet — the reference target for this adapter.</summary>
    Preprod = 0,

    /// <summary>The preview testnet.</summary>
    Preview = 1,

    /// <summary>Mainnet. Anchoring real identities; use with care.</summary>
    Mainnet = 2,
}

/// <summary>Network-derived constants. Internal — the adapter resolves these from <see cref="CardanoNetwork"/>.</summary>
internal static class CardanoNetworkInfo
{
    /// <summary>Blockfrost API base URL (no trailing slash) for the given network.</summary>
    public static string BlockfrostBaseUrl(CardanoNetwork network) => network switch
    {
        CardanoNetwork.Preprod => "https://cardano-preprod.blockfrost.io/api/v0",
        CardanoNetwork.Preview => "https://cardano-preview.blockfrost.io/api/v0",
        CardanoNetwork.Mainnet => "https://cardano-mainnet.blockfrost.io/api/v0",
        _ => throw new ArgumentOutOfRangeException(nameof(network), network, "Unsupported Cardano network."),
    };

    /// <summary>True for testnets (network id 0); false for mainnet (network id 1).</summary>
    public static bool IsTestnet(CardanoNetwork network) => network != CardanoNetwork.Mainnet;

    /// <summary>Shelley address network id: 0 = testnet, 1 = mainnet.</summary>
    public static byte NetworkId(CardanoNetwork network) => (byte)(network == CardanoNetwork.Mainnet ? 1 : 0);

    /// <summary>Bech32 HRP for payment/script addresses on the network.</summary>
    public static string AddressHrp(CardanoNetwork network) => network == CardanoNetwork.Mainnet ? "addr" : "addr_test";
}
