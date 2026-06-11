using NBitcoin;

namespace Tessera.Sources.Bitcoin;

/// <summary>
/// Bitcoin network the source talks to. Determines the default Esplora base URL and the
/// address-network rules used when parsing/deriving addresses for signature verification.
/// </summary>
public enum BitcoinNetwork
{
    /// <summary>Bitcoin mainnet.</summary>
    Mainnet = 0,

    /// <summary>The public test network (testnet3/4).</summary>
    Testnet = 1,

    /// <summary>The signet test network. Shares testnet address formats; distinct Esplora endpoint.</summary>
    Signet = 2,
}

/// <summary>Network-derived constants. Internal — the source resolves these from <see cref="BitcoinNetwork"/>.</summary>
internal static class BitcoinNetworkInfo
{
    /// <summary>
    /// Default Esplora API base URL (no trailing slash) for the given network, pointing at
    /// mempool.space. Override via <see cref="EsploraBitcoinProviderOptions.BaseUrl"/> (e.g. to
    /// blockstream.info or a self-hosted Esplora). Both expose the same Esplora REST shape.
    /// </summary>
    public static string DefaultEsploraBaseUrl(BitcoinNetwork network) => network switch
    {
        BitcoinNetwork.Mainnet => "https://mempool.space/api",
        BitcoinNetwork.Testnet => "https://mempool.space/testnet/api",
        BitcoinNetwork.Signet => "https://mempool.space/signet/api",
        _ => throw new ArgumentOutOfRangeException(nameof(network), network, "Unsupported Bitcoin network."),
    };

    /// <summary>
    /// NBitcoin <see cref="Network"/> for address parsing/derivation. Signet uses the same address
    /// prefixes as testnet (tb1.../m/n/2...), so it maps to <see cref="Network.TestNet"/>; message
    /// signing/recovery is network-independent (the magic prefix is identical on every network).
    /// </summary>
    public static Network ToNBitcoin(BitcoinNetwork network) => network switch
    {
        BitcoinNetwork.Mainnet => Network.Main,
        BitcoinNetwork.Testnet => Network.TestNet,
        BitcoinNetwork.Signet => Network.TestNet,
        _ => throw new ArgumentOutOfRangeException(nameof(network), network, "Unsupported Bitcoin network."),
    };
}
