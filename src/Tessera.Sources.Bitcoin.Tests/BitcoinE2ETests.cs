namespace Tessera.Sources.Bitcoin.Tests;

/// <summary>
/// Live integration against the mempool.space Esplora testnet API. Skipped unless
/// <c>TESSERA_BITCOIN_E2E=1</c>, so CI stays hermetic. Override the queried address with
/// <c>TESSERA_BITCOIN_E2E_ADDRESS</c> and the base URL with <c>TESSERA_BITCOIN_E2E_BASEURL</c>.
/// Assertions are structural (internal API consistency), so they hold regardless of the live balance.
/// </summary>
public class BitcoinE2ETests
{
    [SkippableFact]
    public async Task EsploraProvider_ReadsTestnetAddress_Consistently()
    {
        Skip.IfNot(Environment.GetEnvironmentVariable("TESSERA_BITCOIN_E2E") == "1",
            "Set TESSERA_BITCOIN_E2E=1 to run the live mempool.space testnet integration test.");

        var address = Environment.GetEnvironmentVariable("TESSERA_BITCOIN_E2E_ADDRESS")
            ?? "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        var baseUrl = Environment.GetEnvironmentVariable("TESSERA_BITCOIN_E2E_BASEURL");

        using var provider = new EsploraBitcoinProvider(new EsploraBitcoinProviderOptions
        {
            Network = BitcoinNetwork.Testnet,
            BaseUrl = baseUrl,
        });

        var summary = await provider.GetAddressSummaryAsync(address);
        var utxos = await provider.GetUtxosAsync(address);

        Assert.True(summary.ConfirmedSats >= 0);
        // Esplora invariant: confirmed balance == Σ confirmed UTXO values.
        Assert.Equal(summary.ConfirmedSats, utxos.Sum(u => u.ValueSats));

        foreach (var u in utxos)
        {
            Assert.True(u.ValueSats > 0);
            Assert.True(u.BlockHeight > 0);
            Assert.True(u.BlockTime > 0);
            Assert.Equal(64, u.TxId.Length);
        }
    }
}
