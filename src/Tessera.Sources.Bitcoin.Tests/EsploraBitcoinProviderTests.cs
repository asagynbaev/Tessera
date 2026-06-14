using System.Net;

namespace Tessera.Sources.Bitcoin.Tests;

public class EsploraBitcoinProviderTests
{
    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, int, HttpResponseMessage> _responder;
        private int _calls;
        public int Calls => _calls;
        public StubHandler(Func<HttpRequestMessage, int, HttpResponseMessage> responder) => _responder = responder;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(_responder(request, ++_calls));
    }

    private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK)
        => new(status) { Content = new StringContent(body) };

    private const string SummaryJson =
        """{"address":"tb1qx","chain_stats":{"funded_txo_count":3,"funded_txo_sum":150000,"spent_txo_count":1,"spent_txo_sum":50000,"tx_count":4},"mempool_stats":{"funded_txo_sum":0,"spent_txo_sum":0}}""";

    private const string UtxoJson =
        """[{"txid":"a1a1","vout":0,"value":100000,"status":{"confirmed":true,"block_height":800000,"block_time":1690000000}},{"txid":"b2b2","vout":1,"value":7,"status":{"confirmed":false}}]""";

    private static EsploraBitcoinProvider Provider(StubHandler handler, BitcoinRetryPolicy? retry = null)
        => new(new EsploraBitcoinProviderOptions { Network = BitcoinNetwork.Testnet, Retry = retry ?? BitcoinRetryPolicy.None },
               new HttpClient(handler));

    [Fact]
    public async Task GetAddressSummary_ComputesConfirmedFromFundedMinusSpent()
    {
        var provider = Provider(new StubHandler((_, _) => Json(SummaryJson)));
        var summary = await provider.GetAddressSummaryAsync("tb1qx");
        Assert.Equal(100000, summary.ConfirmedSats); // 150000 − 50000
    }

    [Fact]
    public async Task GetUtxos_OnlyConfirmed_WithValueHeightTime()
    {
        var provider = Provider(new StubHandler((_, _) => Json(UtxoJson)));
        var utxos = await provider.GetUtxosAsync("tb1qx");
        Assert.Single(utxos); // the unconfirmed one is excluded
        Assert.Equal(100000, utxos[0].ValueSats);
        Assert.Equal(800000, utxos[0].BlockHeight);
        Assert.Equal(1690000000, utxos[0].BlockTime);
        Assert.Equal("a1a1", utxos[0].TxId);
    }

    [Fact]
    public async Task NotFoundAddress_YieldsZeroSummary_AndEmptyUtxos()
    {
        var provider = Provider(new StubHandler((_, _) => Json("Not Found", HttpStatusCode.NotFound)));
        Assert.Equal(0, (await provider.GetAddressSummaryAsync("tb1qnever")).ConfirmedSats);
        Assert.Empty(await provider.GetUtxosAsync("tb1qnever"));
    }

    [Fact]
    public async Task TransientStatus_IsRetried_ThenSucceeds()
    {
        var handler = new StubHandler((_, call) =>
            call == 1 ? Json("upstream", HttpStatusCode.ServiceUnavailable) : Json(SummaryJson));
        var provider = Provider(handler, new BitcoinRetryPolicy { MaxAttempts = 3, BaseDelay = TimeSpan.Zero });

        var summary = await provider.GetAddressSummaryAsync("tb1qx");
        Assert.Equal(100000, summary.ConfirmedSats);
        Assert.Equal(2, handler.Calls); // failed once, then succeeded
    }

    [Fact]
    public async Task NonTransientStatus_ThrowsInvalidOperation_NoRetry()
    {
        var handler = new StubHandler((_, _) => Json("bad request", HttpStatusCode.BadRequest));
        var provider = Provider(handler, new BitcoinRetryPolicy { MaxAttempts = 3, BaseDelay = TimeSpan.Zero });

        await Assert.ThrowsAsync<InvalidOperationException>(() => provider.GetAddressSummaryAsync("tb1qx"));
        Assert.Equal(1, handler.Calls); // not retried
    }

    [Fact]
    public async Task GetChainTip_ReadsHeightHashAndBlockTime()
    {
        const string tipHash = "0000000000000000000a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566";
        var handler = new StubHandler((req, _) =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path.EndsWith("/blocks/tip/height", StringComparison.Ordinal)) return Json("850321");
            if (path.EndsWith("/blocks/tip/hash", StringComparison.Ordinal)) return Json(tipHash);
            if (path.Contains("/block/", StringComparison.Ordinal))
                return Json($$"""{"id":"{{tipHash}}","height":850321,"timestamp":1700000000}""");
            return Json("not found", HttpStatusCode.NotFound);
        });
        var provider = Provider(handler);

        var tip = await provider.GetChainTipAsync();

        Assert.Equal(850321, tip.BlockHeight);
        Assert.Equal(tipHash, tip.BlockHash);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1700000000), tip.BlockTimeUtc);
    }

    [Fact]
    public async Task RateLimited_AfterExhaustingAttempts_ThrowsTransient()
    {
        var handler = new StubHandler((_, _) => Json("slow down", HttpStatusCode.TooManyRequests));
        var provider = Provider(handler, BitcoinRetryPolicy.None);
        await Assert.ThrowsAsync<TransientBitcoinProviderException>(() => provider.GetAddressSummaryAsync("tb1qx"));
    }
}
