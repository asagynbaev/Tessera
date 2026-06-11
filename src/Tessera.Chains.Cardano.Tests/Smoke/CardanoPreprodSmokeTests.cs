using System.Security.Cryptography;
using Tessera.Chains.Cardano;
using Tessera.Core;

namespace Tessera.Chains.Cardano.Tests.Smoke;

/// <summary>
/// Live preprod integration. Skipped unless TESSERA_CARDANO_BLOCKFROST_KEY and
/// TESSERA_CARDANO_SKEY are set (and the wallet behind the key is funded). Serialised via a
/// collection so the shared signer's UTxOs are not raced. Mirrors the Solana/EVM smoke suites.
/// Each scenario awaits on-chain confirmation, so a full run takes a few minutes on preprod.
/// </summary>
[Collection("CardanoPreprod")]
public class CardanoPreprodSmokeTests
{
    [SkippableFact]
    public async Task AnchorRoot_RegistersFreshDid()
    {
        using var anchor = SkipOrBuild();
        var did = NewRandomDid();
        var root = RandomBytes(32);

        var tx = await anchor.AnchorRootAsync(did, root);
        Assert.False(string.IsNullOrEmpty(tx.TxId));

        var state = await anchor.GetAnchorAsync(did);
        Assert.NotNull(state);
        Assert.Equal(root, state!.AttestationRoot);
        Assert.Equal(0UL, state.RevocationEpoch);
    }

    [SkippableFact]
    public async Task AnchorRoot_TwiceOnSameDid_UpdatesRoot()
    {
        using var anchor = SkipOrBuild();
        var did = NewRandomDid();

        await anchor.AnchorRootAsync(did, RandomBytes(32));
        var newRoot = RandomBytes(32);
        await anchor.AnchorRootAsync(did, newRoot);

        var state = await anchor.GetAnchorAsync(did);
        Assert.NotNull(state);
        Assert.Equal(newRoot, state!.AttestationRoot);
        Assert.Equal(0UL, state.RevocationEpoch);
    }

    [SkippableFact]
    public async Task BumpRevocation_IncrementsEpoch()
    {
        using var anchor = SkipOrBuild();
        var did = NewRandomDid();

        await anchor.AnchorRootAsync(did, RandomBytes(32));
        await anchor.BumpRevocationAsync(did, RevocationReason.KeyRotation);

        var state = await anchor.GetAnchorAsync(did);
        Assert.NotNull(state);
        Assert.Equal(1UL, state!.RevocationEpoch);
    }

    [SkippableFact]
    public async Task GetAnchor_UnknownDid_ReturnsNull()
    {
        using var anchor = SkipOrBuild();
        Assert.Null(await anchor.GetAnchorAsync(NewRandomDid()));
    }

    [SkippableFact]
    public async Task IsRevokedSince_TracksEpoch()
    {
        using var anchor = SkipOrBuild();
        var did = NewRandomDid();

        await anchor.AnchorRootAsync(did, RandomBytes(32));
        Assert.False(await anchor.IsRevokedSinceAsync(did, 0));

        await anchor.BumpRevocationAsync(did, RevocationReason.Compromise);
        Assert.True(await anchor.IsRevokedSinceAsync(did, 0));
    }

    private static CardanoChainAnchor SkipOrBuild()
    {
        Skip.IfNot(CardanoPreprodConfig.TryLoad(out var config, out var reason), reason);
        return new CardanoChainAnchor(new CardanoAnchorOptions
        {
            Network = config!.Network,
            BlockfrostProjectId = config.BlockfrostProjectId,
            SigningKey = config.SigningKey,
            AnchorMode = config.AnchorMode,
        });
    }

    private static DidId NewRandomDid()
    {
        Span<byte> bytes = stackalloc byte[16];
        RandomNumberGenerator.Fill(bytes);
        return new DidId($"did:tessera:cardano-smoke-{Convert.ToHexString(bytes).ToLowerInvariant()}");
    }

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }
}
