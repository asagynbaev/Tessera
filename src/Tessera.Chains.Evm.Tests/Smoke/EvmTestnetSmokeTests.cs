using System.Security.Cryptography;
using Tessera.Chains;
using Tessera.Core;

namespace Tessera.Chains.Evm.Tests.Smoke;

/// <summary>
/// Live-network smoke tests against a deployed <c>IdentityRegistry</c> contract. This is the
/// A1 "integration test on EVM testnet" Definition of Done — it exercises the real adapter
/// over a real chain. Skipped unless <see cref="EvmTestnetConfig"/> resolves all env vars
/// (see <c>chains/evm/README.md</c>), exactly mirroring the Solana devnet smoke tests.
/// </summary>
/// <remarks>
/// Each test uses a fresh random DID so the on-chain record is unique per run — no collision
/// across re-runs, no cleanup. Marked a single collection so xunit runs them serially to avoid
/// nonce races on the shared signing account and RPC rate limiting.
/// </remarks>
[Collection("EvmTestnet")]
public class EvmTestnetSmokeTests
{
    [SkippableFact]
    public async Task AnchorRoot_RegistersFreshDid()
    {
        var anchor = SkipOrBuild();
        var did = NewRandomDid();
        var root = RandomNumberGenerator.GetBytes(32);

        var result = await anchor.AnchorRootAsync(did, root);
        Assert.False(string.IsNullOrEmpty(result.TxId), "expected non-empty tx hash");

        var state = await anchor.GetAnchorAsync(did);
        Assert.NotNull(state);
        Assert.Equal(root, state!.AttestationRoot);
        Assert.Equal(0UL, state.RevocationEpoch);
    }

    [SkippableFact]
    public async Task AnchorRoot_TwiceOnSameDid_UpdatesRoot()
    {
        var anchor = SkipOrBuild();
        var did = NewRandomDid();
        var firstRoot = RandomNumberGenerator.GetBytes(32);
        var secondRoot = RandomNumberGenerator.GetBytes(32);

        await anchor.AnchorRootAsync(did, firstRoot);   // registerDid
        await anchor.AnchorRootAsync(did, secondRoot);  // auto updateRoot

        var state = await anchor.GetAnchorAsync(did);
        Assert.NotNull(state);
        Assert.Equal(secondRoot, state!.AttestationRoot);
        Assert.Equal(0UL, state.RevocationEpoch);
    }

    [SkippableFact]
    public async Task BumpRevocation_IncrementsEpoch()
    {
        var anchor = SkipOrBuild();
        var did = NewRandomDid();
        await anchor.AnchorRootAsync(did, RandomNumberGenerator.GetBytes(32));

        await anchor.BumpRevocationAsync(did, RevocationReason.HolderRequested);
        Assert.Equal(1UL, (await anchor.GetAnchorAsync(did))!.RevocationEpoch);

        await anchor.BumpRevocationAsync(did, RevocationReason.KeyRotation);
        Assert.Equal(2UL, (await anchor.GetAnchorAsync(did))!.RevocationEpoch);
    }

    [SkippableFact]
    public async Task GetAnchor_UnknownDid_ReturnsNull()
    {
        var anchor = SkipOrBuild();
        Assert.Null(await anchor.GetAnchorAsync(NewRandomDid()));
    }

    [SkippableFact]
    public async Task IsRevokedSince_TracksEpoch()
    {
        var anchor = SkipOrBuild();
        var did = NewRandomDid();
        await anchor.AnchorRootAsync(did, RandomNumberGenerator.GetBytes(32));

        Assert.False(await anchor.IsRevokedSinceAsync(did, 0));

        await anchor.BumpRevocationAsync(did, RevocationReason.HolderRequested);
        Assert.True(await anchor.IsRevokedSinceAsync(did, 0));
        Assert.False(await anchor.IsRevokedSinceAsync(did, 1));  // current epoch, not stale
    }

    // ── helpers ──────────────────────────────────────────────────────────

    private static EvmChainAnchor SkipOrBuild()
    {
        Skip.IfNot(EvmTestnetConfig.TryLoad(out var config, out var reason), reason);
        return new EvmChainAnchor(new EvmChainAnchorOptions
        {
            RpcUrl = config!.RpcUrl,
            ChainId = config.ChainId,
            ContractAddress = config.ContractAddress,
            PrivateKey = config.PrivateKey,
        });
    }

    private static DidId NewRandomDid()
    {
        Span<byte> entropy = stackalloc byte[16];
        RandomNumberGenerator.Fill(entropy);
        return new DidId("did:tessera:evm-smoke-" + Convert.ToHexString(entropy));
    }
}
