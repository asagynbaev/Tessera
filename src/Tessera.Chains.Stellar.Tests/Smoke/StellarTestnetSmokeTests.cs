using System.Security.Cryptography;
using Tessera.Chains;
using Tessera.Core;

namespace Tessera.Chains.Stellar.Tests.Smoke;

/// <summary>
/// Live-network smoke tests against a deployed <c>attestation-anchor</c> Soroban contract. This is
/// the Stellar "integration test on testnet" Definition of Done — it exercises the real adapter
/// over a real chain, mirroring the Solana devnet / EVM testnet / Cardano preprod suites. Skipped
/// unless <see cref="StellarTestnetConfig"/> resolves all env vars (see
/// <c>chains/stellar/DEPLOYMENT.md</c>).
/// </summary>
/// <remarks>
/// Each test uses a fresh random DID so the on-chain record is unique per run. Serialised via a
/// collection so the shared signer's account sequence number is not raced across concurrent writes.
/// The adapter awaits on-chain confirmation per write, so a full run takes ~1 minute on testnet.
/// </remarks>
[Collection("StellarTestnet")]
public class StellarTestnetSmokeTests
{
    [SkippableFact]
    public async Task AnchorRoot_RegistersFreshDid()
    {
        using var anchor = SkipOrBuild();
        var did = NewRandomDid();
        var root = RandomBytes(32);

        var tx = await anchor.AnchorRootAsync(did, root);
        Assert.False(string.IsNullOrEmpty(tx.TxId), "expected non-empty tx hash");

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

        await anchor.AnchorRootAsync(did, RandomBytes(32));   // register
        var newRoot = RandomBytes(32);
        await anchor.AnchorRootAsync(did, newRoot);           // update

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

        await anchor.BumpRevocationAsync(did, RevocationReason.HolderRequested);
        Assert.Equal(1UL, (await anchor.GetAnchorAsync(did))!.RevocationEpoch);

        await anchor.BumpRevocationAsync(did, RevocationReason.KeyRotation);
        Assert.Equal(2UL, (await anchor.GetAnchorAsync(did))!.RevocationEpoch);
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

        await anchor.BumpRevocationAsync(did, RevocationReason.HolderRequested);
        Assert.True(await anchor.IsRevokedSinceAsync(did, 0));
        Assert.False(await anchor.IsRevokedSinceAsync(did, 1));  // current epoch, not stale
    }

    // ── helpers ──────────────────────────────────────────────────────────

    private static StellarChainAnchor SkipOrBuild()
    {
        Skip.IfNot(StellarTestnetConfig.TryLoad(out var config, out var reason), reason);
        return new StellarChainAnchor(new StellarAnchorOptions
        {
            SorobanRpcUrl = config!.SorobanRpcUrl,
            ContractId = config.ContractId,
            SigningKeySeed = config.SigningKeySeed,
            NetworkPassphrase = config.NetworkPassphrase,
        });
    }

    private static DidId NewRandomDid()
    {
        Span<byte> entropy = stackalloc byte[16];
        RandomNumberGenerator.Fill(entropy);
        return new DidId("did:tessera:stellar-smoke-" + Convert.ToHexString(entropy).ToLowerInvariant());
    }

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }
}
