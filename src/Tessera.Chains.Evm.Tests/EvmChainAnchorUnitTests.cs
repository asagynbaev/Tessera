using Nethereum.Util;
using Tessera.Chains;
using Tessera.Chains.Evm.Internal;
using Tessera.Core;

namespace Tessera.Chains.Evm.Tests;

public class EvmChainAnchorUnitTests
{
    // A well-formed throwaway secp256k1 private key (32 bytes). Never used to sign anything real.
    private const string DummyKey = "0x4646464646464646464646464646464646464646464646464646464646464646";
    private const string DummyContract = "0x0000000000000000000000000000000000000001";

    private static EvmChainAnchorOptions Opts(long chainId = 97, string? tag = null) => new()
    {
        RpcUrl = "http://localhost:8545",
        ChainId = chainId,
        ContractAddress = DummyContract,
        PrivateKey = DummyKey,
        ChainTag = tag,
    };

    [Fact]
    public void ChainId_DefaultsTo_EvmColonChainId()
        => Assert.Equal("evm:97", new EvmChainAnchor(Opts(97)).ChainId);

    [Fact]
    public void ChainTag_Override_Wins()
        => Assert.Equal("bsc-testnet", new EvmChainAnchor(Opts(97, "bsc-testnet")).ChainId);

    [Fact]
    public void EffectiveChainTag_OnOptions_Matches()
    {
        Assert.Equal("evm:56", Opts(56).EffectiveChainTag);
        Assert.Equal("custom", (Opts(56, "custom")).EffectiveChainTag);
    }

    [Theory]
    [InlineData("", DummyContract, DummyKey, 97)]   // empty rpc
    [InlineData("http://x", "", DummyKey, 97)]       // empty contract
    [InlineData("http://x", DummyContract, "", 97)]  // empty key
    [InlineData("http://x", DummyContract, DummyKey, 0)]   // non-positive chainId
    [InlineData("http://x", DummyContract, DummyKey, -1)]
    public void Ctor_Validates_RequiredFields(string rpc, string contract, string key, long chainId)
    {
        var options = new EvmChainAnchorOptions { RpcUrl = rpc, ChainId = chainId, ContractAddress = contract, PrivateKey = key };
        Assert.Throws<ArgumentException>(() => new EvmChainAnchor(options));
    }

    [Fact]
    public void ToAnchorState_Null_WhenMissingOrNotExists()
    {
        var did = new DidId("did:tessera:alice");
        Assert.Null(EvmChainAnchor.ToAnchorState(did, null));
        Assert.Null(EvmChainAnchor.ToAnchorState(did, new GetAnchorOutputDTO { Exists = false }));
    }

    [Fact]
    public void ToAnchorState_Maps_AllFields()
    {
        var did = new DidId("did:tessera:alice");
        var root = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var dto = new GetAnchorOutputDTO
        {
            Exists = true,
            Owner = "0x00000000000000000000000000000000000000aa",
            AttestationRoot = root,
            RevocationEpoch = 7,
            CreatedAt = 1_600_000_000,
            UpdatedAt = 1_700_000_000,
        };

        var state = EvmChainAnchor.ToAnchorState(did, dto);

        Assert.NotNull(state);
        Assert.Equal(did, state!.Did);
        Assert.Equal(root, state.AttestationRoot);
        Assert.Equal(7ul, state.RevocationEpoch);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000), state.UpdatedAt);
        // H-2: owner surfaced as the canonical EIP-55 checksum. Pinned with an EXACT (Ordinal) match,
        // because the verifier's owner-check compares case-sensitively — a caller must pin the owner in
        // exactly this checksummed form, so a regression that emitted a lowercase address must fail here.
        Assert.NotNull(state.Owner);
        Assert.Equal(AddressUtil.Current.ConvertToChecksumAddress("0x00000000000000000000000000000000000000aa"), state.Owner);
    }

    [Theory]
    [InlineData(0, 0, false)]
    [InlineData(1, 0, true)]
    [InlineData(5, 5, false)]
    [InlineData(6, 5, true)]
    [InlineData(5, 6, false)]
    public void IsRevokedSince_StaleOnce_EpochMovesPast(ulong current, ulong asOf, bool expected)
        => Assert.Equal(expected, EvmChainAnchor.IsRevokedSince(current, asOf));

    [Fact]
    public void Ctor_Rejects_MalformedContractAddress()
    {
        var options = new EvmChainAnchorOptions { RpcUrl = "http://x", ChainId = 97, ContractAddress = "0x123", PrivateKey = DummyKey };
        Assert.Throws<ArgumentException>(() => new EvmChainAnchor(options));
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(0)]
    public async Task RegisterIssuerAsync_Rejects_BadSigningKeyLength(int len)
    {
        var anchor = new EvmChainAnchor(Opts());
        await Assert.ThrowsAsync<ArgumentException>(() =>
            anchor.RegisterIssuerAsync(new DidId("did:tessera:issuer"), new byte[len], "https://schemas.tessera/kyc/v1"));
    }

    [Fact]
    public async Task RegisterIssuerAsync_Rejects_EmptySchemaUri()
    {
        var anchor = new EvmChainAnchor(Opts());
        await Assert.ThrowsAsync<ArgumentException>(() =>
            anchor.RegisterIssuerAsync(new DidId("did:tessera:issuer"), new byte[32], ""));
    }
}
