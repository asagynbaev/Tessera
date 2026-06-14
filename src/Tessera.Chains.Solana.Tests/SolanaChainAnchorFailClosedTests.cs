using System.Security.Cryptography;
using Moq;
using Solnet.Rpc;
using Solnet.Rpc.Core.Http;
using Solnet.Rpc.Messages;
using Solnet.Rpc.Models;
using Solnet.Rpc.Types;
using Solnet.Wallet;
using Tessera.Chains.Solana.Accounts;
using Tessera.Chains.Solana.Internal;
using Tessera.Core;

namespace Tessera.Chains.Solana.Tests;

/// <summary>
/// Unit tests for the fail-closed reading behaviour of <see cref="SolanaChainAnchor"/>
/// (C# adapter finding "C# adapter fail-open"):
/// <list type="bullet">
///   <item>RPC/transport errors must THROW, never silently report "not revoked".</item>
///   <item>A genuine "no account" (RPC success, <c>value: null</c>) returns null / not revoked.</item>
///   <item>Accounts not owned by the identity-registry program are rejected (substitution).</item>
///   <item>Accounts with a wrong discriminator are rejected before being decoded.</item>
/// </list>
/// The RPC client is mocked so no network is touched.
/// </summary>
public class SolanaChainAnchorFailClosedTests
{
    // Valid base58 strings so the PublicKey ctor accepts them at construction time.
    private static readonly PublicKey ProgramId = new("11111111111111111111111111111114");
    private static readonly PublicKey OtherProgramId = new("11111111111111111111111111111112");
    private static readonly DidId Did = new("did:tessera:test-subject");

    private static SolanaChainAnchor BuildAnchor(IRpcClient rpc)
    {
        // Throwaway keypair — these tests only exercise reads (GetAccountInfo) and never submit,
        // so the payer only has to be a structurally valid Account.
        var payer = new Account();
        return new SolanaChainAnchor(rpc, ProgramId, payer, Commitment.Confirmed);
    }

    private static Mock<IRpcClient> NewRpcMock() => new(MockBehavior.Strict);

    private static void SetupGetAccountInfo(
        Mock<IRpcClient> rpc,
        RequestResult<ResponseValue<AccountInfo>> response)
    {
        rpc.Setup(c => c.GetAccountInfoAsync(
                It.IsAny<string>(),
                It.IsAny<Commitment>(),
                It.IsAny<BinaryEncoding>()))
            .ReturnsAsync(response);
    }

    private static RequestResult<ResponseValue<AccountInfo>> RpcError(string reason)
        => new()
        {
            WasHttpRequestSuccessful = false,
            WasRequestSuccessfullyHandled = false,
            Reason = reason,
            // Result intentionally left at its default (null) — an unsuccessful RPC carries no payload.
        };

    private static RequestResult<ResponseValue<AccountInfo>> RpcSuccess(AccountInfo? value)
        => new()
        {
            WasHttpRequestSuccessful = true,
            WasRequestSuccessfullyHandled = true,
            Result = new ResponseValue<AccountInfo> { Value = value! },
        };

    private static AccountInfo Account(string owner, byte[] rawData)
        => new()
        {
            Owner = owner,
            Lamports = 1_000_000,
            Executable = false,
            RentEpoch = 0,
            Data = new List<string> { Convert.ToBase64String(rawData), "base64" },
        };

    private static byte[] ValidDidAnchorBytes()
    {
        byte[] Filled(byte seed, int n)
        {
            var b = new byte[n];
            for (int i = 0; i < n; i++) b[i] = (byte)(seed + i);
            return b;
        }

        return Concat(
            IdentityRegistryDiscriminators.DidAnchorAccount,
            new AnchorBorshWriter()
                .WriteU8(1)
                .WriteFixedBytes(Filled(10, 32), 32)  // did_hash
                .WriteFixedBytes(Filled(50, 32), 32)  // owner
                .WriteFixedBytes(Filled(100, 32), 32) // attestation_root
                .WriteU64(7)                           // revocation_epoch
                .WriteI64(1_700_000_000)               // created_at
                .WriteI64(1_700_000_500)               // updated_at
                .ToArray());
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var c = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, c, 0, a.Length);
        Buffer.BlockCopy(b, 0, c, a.Length, b.Length);
        return c;
    }

    // ── GetAnchorAsync ────────────────────────────────────────────────────

    [Fact]
    public async Task GetAnchor_RpcError_Throws_DoesNotReturnNull()
    {
        var rpc = NewRpcMock();
        SetupGetAccountInfo(rpc, RpcError("502 Bad Gateway"));
        var anchor = BuildAnchor(rpc.Object);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => anchor.GetAnchorAsync(Did));
        Assert.Contains("fail-closed", ex.Message);
    }

    [Fact]
    public async Task GetAnchor_NoAccount_ReturnsNull()
    {
        var rpc = NewRpcMock();
        SetupGetAccountInfo(rpc, RpcSuccess(value: null)); // Solana returns value: null for missing account
        var anchor = BuildAnchor(rpc.Object);

        var state = await anchor.GetAnchorAsync(Did);
        Assert.Null(state);
    }

    [Fact]
    public async Task GetAnchor_ValidAccountOwnedByProgram_Decodes()
    {
        var rpc = NewRpcMock();
        SetupGetAccountInfo(rpc, RpcSuccess(Account(ProgramId.Key, ValidDidAnchorBytes())));
        var anchor = BuildAnchor(rpc.Object);

        var state = await anchor.GetAnchorAsync(Did);
        Assert.NotNull(state);
        Assert.Equal(7UL, state!.RevocationEpoch);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_700_000_500), state.UpdatedAt);
    }

    [Fact]
    public async Task GetAnchor_AccountOwnedByOtherProgram_Throws()
    {
        var rpc = NewRpcMock();
        // Correct discriminator + data, but owned by a different program → substitution attempt.
        SetupGetAccountInfo(rpc, RpcSuccess(Account(OtherProgramId.Key, ValidDidAnchorBytes())));
        var anchor = BuildAnchor(rpc.Object);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => anchor.GetAnchorAsync(Did));
        Assert.Contains("substitution", ex.Message);
    }

    [Fact]
    public async Task GetAnchor_WrongDiscriminator_Throws()
    {
        var rpc = NewRpcMock();
        // Owned by our program but the account bytes carry the Issuer discriminator, not DidAnchor.
        var wrongTypeBytes = Concat(
            IdentityRegistryDiscriminators.IssuerAccount,
            new byte[129 - 8]); // pad to DidAnchor's expected length so the disc check is what fails
        SetupGetAccountInfo(rpc, RpcSuccess(Account(ProgramId.Key, wrongTypeBytes)));
        var anchor = BuildAnchor(rpc.Object);

        await Assert.ThrowsAsync<ArgumentException>(() => anchor.GetAnchorAsync(Did));
    }

    [Fact]
    public async Task GetAnchor_AccountExistsButNoData_Throws()
    {
        var rpc = NewRpcMock();
        var emptyData = Account(ProgramId.Key, Array.Empty<byte>());
        emptyData.Data = new List<string>(); // exists, owned by program, but zero data entries
        SetupGetAccountInfo(rpc, RpcSuccess(emptyData));
        var anchor = BuildAnchor(rpc.Object);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => anchor.GetAnchorAsync(Did));
        Assert.Contains("no data", ex.Message);
    }

    // ── IsRevokedSinceAsync (fail closed) ─────────────────────────────────

    [Fact]
    public async Task IsRevokedSince_RpcError_Throws_NotFalse()
    {
        var rpc = NewRpcMock();
        SetupGetAccountInfo(rpc, RpcError("connection reset"));
        var anchor = BuildAnchor(rpc.Object);

        // The previous fail-open behaviour returned false here. It must now throw.
        await Assert.ThrowsAsync<InvalidOperationException>(() => anchor.IsRevokedSinceAsync(Did, 0));
    }

    [Fact]
    public async Task IsRevokedSince_NoAccount_ReturnsFalse()
    {
        var rpc = NewRpcMock();
        SetupGetAccountInfo(rpc, RpcSuccess(value: null));
        var anchor = BuildAnchor(rpc.Object);

        Assert.False(await anchor.IsRevokedSinceAsync(Did, 0));
    }

    [Fact]
    public async Task IsRevokedSince_EpochAdvanced_ReturnsTrue()
    {
        var rpc = NewRpcMock();
        SetupGetAccountInfo(rpc, RpcSuccess(Account(ProgramId.Key, ValidDidAnchorBytes()))); // epoch = 7
        var anchor = BuildAnchor(rpc.Object);

        Assert.True(await anchor.IsRevokedSinceAsync(Did, 6));
        Assert.False(await anchor.IsRevokedSinceAsync(Did, 7));
    }

    [Fact]
    public async Task IsRevokedSince_SubstitutedAccount_Throws_NotFalse()
    {
        var rpc = NewRpcMock();
        SetupGetAccountInfo(rpc, RpcSuccess(Account(OtherProgramId.Key, ValidDidAnchorBytes())));
        var anchor = BuildAnchor(rpc.Object);

        await Assert.ThrowsAsync<InvalidOperationException>(() => anchor.IsRevokedSinceAsync(Did, 0));
    }
}
