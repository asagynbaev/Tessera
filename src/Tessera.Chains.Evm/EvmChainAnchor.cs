using System.Numerics;
using Nethereum.Contracts;
using Nethereum.Contracts.ContractHandlers;
using Nethereum.Hex.HexTypes;
using Nethereum.Util;
using Nethereum.Web3;
using Nethereum.Web3.Accounts;
using Tessera.Chains.Evm.Internal;
using Tessera.Core;

namespace Tessera.Chains.Evm;

/// <summary>
/// Generic EVM implementation of <see cref="IChainAnchor"/>. Drives the
/// <c>chains/evm</c> <c>IdentityRegistry</c> contract via Nethereum on any EVM network —
/// chainId and RPC are pure configuration, so the same adapter serves BNB Chain, Ethereum,
/// Polygon, or a local devnet without code changes.
/// </summary>
/// <remarks>
/// <para>
/// Owner semantics mirror the Solana adapter: the account behind <see cref="EvmChainAnchorOptions.PrivateKey"/>
/// becomes the <c>owner</c> of any DID anchor it registers, and the contract enforces
/// <c>msg.sender == owner</c> on every subsequent <see cref="AnchorRootAsync"/> / <see cref="BumpRevocationAsync"/>.
/// </para>
/// <para>
/// <see cref="AnchorRootAsync"/> auto-detects whether to call <c>registerDid</c> (no anchor yet)
/// or <c>updateRoot</c> (anchor exists), and tolerates the register/register race.
/// </para>
/// <para>
/// Read calls are retried per <see cref="EvmRetryPolicy"/>. Write transactions are sent
/// <em>once</em> by design: retrying a broadcast whose receipt-wait timed out could double-submit
/// the transaction under a new nonce, so writes are never auto-retried.
/// </para>
/// </remarks>
public sealed class EvmChainAnchor : IChainAnchor
{
    private readonly IWeb3 _web3;
    private readonly string _contractAddress;
    private readonly string _chainTag;
    private readonly BigInteger? _gasLimit;
    private readonly EvmRetryPolicy _retry;
    private readonly TimeProvider _clock;
    // Used to prove control of the DID when registering (see AnchorRootAsync). The signing key is the
    // controller; the numeric chainId is bound into the registration signature for replay protection.
    private readonly string? _signingKey;
    private readonly BigInteger _numericChainId;

    public EvmChainAnchor(EvmChainAnchorOptions options, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.RpcUrl)) throw new ArgumentException("RpcUrl required.", nameof(options));
        if (string.IsNullOrWhiteSpace(options.ContractAddress)) throw new ArgumentException("ContractAddress required.", nameof(options));
        if (!AddressUtil.Current.IsValidEthereumAddressHexFormat(options.ContractAddress))
            throw new ArgumentException($"ContractAddress is not a valid EVM address: '{options.ContractAddress}'.", nameof(options));
        if (string.IsNullOrWhiteSpace(options.PrivateKey)) throw new ArgumentException("PrivateKey required.", nameof(options));
        if (options.ChainId <= 0) throw new ArgumentException("ChainId must be positive.", nameof(options));

        var account = new Account(options.PrivateKey, options.ChainId);
        _web3 = new Web3(account, options.RpcUrl);
        _contractAddress = options.ContractAddress;
        _chainTag = options.EffectiveChainTag;
        _gasLimit = options.GasLimit;
        _retry = options.Retry;
        _clock = clock ?? TimeProvider.System;
        _signingKey = options.PrivateKey;
        _numericChainId = options.ChainId;
    }

    /// <summary>
    /// Advanced/testing constructor: inject a pre-built <see cref="IWeb3"/> (custom account,
    /// signer, HTTP client, or test double). The caller is responsible for the signing account.
    /// </summary>
    /// <param name="signingKey">
    /// Optional controller private key used to sign DID registrations. Required only if this instance
    /// will call <see cref="AnchorRootAsync"/> for a not-yet-registered DID (the <c>registerDid</c> path).
    /// </param>
    /// <param name="numericChainId">EIP-155 chain id bound into the registration signature.</param>
    internal EvmChainAnchor(
        IWeb3 web3,
        string contractAddress,
        string chainTag,
        BigInteger? gasLimit = null,
        EvmRetryPolicy? retry = null,
        TimeProvider? clock = null,
        string? signingKey = null,
        BigInteger numericChainId = default)
    {
        _web3 = web3 ?? throw new ArgumentNullException(nameof(web3));
        ArgumentNullException.ThrowIfNull(contractAddress);
        if (!AddressUtil.Current.IsValidEthereumAddressHexFormat(contractAddress))
            throw new ArgumentException($"contractAddress is not a valid EVM address: '{contractAddress}'.", nameof(contractAddress));
        _contractAddress = contractAddress;
        _chainTag = chainTag ?? throw new ArgumentNullException(nameof(chainTag));
        _gasLimit = gasLimit;
        _retry = retry ?? EvmRetryPolicy.Default;
        _clock = clock ?? TimeProvider.System;
        _signingKey = signingKey;
        _numericChainId = numericChainId;
    }

    public string ChainId => _chainTag;

    public async Task<AnchorTxResult> AnchorRootAsync(DidId did, byte[] attestationRoot, CancellationToken ct = default)
    {
        if (attestationRoot is null || attestationRoot.Length != 32)
            throw new ArgumentException("attestationRoot must be exactly 32 bytes.", nameof(attestationRoot));

        var didHash = DidHash.Compute(did);
        var handler = _web3.Eth.GetContractHandler(_contractAddress);

        var existing = await QueryAnchorAsync(handler, didHash, ct).ConfigureAwait(false);
        if (existing is { Exists: true })
            return await SendAsync(handler, new UpdateRootFunction { DidHash = didHash, NewRoot = attestationRoot }, ct).ConfigureAwait(false);

        // No anchor yet → register. The register is itself single-shot. If it throws, re-read:
        //  - anchor now exists (a concurrent writer won the race, OR our own register actually
        //    landed but the receipt wait timed out): fall back to updateRoot, which writes the
        //    same root idempotently and reverts NotOwner if a different writer owns the DID.
        //  - anchor still absent (the register genuinely failed / never landed): rethrow the
        //    ORIGINAL error so the real failure cause surfaces, not a derived one.
        // This is recovery gated on observed on-chain state, not a blind retry of the write.
        var register = BuildRegisterDid(didHash, attestationRoot);
        try
        {
            return await SendAsync(handler, register, ct).ConfigureAwait(false);
        }
        catch (Exception registerError) when (!ct.IsCancellationRequested)
        {
            var now = await QueryAnchorAsync(handler, didHash, ct).ConfigureAwait(false);
            if (now is { Exists: true })
                return await SendAsync(handler, new UpdateRootFunction { DidHash = didHash, NewRoot = attestationRoot }, ct).ConfigureAwait(false);
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(registerError).Throw();
            throw; // unreachable; keeps the compiler happy
        }
    }

    public async Task<AnchorState?> GetAnchorAsync(DidId did, CancellationToken ct = default)
    {
        var didHash = DidHash.Compute(did);
        var handler = _web3.Eth.GetContractHandler(_contractAddress);
        var dto = await QueryAnchorAsync(handler, didHash, ct).ConfigureAwait(false);
        return ToAnchorState(did, dto);
    }

    public async Task<AnchorTxResult> BumpRevocationAsync(DidId did, RevocationReason reason, CancellationToken ct = default)
    {
        var didHash = DidHash.Compute(did);
        var handler = _web3.Eth.GetContractHandler(_contractAddress);
        return await SendAsync(handler, new BumpRevocationFunction { DidHash = didHash, Reason = (byte)reason }, ct).ConfigureAwait(false);
    }

    public async Task<bool> IsRevokedSinceAsync(DidId did, ulong asOfEpoch, CancellationToken ct = default)
    {
        var state = await GetAnchorAsync(did, ct).ConfigureAwait(false);
        return state is not null && IsRevokedSince(state.RevocationEpoch, asOfEpoch);
    }

    /// <summary>
    /// Register or refresh an issuer in the on-chain registry. Not part of <see cref="IChainAnchor"/>
    /// (parity with the contract's <c>registerIssuer</c>); the caller must be the contract authority.
    /// </summary>
    /// <param name="issuerDid">Issuer DID; hashed to <c>issuerDidHash</c>.</param>
    /// <param name="signingKey">Issuer's 32-byte Ed25519 verification key.</param>
    /// <param name="schemaUri">Schema URI (≤ 200 bytes).</param>
    public async Task<AnchorTxResult> RegisterIssuerAsync(DidId issuerDid, byte[] signingKey, string schemaUri, CancellationToken ct = default)
    {
        if (signingKey is null || signingKey.Length != 32)
            throw new ArgumentException("signingKey must be a 32-byte Ed25519 public key.", nameof(signingKey));
        ArgumentException.ThrowIfNullOrEmpty(schemaUri);

        var issuerHash = DidHash.Compute(issuerDid);
        var handler = _web3.Eth.GetContractHandler(_contractAddress);
        return await SendAsync(
            handler,
            new RegisterIssuerFunction { IssuerDidHash = issuerHash, SigningKey = signingKey, SchemaUri = schemaUri },
            ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Mark an issuer inactive in the on-chain registry. Not part of <see cref="IChainAnchor"/>;
    /// the caller must be the contract authority. Off-chain verification of an inactive issuer's
    /// attestations fails. (The Solana program will gain an equivalent instruction in a later revision.)
    /// </summary>
    public async Task<AnchorTxResult> DeactivateIssuerAsync(DidId issuerDid, CancellationToken ct = default)
    {
        var issuerHash = DidHash.Compute(issuerDid);
        var handler = _web3.Eth.GetContractHandler(_contractAddress);
        return await SendAsync(handler, new DeactivateIssuerFunction { IssuerDidHash = issuerHash }, ct).ConfigureAwait(false);
    }

    // ── internals ────────────────────────────────────────────────────────────

    /// <summary>
    /// Build the <c>registerDid</c> call, signing the registration with the controller key so that —
    /// although <c>didHash</c> is public — only the DID controller can create the anchor (no squatting).
    /// The controller becomes the on-chain owner; updateRoot / bumpRevocation remain owner-gated.
    /// </summary>
    private RegisterDidFunction BuildRegisterDid(byte[] didHash, byte[] attestationRoot)
    {
        if (string.IsNullOrWhiteSpace(_signingKey))
            throw new InvalidOperationException(
                "Registering a new DID anchor requires a controller signing key, but this EvmChainAnchor " +
                "was constructed without one (the advanced IWeb3 constructor). Supply 'signingKey' to register DIDs.");

        var controller = EvmRegistrationSigner.DeriveController(_signingKey);
        var signature = EvmRegistrationSigner.Sign(_signingKey, didHash, attestationRoot, _numericChainId, _contractAddress);
        return new RegisterDidFunction
        {
            DidHash = didHash,
            AttestationRoot = attestationRoot,
            Controller = controller,
            Signature = signature,
        };
    }

    private async Task<GetAnchorOutputDTO?> QueryAnchorAsync(ContractHandler handler, byte[] didHash, CancellationToken ct)
        => await EvmRetry.RunAsync(
            _retry,
            () => handler.QueryDeserializingToObjectAsync<GetAnchorFunction, GetAnchorOutputDTO>(new GetAnchorFunction { DidHash = didHash }),
            ct).ConfigureAwait(false);

    private async Task<AnchorTxResult> SendAsync<TFunc>(ContractHandler handler, TFunc fn, CancellationToken ct)
        where TFunc : FunctionMessage, new()
    {
        if (_gasLimit is { } g) fn.Gas = new HexBigInteger(g);
        ct.ThrowIfCancellationRequested();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var receipt = await handler.SendRequestAndWaitForReceiptAsync(fn, cts).ConfigureAwait(false);

        // Nethereum's wait-for-receipt does NOT throw when a transaction is mined but reverted:
        // the receipt simply carries status 0. Assert success (treat a null status as failure)
        // so a reverted write never silently returns a "success" result to the caller.
        EvmTx.EnsureReceiptSucceeded(receipt.Status, receipt.TransactionHash);

        ulong? block = receipt.BlockNumber is { } bn ? (ulong)bn.Value : null;
        return new AnchorTxResult(receipt.TransactionHash, block, _clock.GetUtcNow());
    }

    /// <summary>Map a contract read to the chain-agnostic <see cref="AnchorState"/>. Null when the DID has no anchor.</summary>
    internal static AnchorState? ToAnchorState(DidId did, GetAnchorOutputDTO? dto)
    {
        if (dto is null || !dto.Exists) return null;
        return new AnchorState
        {
            Did = did,
            AttestationRoot = dto.AttestationRoot ?? Array.Empty<byte>(),
            RevocationEpoch = dto.RevocationEpoch,
            UpdatedAt = DateTimeOffset.FromUnixTimeSeconds((long)dto.UpdatedAt),
        };
    }

    /// <summary>A presentation anchored at <paramref name="asOfEpoch"/> is stale once the chain epoch moves past it.</summary>
    internal static bool IsRevokedSince(ulong currentEpoch, ulong asOfEpoch) => currentEpoch > asOfEpoch;
}
