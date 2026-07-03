using System.Security.Cryptography;
using System.Text;
using Solnet.Rpc;
using Solnet.Rpc.Builders;
using Solnet.Rpc.Models;
using Solnet.Rpc.Types;
using Solnet.Wallet;
using Tessera.Chains.Solana.Accounts;
using Tessera.Chains.Solana.Instructions;
using Tessera.Chains.Solana.Internal;
using Tessera.Core;

namespace Tessera.Chains.Solana;

/// <summary>
/// Solana implementation of <see cref="IChainAnchor"/>. Drives the
/// <c>chains/solana/programs/identity-registry</c> Anchor program via Solnet RPC.
/// </summary>
/// <remarks>
/// <para>
/// Owner semantics: the <c>owner</c> field of the on-chain <c>DidAnchor</c> account is the
/// payer keypair passed to this anchor. The same keypair must sign every subsequent
/// <see cref="AnchorRootAsync"/> / <see cref="BumpRevocationAsync"/> call, which the
/// program enforces via <c>require_keys_eq!(anchor.owner, signer)</c>.
/// </para>
/// <para>
/// <see cref="AnchorRootAsync"/> auto-detects whether to call <c>register_did</c>
/// (PDA does not exist yet) or <c>update_root</c> (PDA already exists).
/// </para>
/// </remarks>
public sealed class SolanaChainAnchor : IChainAnchor
{
    private readonly IRpcClient _rpc;
    private readonly PublicKey _programId;
    private readonly Account _payer;
    private readonly Commitment _commitment;

    /// <param name="rpcUrl">Solana RPC endpoint, e.g. <c>https://api.devnet.solana.com</c>.</param>
    /// <param name="programId">Deployed identity-registry program ID, base58.</param>
    /// <param name="payerKeypair">64-byte Ed25519 keypair: 32-byte seed ‖ 32-byte public key.</param>
    /// <param name="commitment">Confirmation level for reads and submission. Default: <see cref="Commitment.Confirmed"/>.</param>
    public SolanaChainAnchor(
        string rpcUrl,
        string programId,
        byte[] payerKeypair,
        Commitment commitment = Commitment.Confirmed)
    {
        if (string.IsNullOrEmpty(rpcUrl)) throw new ArgumentException("rpcUrl required.", nameof(rpcUrl));
        if (string.IsNullOrEmpty(programId)) throw new ArgumentException("programId required.", nameof(programId));
        if (payerKeypair is null || payerKeypair.Length != 64)
            throw new ArgumentException("payerKeypair must be a 64-byte Ed25519 keypair (32-byte seed + 32-byte public key).", nameof(payerKeypair));

        _rpc = ClientFactory.GetClient(rpcUrl);
        _programId = new PublicKey(programId);
        // Solnet's Account/PrivateKey expects the FULL 64-byte Ed25519 secret key (32-byte seed ‖
        // 32-byte public key) as the private key — passing only the 32-byte seed throws
        // "invalid key length". The supplied 64-byte keypair is exactly that secret key.
        _payer = new Account(payerKeypair.ToArray(), payerKeypair[32..].ToArray());
        _commitment = commitment;
    }

    /// <summary>Testing/composition-root constructor. Lets callers inject a mock <see cref="IRpcClient"/>.</summary>
    internal SolanaChainAnchor(
        IRpcClient rpc,
        PublicKey programId,
        Account payer,
        Commitment commitment = Commitment.Confirmed)
    {
        _rpc = rpc;
        _programId = programId;
        _payer = payer;
        _commitment = commitment;
    }

    public string ChainId => "solana";

    public async Task<AnchorTxResult> AnchorRootAsync(DidId did, byte[] attestationRoot, CancellationToken ct = default)
    {
        if (attestationRoot is null || attestationRoot.Length != 32)
            throw new ArgumentException("attestationRoot must be exactly 32 bytes.", nameof(attestationRoot));

        var didHash = ComputeDidHash(did);
        var (pda, _) = IdentityRegistryPdas.DidAnchor(_programId, didHash);

        // If the PDA already exists, update; otherwise register.
        var existing = await TryLoadDidAnchorAsync(pda, ct).ConfigureAwait(false);
        var ix = existing is null
            ? IdentityRegistryInstructions.RegisterDid(_programId, pda, _payer.PublicKey, didHash, attestationRoot)
            : IdentityRegistryInstructions.UpdateRoot(_programId, pda, _payer.PublicKey, attestationRoot);

        return await SubmitAsync(ix, ct).ConfigureAwait(false);
    }

    public async Task<AnchorState?> GetAnchorAsync(DidId did, CancellationToken ct = default)
    {
        var didHash = ComputeDidHash(did);
        var (pda, _) = IdentityRegistryPdas.DidAnchor(_programId, didHash);
        var account = await TryLoadDidAnchorAsync(pda, ct).ConfigureAwait(false);
        if (account is null) return null;

        return new AnchorState
        {
            Did = did,
            AttestationRoot = account.AttestationRoot,
            RevocationEpoch = account.RevocationEpoch,
            UpdatedAt = DateTimeOffset.FromUnixTimeSeconds(account.UpdatedAt),
            // The on-chain owner is the payer pubkey the program enforces via require_keys_eq! on
            // every write. Surface it as a base58 pubkey so verifiers can compare it against the
            // DID's expected controller and detect a second anchor written by an attacker key.
            Owner = new PublicKey(account.Owner).Key,
        };
    }

    public async Task<AnchorTxResult> BumpRevocationAsync(DidId did, RevocationReason reason, CancellationToken ct = default)
    {
        var didHash = ComputeDidHash(did);
        var (pda, _) = IdentityRegistryPdas.DidAnchor(_programId, didHash);
        var ix = IdentityRegistryInstructions.BumpRevocation(_programId, pda, _payer.PublicKey, (byte)reason);
        return await SubmitAsync(ix, ct).ConfigureAwait(false);
    }

    public async Task<bool> IsRevokedSinceAsync(DidId did, ulong asOfEpoch, CancellationToken ct = default)
    {
        // Fail closed: GetAnchorAsync throws on RPC/transport errors (see TryLoadDidAnchorAsync),
        // so a transient RPC failure surfaces as an exception here rather than a false
        // "not revoked". A genuine "no anchor exists" still returns null → not revoked.
        var state = await GetAnchorAsync(did, ct).ConfigureAwait(false);
        if (state is null) return false;
        return state.RevocationEpoch > asOfEpoch;
    }

    // ── helpers ──────────────────────────────────────────────────────────

    /// <summary>
    /// Load and decode the <c>DidAnchor</c> account at <paramref name="pda"/>.
    /// </summary>
    /// <returns>
    /// The decoded account, or <c>null</c> only when the RPC call <em>succeeded</em> and the
    /// account genuinely does not exist (Solana returns <c>value: null</c>).
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown (fail closed) when the RPC/transport call fails, when the returned account is
    /// owned by a program other than the configured identity-registry program (account
    /// substitution), or when the account data is malformed / has the wrong discriminator.
    /// </exception>
    private async Task<DidAnchorAccount?> TryLoadDidAnchorAsync(PublicKey pda, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var response = await _rpc.GetAccountInfoAsync(pda.Key, _commitment).ConfigureAwait(false);

        // Distinguish a transport/RPC error from a legitimate "account does not exist".
        // On a successful call to a non-existent account, Solana returns a populated response
        // whose Result.Value is null; WasSuccessful stays true. Any unsuccessful call is an
        // RPC/transport failure and MUST fail closed (throw) rather than masquerade as "no anchor".
        if (!response.WasSuccessful)
            throw new InvalidOperationException(
                $"Solana getAccountInfo failed for {pda.Key} (fail-closed): {response.Reason}");

        var value = response.Result?.Value;

        // Genuine "no account at this PDA" — legitimately not anchored / not revoked.
        if (value is null)
            return null;

        // Account-substitution defense: the account at this PDA MUST be owned by the
        // identity-registry program. A PDA is only ever assigned to its program at init,
        // but verifying explicitly closes the door on a spoofed/cloned-RPC response.
        if (!string.Equals(value.Owner, _programId.Key, StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"Account {pda.Key} is owned by '{value.Owner}', not the identity-registry program " +
                $"'{_programId.Key}' (possible account substitution).");

        if (value.Data is null || value.Data.Count == 0)
            throw new InvalidOperationException(
                $"Account {pda.Key} exists but has no data to decode.");

        var raw = Convert.FromBase64String(value.Data[0]);

        // DidAnchorAccount.Decode validates the 8-byte Anchor discriminator and the minimum
        // length, throwing if either is wrong — so a wrong account type owned by our program
        // (or truncated data) cannot be silently mis-decoded.
        return DidAnchorAccount.Decode(raw);
    }

    private async Task<AnchorTxResult> SubmitAsync(TransactionInstruction ix, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var blockhashResp = await _rpc.GetLatestBlockHashAsync(_commitment).ConfigureAwait(false);
        if (!blockhashResp.WasSuccessful || blockhashResp.Result?.Value is null)
            throw new InvalidOperationException($"Failed to fetch latest blockhash: {blockhashResp.Reason}");

        var tx = new TransactionBuilder()
            .SetRecentBlockHash(blockhashResp.Result.Value.Blockhash)
            .SetFeePayer(_payer)
            .AddInstruction(ix)
            .Build(_payer);

        ct.ThrowIfCancellationRequested();
        var sendResp = await _rpc.SendTransactionAsync(tx, commitment: _commitment).ConfigureAwait(false);
        if (!sendResp.WasSuccessful || string.IsNullOrEmpty(sendResp.Result))
            throw new InvalidOperationException($"Solana submit failed: {sendResp.Reason}");

        // SendTransaction returns before the cluster makes the write visible to reads. Without
        // waiting for the signature to reach the configured commitment, a caller's read-back or a
        // dependent instruction races propagation — on devnet that surfaces as AccountNotInitialized
        // on the next instruction, or a null/stale read right after a write.
        await ConfirmAsync(sendResp.Result, ct).ConfigureAwait(false);

        return new AnchorTxResult(sendResp.Result, null, DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Poll until <paramref name="signature"/> reaches at least <c>confirmed</c>, or throw on
    /// timeout. Makes a submitted write durable/visible before <see cref="SubmitAsync"/> returns.
    /// </summary>
    private async Task ConfirmAsync(string signature, CancellationToken ct)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(60);
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var resp = await _rpc
                .GetSignatureStatusesAsync(new List<string> { signature }, searchTransactionHistory: true)
                .ConfigureAwait(false);
            var info = resp.WasSuccessful ? resp.Result?.Value?.FirstOrDefault() : null;
            var status = info?.ConfirmationStatus;
            if (status is "confirmed" or "finalized")
                return;
            if (DateTimeOffset.UtcNow > deadline)
                throw new InvalidOperationException($"Solana tx {signature} not confirmed within 60s (last status: {status ?? "none"}).");
            await Task.Delay(1000, ct).ConfigureAwait(false);
        }
    }

    private static byte[] ComputeDidHash(DidId did)
        => SHA256.HashData(Encoding.UTF8.GetBytes(did.Value));
}
