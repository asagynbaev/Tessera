using System.Security.Cryptography;
using StellarDotnetSdk;
using StellarDotnetSdk.Accounts;
using StellarDotnetSdk.Operations;
using StellarDotnetSdk.Soroban;
using StellarDotnetSdk.Transactions;
using Tessera.Chains;
using Tessera.Core;
using SendStatus = StellarDotnetSdk.Responses.SorobanRpc.SendTransactionResponse.SendTransactionStatus;
using TxStatus = StellarDotnetSdk.Responses.SorobanRpc.TransactionInfo.TransactionStatus;

namespace Tessera.Chains.Stellar
{
    /// <summary>
    /// Stellar/Soroban implementation of <see cref="IChainAnchor"/>. Anchors attestation Merkle
    /// roots and revocation epochs for a DID by invoking the deployed <c>attestation-anchor</c>
    /// Soroban contract (see <c>chains/stellar/contracts/attestation-anchor</c>). Full EC proof
    /// verification stays off-chain; the contract stores and reads <c>(did_hash → root, epoch)</c>
    /// only, mirroring the Solana program and EVM contract.
    /// </summary>
    /// <remarks>
    /// Writes follow the standard Soroban flow: build the <c>InvokeContract</c> transaction,
    /// <c>simulateTransaction</c> to obtain the footprint + resource fee + auth, assemble those
    /// onto the transaction, sign, <c>sendTransaction</c>, then poll <c>getTransaction</c> until
    /// the ledger applies it. Reads are pure simulations (no fee, no signature). The configured
    /// signing key is both the fee source and the anchor <c>owner</c>, so the contract's
    /// <c>require_auth(owner)</c> is satisfied by source-account authorization.
    /// </remarks>
    public sealed class StellarChainAnchor : IChainAnchor, IDisposable
    {
        private readonly SorobanServer _server;
        private readonly KeyPair _signer;
        private readonly string _contractId;
        private readonly Network _network;
        private readonly TimeSpan _confirmTimeout;
        private readonly TimeSpan _pollInterval;
        private readonly uint _feeBuffer;

        /// <summary>Creates an anchor bound to a deployed contract and signing account.</summary>
        public StellarChainAnchor(StellarAnchorOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);
            if (string.IsNullOrWhiteSpace(options.SorobanRpcUrl)) throw new ArgumentException("SorobanRpcUrl required.", nameof(options));
            if (string.IsNullOrWhiteSpace(options.ContractId)) throw new ArgumentException("ContractId required.", nameof(options));
            if (string.IsNullOrWhiteSpace(options.SigningKeySeed)) throw new ArgumentException("SigningKeySeed required.", nameof(options));

            _server = new SorobanServer(options.SorobanRpcUrl);
            _signer = KeyPair.FromSecretSeed(options.SigningKeySeed);
            _contractId = options.ContractId;
            _network = new Network(options.NetworkPassphrase);
            _confirmTimeout = options.ConfirmationTimeout;
            _pollInterval = options.ConfirmationPollInterval;
            _feeBuffer = options.ResourceFeeBuffer;
        }

        /// <inheritdoc/>
        public string ChainId => "stellar";

        /// <summary>
        /// Anchors the holder's Merkle attestation root on-chain by invoking
        /// <c>anchor_root(owner: Address, did_hash: BytesN&lt;32&gt;, root: BytesN&lt;32&gt;)</c>.
        /// The first call for a DID registers it (epoch 0); a later call updates the root.
        /// </summary>
        public async Task<AnchorTxResult> AnchorRootAsync(DidId did, byte[] attestationRoot, CancellationToken ct = default)
        {
            if (attestationRoot is null || attestationRoot.Length != 32)
                throw new ArgumentException("attestationRoot must be exactly 32 bytes.", nameof(attestationRoot));

            var args = new SCVal[]
            {
                new ScAccountId(_signer.AccountId),         // owner Address (== source account)
                new SCBytes(ComputeDidHash(did)),           // did_hash: BytesN<32>
                new SCBytes(attestationRoot),               // root: BytesN<32>
            };

            var txId = await InvokeAndConfirmAsync("anchor_root", args, ct).ConfigureAwait(false);
            return new AnchorTxResult(txId, null, DateTimeOffset.UtcNow);
        }

        /// <summary>
        /// Reads the current anchor state via <c>get_anchor(did_hash) → Option&lt;Anchor&gt;</c>,
        /// returning null when the DID has never been anchored.
        /// </summary>
        public async Task<AnchorState?> GetAnchorAsync(DidId did, CancellationToken ct = default)
        {
            var args = new SCVal[] { new SCBytes(ComputeDidHash(did)) };
            var result = await SimulateReadAsync("get_anchor", args, ct).ConfigureAwait(false);

            // Option::None is encoded as ScVoid; Option::Some(Anchor) as an SCMap of fields.
            if (result is null or SCVoid)
                return null;

            if (result is not SCMap map)
                throw new InvalidOperationException($"get_anchor returned an unexpected value type: {result.GetType().Name}.");

            byte[]? root = null;
            ulong epoch = 0;
            ulong updatedAt = 0;
            foreach (var entry in map.Entries)
            {
                if (entry.Key is not SCSymbol key) continue;
                switch (key.InnerValue)
                {
                    case "root": root = (entry.Value as SCBytes)?.InnerValue; break;
                    case "epoch": epoch = (entry.Value as SCUint64)?.InnerValue ?? 0; break;
                    case "updated_at": updatedAt = (entry.Value as SCUint64)?.InnerValue ?? 0; break;
                }
            }

            if (root is null)
                throw new InvalidOperationException("get_anchor result is missing the 'root' field.");

            return new AnchorState
            {
                Did = did,
                AttestationRoot = root,
                RevocationEpoch = epoch,
                UpdatedAt = DateTimeOffset.FromUnixTimeSeconds((long)updatedAt),
            };
        }

        /// <summary>
        /// Bumps the revocation epoch via <c>bump_revocation(did_hash, reason) → u64</c>.
        /// </summary>
        public async Task<AnchorTxResult> BumpRevocationAsync(DidId did, RevocationReason reason, CancellationToken ct = default)
        {
            var args = new SCVal[]
            {
                new SCBytes(ComputeDidHash(did)),
                new SCUint32((uint)reason),
            };

            var txId = await InvokeAndConfirmAsync("bump_revocation", args, ct).ConfigureAwait(false);
            return new AnchorTxResult(txId, null, DateTimeOffset.UtcNow);
        }

        /// <summary>
        /// Returns true when the DID's on-chain revocation epoch is strictly greater than
        /// <paramref name="asOfEpoch"/>, meaning presentations anchored at that epoch are stale.
        /// </summary>
        public async Task<bool> IsRevokedSinceAsync(DidId did, ulong asOfEpoch, CancellationToken ct = default)
        {
            var state = await GetAnchorAsync(did, ct).ConfigureAwait(false);
            if (state is null) return false;
            return state.RevocationEpoch > asOfEpoch;
        }

        // ── Soroban plumbing ─────────────────────────────────────────────────

        /// <summary>
        /// Builds an invoke transaction, simulates it to obtain the footprint/fee/auth, assembles
        /// those onto the transaction, signs, submits, and polls until the ledger applies it.
        /// Returns the transaction hash.
        /// </summary>
        private async Task<string> InvokeAndConfirmAsync(string function, SCVal[] args, CancellationToken ct)
        {
            var source = await _server.GetAccount(_signer.AccountId).ConfigureAwait(false);
            var op = new InvokeContractOperation(_contractId, function, args, null);
            var tx = new TransactionBuilder(source).AddOperation(op).Build();

            var sim = await _server.SimulateTransaction(tx).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(sim.Error))
                throw new InvalidOperationException($"Soroban simulation of {function} failed: {sim.Error}");
            if (sim.SorobanTransactionData is null || sim.MinResourceFee is null)
                throw new InvalidOperationException($"Soroban simulation of {function} returned no transaction data.");

            tx.SetSorobanTransactionData(sim.SorobanTransactionData);
            if (sim.SorobanAuthorization is { Length: > 0 })
                tx.SetSorobanAuthorization(sim.SorobanAuthorization);
            tx.AddResourceFee(checked((uint)sim.MinResourceFee.Value + _feeBuffer));
            tx.Sign(_signer, _network);

            var send = await _server.SendTransaction(tx).ConfigureAwait(false);
            if (send.Status == SendStatus.ERROR)
                throw new InvalidOperationException($"Soroban sendTransaction for {function} was rejected (status ERROR).");
            if (string.IsNullOrEmpty(send.Hash))
                throw new InvalidOperationException($"Soroban sendTransaction for {function} returned no hash.");

            await ConfirmAsync(send.Hash, function, ct).ConfigureAwait(false);
            return send.Hash;
        }

        /// <summary>Polls <c>getTransaction</c> until the tx succeeds, fails, or the timeout elapses.</summary>
        private async Task ConfirmAsync(string hash, string function, CancellationToken ct)
        {
            var deadline = DateTimeOffset.UtcNow + _confirmTimeout;
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                var info = await _server.GetTransaction(hash).ConfigureAwait(false);
                switch (info.Status)
                {
                    case TxStatus.SUCCESS:
                        return;
                    case TxStatus.FAILED:
                        throw new InvalidOperationException($"Soroban transaction {function} ({hash}) failed on-ledger.");
                    default: // NOT_FOUND — not yet applied
                        if (DateTimeOffset.UtcNow >= deadline)
                            throw new TimeoutException($"Soroban transaction {function} ({hash}) was not confirmed within {_confirmTimeout}.");
                        await Task.Delay(_pollInterval, ct).ConfigureAwait(false);
                        break;
                }
            }
        }

        /// <summary>Simulates a read-only contract call and returns its decoded return value.</summary>
        private async Task<SCVal?> SimulateReadAsync(string function, SCVal[] args, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            var source = await _server.GetAccount(_signer.AccountId).ConfigureAwait(false);
            var op = new InvokeContractOperation(_contractId, function, args, null);
            var tx = new TransactionBuilder(source).AddOperation(op).Build();

            var sim = await _server.SimulateTransaction(tx).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(sim.Error))
                throw new InvalidOperationException($"Soroban simulation of {function} failed: {sim.Error}");

            var xdr = sim.Results is { Length: > 0 } ? sim.Results[0].Xdr : null;
            return string.IsNullOrEmpty(xdr) ? null : SCVal.FromXdrBase64(xdr);
        }

        private static byte[] ComputeDidHash(DidId did)
            => SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(did.Value));

        /// <summary>Disposes the underlying Soroban RPC client.</summary>
        public void Dispose() => _server.Dispose();
    }
}
