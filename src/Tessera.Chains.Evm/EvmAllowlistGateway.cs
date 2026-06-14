using Nethereum.Contracts;
using Nethereum.Hex.HexTypes;
using Nethereum.Util;
using Nethereum.Web3;
using Nethereum.Web3.Accounts;
using Tessera.Chains.Evm.Internal;

namespace Tessera.Chains.Evm;

/// <summary>
/// Generic EVM implementation of <see cref="IAllowlistGateway"/>. Reflects an off-chain
/// verification decision onto an on-chain transfer-restriction contract by calling its
/// allow/disallow functions. Function names and call style are configuration, so the same
/// adapter drives the reference <c>Allowlist</c> contract or any compatible whitelist
/// (including ERC-3643/T-REX whitelist modules) without code changes.
/// </summary>
/// <remarks>
/// Reads (<see cref="IsAllowedAsync"/>) are retried per <see cref="EvmRetryPolicy"/>. Writes
/// are single-shot to avoid double-submission on a receipt-wait timeout (see <see cref="EvmChainAnchor"/>).
/// The signing account must be authorized (agent/owner) on the restriction contract.
/// </remarks>
public sealed class EvmAllowlistGateway : IAllowlistGateway
{
    private readonly string _from;
    private readonly string _chainTag;
    private readonly EvmAllowlistGatewayOptions _o;
    private readonly Contract _contract;

    public EvmAllowlistGateway(EvmAllowlistGatewayOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.RpcUrl)) throw new ArgumentException("RpcUrl required.", nameof(options));
        if (string.IsNullOrWhiteSpace(options.ContractAddress)) throw new ArgumentException("ContractAddress required.", nameof(options));
        if (!AddressUtil.Current.IsValidEthereumAddressHexFormat(options.ContractAddress))
            throw new ArgumentException($"ContractAddress is not a valid EVM address: '{options.ContractAddress}'.", nameof(options));
        if (string.IsNullOrWhiteSpace(options.PrivateKey)) throw new ArgumentException("PrivateKey required.", nameof(options));
        if (options.ChainId <= 0) throw new ArgumentException("ChainId must be positive.", nameof(options));

        var account = new Account(options.PrivateKey, options.ChainId);
        var web3 = new Web3(account, options.RpcUrl);
        _from = account.Address;
        _chainTag = options.EffectiveChainTag;
        _o = options;
        _contract = web3.Eth.GetContract(BuildAbi(options), options.ContractAddress);
    }

    /// <summary>Advanced/testing constructor: inject a pre-built <see cref="IWeb3"/> and signer address.</summary>
    internal EvmAllowlistGateway(IWeb3 web3, string fromAddress, EvmAllowlistGatewayOptions options)
    {
        _o = options ?? throw new ArgumentNullException(nameof(options));
        _from = fromAddress ?? throw new ArgumentNullException(nameof(fromAddress));
        _chainTag = options.EffectiveChainTag;
        _contract = web3.Eth.GetContract(BuildAbi(options), options.ContractAddress);
    }

    public string ChainId => _chainTag;

    public Task AddAsync(string address, CancellationToken ct = default)
    {
        var (name, args) = ResolveAdd(RequireAddress(address));
        return SendAsync(name, args, ct);
    }

    public Task RevokeAsync(string address, CancellationToken ct = default)
    {
        var (name, args) = ResolveRevoke(RequireAddress(address));
        return SendAsync(name, args, ct);
    }

    /// <summary>Query whether an address is currently allowed. Convenience beyond the interface.</summary>
    public async Task<bool> IsAllowedAsync(string address, CancellationToken ct = default)
    {
        var fn = GetFunctionOrThrow(_o.IsAllowedFunctionName);
        return await EvmRetry.RunAsync(_o.Retry, () => fn.CallAsync<bool>(RequireAddress(address)), ct).ConfigureAwait(false);
    }

    // ── internals ────────────────────────────────────────────────────────────

    internal (string name, object[] args) ResolveAdd(string address) =>
        _o.Style == AllowlistFunctionStyle.SetBoolFlag
            ? (_o.SetFunctionName, new object[] { address, true })
            : (_o.AddFunctionName, new object[] { address });

    internal (string name, object[] args) ResolveRevoke(string address) =>
        _o.Style == AllowlistFunctionStyle.SetBoolFlag
            ? (_o.SetFunctionName, new object[] { address, false })
            : (_o.RemoveFunctionName, new object[] { address });

    private async Task SendAsync(string name, object[] args, CancellationToken ct)
    {
        var fn = GetFunctionOrThrow(name);
        ct.ThrowIfCancellationRequested();

        HexBigInteger gas;
        if (_o.GasLimit is { } g)
        {
            gas = new HexBigInteger(g);
        }
        else
        {
            try
            {
                gas = await fn.EstimateGasAsync(_from, null, null, args).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    $"Gas estimation failed for '{name}' on {_o.ContractAddress}. The signing account ({_from}) may not be " +
                    $"authorized (agent/owner) on the restriction contract, or the call would revert. Original error: {ex.Message}", ex);
            }
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var receipt = await fn.SendTransactionAndWaitForReceiptAsync(_from, gas, new HexBigInteger(0), cts, args).ConfigureAwait(false);

        // A mined-but-reverted allow/revoke would otherwise return silently (Nethereum does not throw
        // on status 0 here). Assert success so a failed list mutation never looks like it took effect.
        EvmTx.EnsureReceiptSucceeded(receipt.Status, receipt.TransactionHash);
    }

    private Function GetFunctionOrThrow(string name)
        => _contract.GetFunction(name)
           ?? throw new InvalidOperationException(
               $"Function '{name}' is not in the contract ABI. Check the function-name options on EvmAllowlistGatewayOptions " +
               $"(Style={_o.Style}; add={_o.AddFunctionName}, remove={_o.RemoveFunctionName}, set={_o.SetFunctionName}, isAllowed={_o.IsAllowedFunctionName}).");

    private static string RequireAddress(string address)
    {
        if (string.IsNullOrWhiteSpace(address) || !AddressUtil.Current.IsValidEthereumAddressHexFormat(address))
            throw new ArgumentException($"Not a valid EVM address: '{address}'.", nameof(address));
        return address;
    }

    /// <summary>Build a minimal ABI for the configured functions so the dynamic contract can encode calls.</summary>
    internal static string BuildAbi(EvmAllowlistGatewayOptions o)
    {
        const string addrIn = "{\"name\":\"account\",\"type\":\"address\"}";
        const string addrBoolIn = "{\"name\":\"account\",\"type\":\"address\"},{\"name\":\"allowed\",\"type\":\"bool\"}";

        static string Write(string name, string inputs) =>
            $"{{\"type\":\"function\",\"name\":\"{ValidName(name)}\",\"stateMutability\":\"nonpayable\",\"inputs\":[{inputs}],\"outputs\":[]}}";

        var entries = new List<string>();
        if (o.Style == AllowlistFunctionStyle.SetBoolFlag)
            entries.Add(Write(o.SetFunctionName, addrBoolIn));
        else
        {
            entries.Add(Write(o.AddFunctionName, addrIn));
            entries.Add(Write(o.RemoveFunctionName, addrIn));
        }

        entries.Add(
            $"{{\"type\":\"function\",\"name\":\"{ValidName(o.IsAllowedFunctionName)}\",\"stateMutability\":\"view\",\"inputs\":[{addrIn}],\"outputs\":[{{\"name\":\"\",\"type\":\"bool\"}}]}}");

        return "[" + string.Join(",", entries) + "]";
    }

    /// <summary>
    /// Validate a configured function name is a valid Solidity identifier before it is interpolated
    /// into the ABI JSON — prevents both malformed JSON and any injection via misconfiguration.
    /// </summary>
    private static string ValidName(string name)
    {
        if (string.IsNullOrEmpty(name) || !System.Text.RegularExpressions.Regex.IsMatch(name, "^[A-Za-z_][A-Za-z0-9_]*$"))
            throw new ArgumentException($"'{name}' is not a valid Solidity function identifier.", nameof(name));
        return name;
    }
}
