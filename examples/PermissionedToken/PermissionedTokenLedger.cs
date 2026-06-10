namespace Tessera.Examples.PermissionedToken;

/// <summary>
/// In-memory mirror of the on-chain <c>PermissionedToken</c>: every party to a transfer (and every
/// mint recipient) must be allowed by the gating predicate. Demonstrates, deterministically, that
/// revoking an address blocks its transfers — the on-chain contract enforces the same in Solidity.
/// </summary>
public sealed class PermissionedTokenLedger
{
    private readonly Func<string, bool> _isAllowed;
    private readonly Dictionary<string, long> _balances = new(StringComparer.OrdinalIgnoreCase);

    public PermissionedTokenLedger(Func<string, bool> isAllowed)
        => _isAllowed = isAllowed ?? throw new ArgumentNullException(nameof(isAllowed));

    public long BalanceOf(string address) => _balances.TryGetValue(address, out var b) ? b : 0;

    public void Mint(string to, long amount)
    {
        RequireAllowed(to);
        _balances[to] = BalanceOf(to) + amount;
    }

    public void Transfer(string from, string to, long amount)
    {
        RequireAllowed(from);
        RequireAllowed(to);
        if (BalanceOf(from) < amount) throw new InvalidOperationException("insufficient balance");
        _balances[from] = BalanceOf(from) - amount;
        _balances[to] = BalanceOf(to) + amount;
    }

    private void RequireAllowed(string address)
    {
        if (!_isAllowed(address)) throw new PermissionedTransferBlockedException(address);
    }
}

/// <summary>Thrown when a transfer touches an address that is not (or no longer) allowed.</summary>
public sealed class PermissionedTransferBlockedException : Exception
{
    public string Address { get; }
    public PermissionedTransferBlockedException(string address)
        : base($"Address is not allowed by the permissioned token: {address}.") => Address = address;
}
