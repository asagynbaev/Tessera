namespace Tessera.Chains;

/// <summary>
/// Bridges a verified subject to an external on-chain transfer-restriction contract:
/// once a subject's identity is verified (off-chain, by a <c>Verifier</c>), the gateway
/// adds their address to the restriction contract's allowlist; on revocation it removes them.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately narrow — two operations, an address in, no token, network, or contract
/// specifics leaking through. Concrete implementations bind to a specific restriction
/// contract (a simple allowlist, an ERC-3643/T-REX whitelist module, ...) entirely via
/// configuration, so swapping the gated token or chain never touches the core.
/// </para>
/// <para>
/// The gateway does NOT decide <em>whether</em> a subject is eligible — that is the
/// verifier/policy layer's job. It only reflects an already-made decision on-chain.
/// </para>
/// </remarks>
public interface IAllowlistGateway
{
    /// <summary>Identifies the chain this gateway writes to ("evm:56", ...).</summary>
    string ChainId { get; }

    /// <summary>Add (allow) an address on the restriction contract. Idempotent on-chain.</summary>
    Task AddAsync(string address, CancellationToken ct = default);

    /// <summary>Remove (disallow) an address from the restriction contract. Idempotent on-chain.</summary>
    Task RevokeAsync(string address, CancellationToken ct = default);
}
