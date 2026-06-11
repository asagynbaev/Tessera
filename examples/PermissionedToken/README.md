# PermissionedToken (reference)

A Layer-3 **reference**, not a shipped product: it assembles the generic Tessera building
blocks into an end-to-end **compliance flow** for a permissioned token.

## What it demonstrates

Onboarding → DID + attestations → presentation → `VerificationPolicy` → **allowlist admission**
(`IAllowlistGateway`) → token ownership, then a **revocation-epoch** bump that makes the prior
presentation stale and removes the address — blocking further transfers. The pieces:

- `CompliancePolicies` — the declarative `VerificationPolicy` (required attestation types +
  predicate rules).
- `InMemoryAllowlistGateway` / `InMemoryComplianceChain` — in-memory stand-ins for the on-chain
  allowlist + anchor, so the whole flow runs without a node.
- `PermissionedTokenLedger` — a minimal allowlist-gated transfer ledger.

The on-chain counterpart is
[`chains/evm/contracts/PermissionedToken.sol`](../../chains/evm/contracts/PermissionedToken.sol),
driven via `EvmAllowlistGateway`.

## Run

```bash
dotnet test examples/PermissionedToken.Tests
```

`ComplianceFlowTests` walks the full onboard → admit → revoke → blocked path.

## On standards

The reference token is an **allowlist-gated token**. ERC-3643 / T-REX whitelist modules are
supported by driving them through `IAllowlistGateway` **configuration** (contract address +
function names) — this example is **not** itself an ERC-3643 implementation.
