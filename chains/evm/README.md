# EVM — IdentityRegistry

Generic EVM backend for the Tessera identity layer — the EVM counterpart of
`chains/solana/`. The on-chain contract is deliberately minimal: it anchors Merkle
attestation roots and revocation epochs keyed by DID hash. No proof verification,
no balances, no reputation logic.

The contract is **network-agnostic**: chainId and RPC are pure configuration. The
same bytecode runs on any EVM chain (the reference scenario targets BNB Chain).

## Contracts

`contracts/IdentityRegistry.sol` — the anchor. State:

- `DidAnchor` (keyed by `didHash`) — owner address, current attestation Merkle root,
  revocation epoch, timestamps.
- `IssuerRecord` (keyed by `issuerDidHash`) — signing key (32-byte Ed25519, off-chain
  verification), schema URI, active flag.

Operations (parity with the Solana program):

| Function | Caller | Effect |
|---|---|---|
| `registerDid(didHash, attestationRoot, controller, signature)` | Anyone (relayer); `controller` becomes `owner` | Create the DID anchor. Requires a `controller` ECDSA signature so a public `didHash` cannot be squatted. |
| `updateRoot(didHash, newRoot)` | DID owner | Replace the attestation Merkle root. |
| `bumpRevocation(didHash, reason)` | DID owner | Increment the revocation epoch — prior presentations are stale. |
| `registerIssuer(issuerDidHash, signingKey, schemaUri)` | Registry authority | Add/refresh an issuer record. |
| `deactivateIssuer(issuerDidHash)` | Registry authority | Mark an issuer inactive. |

`didHash = SHA-256(utf8(did))` — identical across the C# adapter, the Solana program,
and this contract, so a DID hashes to the same value on every backend.

`registerDid` binds the anchor to the DID **controller**, not merely the first caller. Because
`didHash` is public, an unauthenticated `registerDid` would let an attacker front-run / squat any
DID and have the off-chain verifier trust their root. The caller must therefore supply
`controller` (the address that becomes `owner`) plus a 65-byte EIP-191/ECDSA `signature` by that
controller over `keccak256(abi.encode(didHash, attestationRoot, block.chainid, address(this)))`.
Binding `block.chainid` + the registry address prevents cross-chain / cross-contract replay; the
transaction may be relayed by any sender, so the controller need not pay gas. The C# adapter
(`EvmChainAnchor`) produces this signature automatically from its configured signing key.

`contracts/Allowlist.sol` — a minimal agent-gated address allowlist / transfer-restriction
registry (`addToAllowlist` / `removeFromAllowlist` / `isAllowed`). The C# `EvmAllowlistGateway`
drives it (or any compatible whitelist, e.g. an ERC-3643/T-REX module) to reflect off-chain
identity decisions on-chain.

`contracts/PermissionedToken.sol` — **reference (Layer 3), not product.** A minimal permissioned
BEP-20/ERC-20 whose transfers and mints are gated by an `Allowlist`. Removing an address blocks
its transfers on-chain, with no token-side identity logic. Used by the
`examples/PermissionedToken` end-to-end scenario.

## What is NOT here

This contract **does not**: verify zero-knowledge proofs (Bulletproofs verification
stays off-chain in C#), store DID documents / attestation payloads / names / handles /
any PII, compute reputation, or implement a token / governance / DAO surface.

## Build & test

```bash
cd chains/evm
npm install
npm run build      # hardhat compile (solc 0.8.24)
npm test           # contract unit tests
npm run export-abi # refresh abi/*.abi.json (checked into the repo)
```

The checked-in `abi/IdentityRegistry.abi.json` is the stable interface the C# adapter
(`src/Tessera.Chains.Evm/`) and its integration tests target.

> **v3.2.0 — breaking ABI change.** `registerDid` gained `controller` + `signature`
> parameters (the controller proof above), so its selector changed and the checked-in
> ABI was regenerated. Any already-deployed `IdentityRegistry` from a prior version is
> incompatible and must be **redeployed**; clients must use the regenerated ABI.

## Deploy

```bash
export TESSERA_EVM_RPC=https://...        # any EVM RPC
export TESSERA_EVM_KEY=<deployer-privkey> # funded account
npm run deploy:bnbtestnet
```

The deployer becomes the initial issuer-registry authority unless
`TESSERA_EVM_AUTHORITY` overrides it.

## Local smoke tests (C# adapter ↔ a real chain)

The `EvmChainAnchor` / `EvmAllowlistGateway` smoke tests in `src/Tessera.Chains.Evm.Tests`
are `[SkippableFact]`-gated on the `TESSERA_EVM_*` env vars, so they skip unless pointed at a
live chain. Run them against a throwaway local Hardhat node — no funds, no faucet:

```bash
cd chains/evm
npm ci && npx hardhat compile
npx hardhat node &                                            # local chain on :8545
npx hardhat run scripts/deploy-local.js --network localhost   # deploys both, writes deployed.local.json
cp .env.local.example .env.local && set -a && . ./.env.local && set +a
dotnet test ../../src/Tessera.Chains.Evm.Tests -c Release     # smoke tests now run live
```

`deploy-local.js` deploys `IdentityRegistry` + `Allowlist` and records their addresses in
`deployed.local.json` (gitignored). `.env.local.example` uses the stock, publicly-known Hardhat
account #0 — a throwaway key valid only on a local node; never put a real key there.

CI runs exactly this in the **`evm-smoke`** GitHub Actions job, so the on-chain anchor path is
exercised on every push/PR rather than silently skipping.

## C# client

`src/Tessera.Chains.Evm/EvmChainAnchor` implements `IChainAnchor` against this
contract via Nethereum. On the `registerDid` path it derives `controller` from its
configured signing key and produces the controller signature automatically. Every write
asserts the mined receipt's EIP-658 `Status == 1` (a missing/null status is treated as
failure), throwing `EvmTransactionFailedException` rather than reporting a reverted or
unverifiable transaction as success. See that package for the adapter and tests.
