# Solana — IdentityRegistry

Primary chain backend for the Tessera identity layer. The on-chain program is
deliberately minimal: it anchors Merkle attestation roots and revocation epochs
keyed by DID hash. No proof verification, no balances, no reputation logic.

## Program

`programs/identity-registry/` — single Anchor program. State:

- `RegistryConfig` (singleton PDA seeded by the constant `["config"]`) — holds the `admin`
  pubkey that gates issuer registration / deactivation. Created once by `initialize`.
- `DidAnchor` (PDA seeded by `["did", did_hash]`) — owner pubkey, current attestation
  Merkle root, revocation epoch, timestamps.
- `Issuer` (PDA seeded by `["issuer", issuer_did_hash]`) — registered issuer record:
  signing key, schema URI, active flag.

Instructions:

| Instruction | Signer | Effect |
|---|---|---|
| `initialize(admin)` | Deployer / governance | Create the singleton `RegistryConfig` PDA and record the `admin`. Must run once before any issuer can be registered; a second call fails (`init` on the constant `["config"]` seed). |
| `register_did(did_hash, attestation_root)` | DID owner | Create the DID anchor account; the recorded `owner` is the signer (the Solana-native equivalent of the EVM `registerDid` controller signature). |
| `update_root(new_root)` | DID owner | Replace the attestation Merkle root. |
| `bump_revocation(reason)` | DID owner | Increment the revocation epoch — prior presentations are stale. |
| `register_issuer(issuer_did_hash, schema_uri)` | Registry admin | Add an issuer record. **Admin-gated**: the `admin` signer must equal `RegistryConfig.admin` (enforced by `has_one = admin`). Off-chain attestation signatures are checked against the recorded signing key. |
| `deactivate_issuer()` | Registry admin | Flip an issuer record inactive. Same admin gate as `register_issuer`; mirrors the EVM `deactivateIssuer`. |

> **Admin gate (C4 fix):** issuer registration is no longer open to any signer. Run
> `initialize(admin)` first; only that recorded admin key can `register_issuer` /
> `deactivate_issuer` thereafter. The C# adapter's `IChainAnchor` runtime path
> (`src/Tessera.Chains.Solana/`) covers `register_did` / `update_root` /
> `bump_revocation` / reads; `initialize` / `register_issuer` / `deactivate_issuer` are
> admin-only instruction builders intended for governance tooling.

## What is NOT here

This program **does not**:

- Verify zero-knowledge proofs (Bulletproofs verification stays off-chain).
- Store DID documents, attestation payloads, names, handles, or any identity data.
- Compute or store reputation scores.
- Implement a token, governance, or DAO surface.

## Build

```bash
cd chains/solana
anchor build
```

Anchor 0.30.x is required.

## Deploy

```bash
anchor deploy --provider.cluster devnet
```

The program ID ships as a placeholder (`declare_id!("11111111111111111111111111111114")`);
generate a real keypair and run `anchor keys sync` before deploying. After deploy, call
`initialize(admin)` once to create the `RegistryConfig` PDA and set the admin that gates
issuer registration. See [`docs/deploying-solana.md`](../../docs/deploying-solana.md) for the
full end-to-end flow.

## C# client

The C# implementation of `IChainAnchor` for Solana lives at `src/Tessera.Chains.Solana/`
(complete: Borsh codec, Anchor discriminators, PDA derivation, instruction builders, account
decoders, and env-gated devnet smoke tests). Reads fail closed: a failed RPC call throws
rather than masquerading as "no anchor", and a returned account is rejected unless it is
owned by the configured program and carries the expected 8-byte Anchor discriminator
(account-substitution defense). The generic EVM counterpart is `chains/evm/`.
