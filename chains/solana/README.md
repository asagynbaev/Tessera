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

## Deploy (devnet)

One command takes a clean checkout to a deployed devnet program:

```bash
./scripts/deploy-devnet.sh      # build → sync declare_id! → rebuild → anchor deploy
```

[`scripts/deploy-devnet.sh`](scripts/deploy-devnet.sh) builds, reads the program id from
the generated keypair (`anchor keys list`), patches `declare_id!` + `Anchor.toml` to it,
rebuilds, deploys, and prints the program id + an explorer link. It is idempotent and fails
loudly if the toolchain is missing. The committed `declare_id!("11111111111111111111111111111114")`
is an intentional placeholder — the script patches it locally at deploy time; only the Rust
side carries a hardcoded id (the C# client reads it from `TESSERA_SOLANA_PROGRAM_ID`).

The program ships as an upgradeable program; re-running the script upgrades the same id in
place. Record the deployed id + sample tx links in [`DEPLOYMENT.md`](DEPLOYMENT.md).

Then point the env-gated smoke tests at the deployment (the script prints these):

```bash
export TESSERA_SOLANA_RPC="https://api.devnet.solana.com"
export TESSERA_SOLANA_PROGRAM_ID="<program id printed by the script>"
export TESSERA_SOLANA_PAYER_KEYPAIR="$HOME/.config/solana/id.json"

dotnet test ../../src/Tessera.Chains.Solana.Tests \
    --filter "FullyQualifiedName~Smoke.SolanaDevnetSmokeTests"
```

`initialize(admin)` is **optional** — the smoke tests use owner-signed DID instructions and
need no `RegistryConfig`. Run [`scripts/initialize-devnet.sh`](scripts/initialize-devnet.sh)
only for the admin-gated issuer flows. See
[`docs/deploying-solana.md`](../../docs/deploying-solana.md) for the full end-to-end guide,
including issuer registration and re-deploy/cleanup.

## C# client

The C# implementation of `IChainAnchor` for Solana lives at `src/Tessera.Chains.Solana/`
(complete: Borsh codec, Anchor discriminators, PDA derivation, instruction builders, account
decoders, and env-gated devnet smoke tests). Reads fail closed: a failed RPC call throws
rather than masquerading as "no anchor", and a returned account is rejected unless it is
owned by the configured program and carries the expected 8-byte Anchor discriminator
(account-substitution defense). The generic EVM counterpart is `chains/evm/`.
