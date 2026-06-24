# Stellar anchor

Soroban contracts for anchoring DID roots on Stellar. Tessera is chain-agnostic — any
network that implements `IChainAnchor` is a first-class anchor target. The Stellar adapter
is **complete** and at parity with Solana/EVM: pick the network at registration time.

> **✅ Verified live on testnet (5/5).** The full `StellarTestnetSmokeTests` suite passed against a
> deployed `attestation-anchor` contract — `CCD5ADZNH5CSULAHJHAQPBULVDDCOUGLS2N33DVS5JP3EBKOOY33VLQJ`.

## Status

| Component | State |
|---|---|
| `contracts/attestation-anchor/` | **DID anchor.** Stores `(did_hash → owner, root, epoch)` and implements `anchor_root` / `bump_revocation` / `get_anchor`. The on-chain counterpart of the Solana `identity-registry` program and the EVM `IdentityRegistry`. |
| `contracts/attestation-verifier/` | Working contract from v2.x. Verifies issuer Ed25519 signatures and Bulletproof-structure on-chain. Kept for backward compatibility with v2.x consumers. |
| C# adapter `Tessera.Chains.Stellar` | **Complete.** `StellarChainAnchor` implements `IChainAnchor` against `attestation-anchor` via Soroban RPC (simulate → assemble → sign → send → confirm for writes; pure simulation for reads). Env-gated testnet smoke tests in `src/Tessera.Chains.Stellar.Tests`. |

See [DEPLOYMENT.md](DEPLOYMENT.md) for the full deploy + C# smoke flow.

## What the existing `attestation-verifier` contract does

The contract in [`contracts/attestation-verifier/`](contracts/attestation-verifier/) is
the v2-era proof verifier (renamed from `proof-balance` to match the new architecture).
It performs:

- **Issuer Ed25519 signature verification** — checks an off-chain issuer's signature over
  the canonical attestation message (`data || salt`) against the issuer public key stored
  in instance storage by an authenticated admin. No secret is ever supplied by the caller.
- **Bulletproof structural validation** — checks compressed-point prefixes and IPA length;
  emits a transcript-binding hash for off-chain auditing. Soroban does not natively
  support secp256k1 EC math, so full Bulletproof verification **must** run off-chain via
  `Tessera.Attestations.CredentialProof.Verify`.

It is **not** the DID anchor contract — that is [`attestation-anchor/`](contracts/attestation-anchor/),
described next.

## The `attestation-anchor` contract

[`contracts/attestation-anchor/`](contracts/attestation-anchor/) is the DID anchor — the
on-chain store for `(did_hash → owner, root, epoch)`, at parity with the Solana
`identity-registry` program and the EVM `IdentityRegistry`. Functions:

| Function | Caller | Effect |
|---|---|---|
| `anchor_root(owner, did_hash, root)` | `owner` (`require_auth`) | First call binds the DID to `owner` at epoch 0; later calls (same owner) replace the root. |
| `bump_revocation(did_hash, reason) → u64` | the anchor's `owner` | Increment the revocation epoch — prior presentations are stale. |
| `get_anchor(did_hash) → Option<Anchor>` | anyone (read) | Read the current `(owner, root, epoch, timestamps)`, or `None`. |

`did_hash = SHA-256(utf8(did))`, identical across the C# adapter and every backend. Because
`did_hash` is public, every write requires the `owner` to authorize (`require_auth`) — the
Soroban-native equivalent of the EVM controller signature and the Solana `owner: Signer`
constraint. Anchor records live in persistent storage; their TTL is extended on every write.

## Build and deploy

```bash
cargo build --target wasm32v1-none --release        # builds both contracts (workspace)
stellar contract deploy \
    --wasm target/wasm32v1-none/release/attestation_anchor.wasm \
    --source alice \
    --network testnet
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for the full deploy + C# smoke flow (Rust + Stellar CLI +
network config).
