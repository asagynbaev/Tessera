# Stellar anchor

Soroban contract for anchoring DID roots on Stellar. Tessera is chain-agnostic — any
network that implements `IChainAnchor` is a first-class anchor target. The Solana adapter
is complete; the Stellar adapter is in progress (anchor contract not yet written).

## Status

| Component | State |
|---|---|
| `contracts/attestation-verifier/` | Working contract from v2.x. Verifies HMAC and Bulletproof-structure on-chain. Kept for backward compatibility with v2.x consumers. |
| C# adapter `Tessera.Chains.Stellar` | Scaffolded against `IChainAnchor` but the dedicated anchor contract for storing roots/epochs has not been written yet. The C# side is wired; the Rust contract for anchor-state needs to be added. |

If you need on-chain anchoring of DID roots **today**, use the Solana adapter.
Stellar reaches full parity when the anchor contract lands — at that point both adapters
are interchangeable and you pick the network at registration time.

## What the existing `attestation-verifier` contract does

The contract in [`contracts/attestation-verifier/`](contracts/attestation-verifier/) is
the v2-era proof verifier (renamed from `proof-balance` to match the new architecture).
It performs:

- **HMAC-SHA256 verification** — full on-chain recomputation + constant-time compare.
- **Bulletproof structural validation** — checks compressed-point prefixes and IPA length;
  emits a transcript-binding hash for off-chain auditing. Soroban does not natively
  support secp256k1 EC math, so full Bulletproof verification **must** run off-chain via
  `Tessera.Attestations.CredentialProof.Verify`.

It is **not** the DID anchor contract — that is a separate contract that will live next
to it once written.

## Build and deploy

```bash
cargo build --target wasm32v1-none --release
soroban contract deploy \
    --wasm target/wasm32v1-none/release/attestation_verifier.wasm \
    --source alice \
    --network testnet
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for full setup (Rust + Stellar CLI + network config).

## Future work

To reach parity with Solana:

1. Write `contracts/attestation-anchor/` with these instructions:
   - `register_did(did_hash, attestation_root)` → init `did_anchor` record
   - `update_root(did_hash, new_root)` → mutate root on owner-signed tx
   - `bump_revocation(did_hash, reason)` → increment epoch
   - `register_issuer(issuer_did_hash, schema_uri)` → register issuer
2. Mirror the Solana data layout (32-byte `did_hash`, 32-byte `attestation_root`, `u64` epoch, owner pubkey).
3. Fill in the `NotImplementedException` paths in [`../../src/Tessera.Chains.Stellar/StellarChainAnchor.cs`](../../src/Tessera.Chains.Stellar/StellarChainAnchor.cs) to invoke the new contract via Soroban RPC.
