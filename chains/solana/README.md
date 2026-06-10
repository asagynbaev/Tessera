# Solana — IdentityRegistry

Primary chain backend for the Tessera identity layer. The on-chain program is
deliberately minimal: it anchors Merkle attestation roots and revocation epochs
keyed by DID hash. No proof verification, no balances, no reputation logic.

## Program

`programs/identity-registry/` — single Anchor program. State:

- `DidAnchor` (PDA seeded by `["did", did_hash]`) — owner pubkey, current attestation
  Merkle root, revocation epoch, timestamps.
- `Issuer` (PDA seeded by `["issuer", issuer_did_hash]`) — registered issuer record:
  signing key, schema URI, active flag.

Instructions:

| Instruction | Signer | Effect |
|---|---|---|
| `register_did(did_hash, attestation_root)` | DID owner | Create the DID anchor account. |
| `update_root(new_root)` | DID owner | Replace the attestation Merkle root. |
| `bump_revocation(reason)` | DID owner | Increment the revocation epoch — prior presentations are stale. |
| `register_issuer(issuer_did_hash, schema_uri)` | Registry authority | Add an issuer record (off-chain attestation signatures are checked against this). |

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

The program ID is a placeholder (`ZkpId1111...`); generate a real keypair before deploying.

## C# client

The C# implementation of `IChainAnchor` for Solana lives at `src/Tessera.Chains.Solana/`
(complete: Borsh codec, Anchor discriminators, PDA derivation, instruction builders, account
decoders, and env-gated devnet smoke tests). The generic EVM counterpart is `chains/evm/`.
