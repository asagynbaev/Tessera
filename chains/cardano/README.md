# Cardano anchor

The Cardano backend for Tessera's chain-agnostic anchoring layer. Like the
Solana and EVM backends, it stores **only** Merkle attestation roots and
revocation epochs — one record per DID hash — and verifies no proofs and holds no
PII. `didHash = SHA-256(utf8(did))` is identical across every backend.

It targets the **preprod** testnet and has functional parity with the Solana
path: `register_did`, `update_root`, `bump_revocation`, `register_issuer`.

## Layout

| Piece | Path | Status |
|---|---|---|
| Aiken validators (Plutus V3) | [`contracts/identity-registry/`](contracts/identity-registry/) | Complete — `aiken check` green (18 tests), blueprint checked in |
| C# adapter | [`src/Tessera.Chains.Cardano/`](../../src/Tessera.Chains.Cardano/) | `CardanoChainAnchor : IChainAnchor`, CardanoSharp + Blockfrost |
| Deploy guide | [`DEPLOYMENT.md`](DEPLOYMENT.md) | preprod end-to-end |

## Design — state-thread (beacon) tokens under eUTXO

One UTxO per DID lives at the validator's script address with an inline
`DidAnchorDatum` and a unique thread token. A single multi-purpose validator is
*both* the minting policy and the spending validator, so
`policy_id == script_hash == script-address payment credential`. The thread token
is named by the `did_hash`, which both keys the record and defeats
double-satisfaction. Registration mints the token; `update_root` /
`bump_revocation` spend-and-recreate the UTxO under controller signature,
preserving the token and the immutable fields. Full datum/redeemer/check spec and
the derived preprod addresses are in the
[contract README](contracts/identity-registry/README.md).

## Operations (parity)

| Operation | Redeemer | Signer | Effect |
|---|---|---|---|
| `register_did` | `mint · RegisterDid` | controller | Create the anchor UTxO, `epoch = 0`. |
| `update_root` | `spend · UpdateRoot { new_root }` | controller | Replace the attestation root. |
| `bump_revocation` | `spend · BumpRevocation { reason }` | controller | `epoch := epoch + 1`. |
| `register_issuer` | `mint · RegisterIssuer` | issuer | Lock an immutable issuer record. |

## Anchor modes (C# adapter)

The adapter exposes two `AnchorMode`s with **different trust properties**:

- **`Validator` (default).** The full Plutus flow above. State lives in a
  script-locked UTxO; the validator enforces controller signatures, monotonic
  epochs, immutable fields, and token continuity. This is the trust-minimised
  path. Requires a controller wallet funded with preprod test ADA (fees +
  min-UTxO + collateral).
- **`Metadata` (demo fallback).** Writes `{ did_hash, root, epoch }` as
  transaction metadata under a fixed label; reads scan that label via Blockfrost.
  No script enforces anything — a verifier trusts the **controller key** that
  signed the metadata transaction, not the chain. Cheaper and simpler, but it
  does **not** give the validator's tamper-evidence. Use it for demos, not
  production.

## Trust boundary (eUTXO)

The thread token + continuity rules make a *live* anchor unforgeable. Strict
*global* "one registration per `did_hash`" is not enforceable on-chain with a
single global policy (two transactions can't observe each other) — the adapter
resolves this the same way the Solana/EVM adapters do: read chain state first,
then route register-vs-update. See the contract README for detail.

## Future work

1. **Strict global registration uniqueness** via a singleton registry UTxO that
   every `register_did` must spend (serialises registrations; trades concurrency
   for an on-chain guarantee).
2. **Issuer deactivation** — the issuer record is immutable today (parity with
   Solana, which also lacks a deactivate path). A revocable variant would add a
   spend handler gated by an authority key.
3. **Reference scripts** — publish the validators as reference scripts on preprod
   so anchoring txs don't carry the script bytes (smaller fees).
4. **Native Midnight integration** is *planned*, not present — a zkSNARK stack
   with selective disclosure on Midnight. Do not assume it exists.

## Build & test

```sh
cd contracts/identity-registry
aiken check     # 18 on-chain unit tests
aiken build     # emit plutus.json
```

Or from this directory: `make check`, `make build`, `make blueprint`.
