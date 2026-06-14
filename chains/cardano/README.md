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
| `register_issuer` | `mint · RegisterIssuer` | governance admin | Lock an immutable issuer record. Onboarding is **governance-gated**: the `issuer_registry` validator is parameterized by an admin VKH that must co-sign (see below). |

## Anchor modes (C# adapter)

The adapter exposes two `AnchorMode`s with **different trust properties**:

- **`Validator` (default).** The full Plutus flow above. State lives in a
  script-locked UTxO; the validator enforces controller signatures, monotonic
  epochs, immutable fields, and token continuity. This is the trust-minimised
  path. Requires a controller wallet funded with preprod test ADA (fees +
  min-UTxO + collateral).
- **`Metadata` (demo fallback).** Writes `{ did_hash, root, epoch }` as
  transaction metadata under a fixed label; reads scan that label via Blockfrost.
  No *script* enforces anything, so a verifier trusts the **controller key**, not
  the chain. Because the metadata label is a shared, permissionless namespace
  (any address can publish under it), the write **authenticates the controller**:
  each tx also carries the controller's Ed25519 public key (`pk`) and a detached
  signature (`sig`) over the canonical message `did_hash ‖ root ‖ epoch`. On read
  the adapter (a) requires the tx to originate from the controller's address and
  (b) verifies that embedded signature against the configured controller key,
  skipping any unauthenticated tx so a poisoned entry cannot suppress the
  controller's own newer state. This is cheaper and simpler than the validator,
  but it still does **not** give the validator's on-chain tamper-evidence. Use it
  for demos, not production.

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
2. **Issuer deactivation** — issuer onboarding is now governance-gated (the
   `issuer_registry` validator is parameterized by an admin VKH that must
   co-sign `register_issuer`), but the issuer record is still immutable once
   minted: there is no spend handler, so it cannot be deactivated (parity with
   Solana, whose program *does* now have a `deactivate_issuer` path). A revocable
   variant would add a spend handler gated by the same admin key.
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

> **Note (issuer_registry).** Governance-gating made `issuer_registry` take an
> `admin: VerificationKeyHash` parameter, so its policy id / script address are
> derived only after that parameter is applied. The checked-in `plutus.json`
> still reflects the pre-parameter scaffold; re-run `aiken build` to regenerate
> the blueprint, then point the C# adapter at the parameter-applied script via
> `CardanoScriptRefs.IssuerRegistryScript` and have the admin co-sign the
> registration tx. The `identity_anchor` validator is unparameterized and
> unaffected. On-chain validator changes only take effect once rebuilt with the
> Aiken toolchain and the new script address is used.
