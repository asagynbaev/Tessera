# Cardano — identity-registry (Aiken / Plutus V3)

The eUTXO counterpart of [`chains/solana/programs/identity-registry/`](../../../solana/programs/identity-registry/)
and [`chains/evm/contracts/IdentityRegistry.sol`](../../../evm/contracts/IdentityRegistry.sol).
Like them, it is deliberately minimal: it anchors **only** a Merkle attestation
root and a monotonic revocation epoch per DID hash. It verifies no proofs, holds
no balances, and stores no PII, attestations, or DID documents — all of that
stays off-chain in C# (`Tessera.*`).

The C# adapter that drives it lives in
[`src/Tessera.Chains.Cardano/`](../../../../src/Tessera.Chains.Cardano/). The
`didHash = SHA-256(utf8(did))` keying is identical across every backend, so the
same identity keys the same record on Solana, EVM, and Cardano.

## State model — the state-thread (beacon) token pattern

There is **one UTxO per DID** at the validator's script address, carrying an
inline datum and a unique **thread token**. A single multi-purpose validator
serves as *both* the minting policy *and* the spending validator, so:

```
policy_id  ==  script_hash  ==  script-address payment credential
```

The thread token is `(policy_id, asset_name = did_hash)`, quantity 1. Because the
token name is the DID hash, distinct DIDs carry distinct tokens — which is also
what defeats double-satisfaction (no single output can satisfy two spends).

| Validator | Module | Policy id / script hash | Testnet (preprod) address |
|---|---|---|---|
| `identity_anchor` | `identity_anchor` | `73f81b6b4d9a0f348391acc37f7122cdca4dcc34a219c5ae111fdd60` | `addr_test1wpelsxmtfkdq7dyrjxkvxlm3ytxu5nwvxj3pn3dwzy0a6cqcu2k9g` |
| `issuer_registry` | `issuer_registry` | `3f94e0bc7163fef7ee132215bd94eee699b3a41fa5e049d4aca884e4` | `addr_test1wqlefc9uw93laalwzv3pt0v5amnfnvayr7j7qjw54j5gfeqt2sa63` |

These are deterministic from source — `aiken build` reproduces them exactly. Both
addresses are testnet-format (`addr_test`), valid on preprod and preview.

## Datums

```aiken
DidAnchorDatum {            // identity_anchor
  did_hash: ByteArray,        // SHA-256(utf8(did)), 32 bytes; == thread-token name
  attestation_root: ByteArray,// Merkle root of the holder's attestation bundle, 32 bytes
  revocation_epoch: Int,      // monotonic; 0 at registration
  controller: VerificationKeyHash, // 28-byte payment-key hash; the on-chain owner
}

IssuerDatum {               // issuer_registry (immutable once created)
  issuer_did_hash: ByteArray, // == thread-token name
  schema_uri_hash: ByteArray, // SHA-256 of the issuer's schema URI (the URI stays off-chain)
  issuer_pubkey: ByteArray,   // Ed25519 verification key (attestation signatures verify off-chain)
}
```

## Operations (parity with the Solana program)

| Operation | Purpose / redeemer | Signer | Effect |
|---|---|---|---|
| `register_did` | `mint` · `RegisterDid` | controller | Mint the thread token (name = `did_hash`) and create the anchor UTxO with `revocation_epoch = 0`. |
| `update_root` | `spend` · `UpdateRoot { new_root }` | controller | Recreate the anchor UTxO with `attestation_root := new_root`; epoch unchanged. |
| `bump_revocation` | `spend` · `BumpRevocation { reason }` | controller | Recreate with `revocation_epoch := epoch + 1`; root unchanged. `reason` is advisory. |
| `register_issuer` | `mint` · `RegisterIssuer` | issuer (self) | Mint the issuer beacon (name = `issuer_did_hash`) and lock the immutable `IssuerDatum`. |

## On-chain checks

**`register_did` (mint):** exactly one token minted under this policy with
quantity 1; exactly one continuing output to the script carrying it with a
well-formed datum where `did_hash == token name` and `revocation_epoch == 0`;
the `controller` named in the datum signs.

**`update_root` / `bump_revocation` (spend):** the spent input carries the thread
token; the `controller` signs; the policy's token is neither minted nor burned in
the tx; **exactly one** continuing output returns the token to the script
(double-satisfaction guard); `did_hash` and `controller` are unchanged;
`update_root` ⇒ epoch unchanged and `attestation_root == new_root`;
`bump_revocation` ⇒ root unchanged and `epoch_out == epoch_in + 1` (strictly
monotonic — Cardano `Int` is arbitrary precision, so there is no overflow case).

**`register_issuer` (mint):** exactly one beacon minted (qty 1) bound to a
continuing output whose datum's `issuer_did_hash == token name`; the issuer
authorises registration by signing with the key committed in `issuer_pubkey`
(`blake2b_224(issuer_pubkey) ∈ extra_signatories`). Immutable thereafter — there
is no spend handler, so the beacon is permanently locked (parity with the Solana
account, which is never closed).

## Trust boundary (eUTXO note)

The thread token + continuity rules make a *live* anchor's state **unforgeable**:
you cannot fork, duplicate, or re-key an existing anchor, and only the controller
can mutate it. What a single global minting policy **cannot** enforce on-chain is
strict *global* uniqueness — two separate transactions could each mint a
`did_hash` token, since neither can observe the other's UTxO. This is the same
class of limitation the Solana program documents as "first to claim"; the C#
adapter resolves it exactly as the Solana/EVM adapters do — **read chain state
first, then route register-vs-update** — so the canonical anchor is the one the
controller actually owns. Strict global uniqueness would require a singleton
registry UTxO that serialises every registration; that is intentionally out of
scope (see [`chains/cardano/README.md`](../../README.md) → Future work).

## Build, test, deploy

```sh
aiken check        # type-check + run the on-chain unit tests (18 tests)
aiken build        # emit plutus.json (the blueprint; checked in, like the EVM ABI)
aiken blueprint policy  -m identity_anchor -v identity_anchor   # policy id
aiken blueprint address -m identity_anchor -v identity_anchor   # preprod script address
```

See [`../../DEPLOYMENT.md`](../../DEPLOYMENT.md) for the end-to-end preprod flow
(build → configure the C# adapter → exercise register/update/bump).
