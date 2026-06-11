# Tessera.Sources.Bitcoin

Layer-2 plugin that turns **proven control of Bitcoin addresses** into Tessera attestations — the
basis for "private proof-of-Bitcoin". The holder signs a challenge with their wallet; the plugin
verifies it, reads confirmed balances/UTXOs through a pluggable provider, and emits attestation
drafts that carry **only commitments and an address count** — never an address, txid, or amount.

It implements `IAttestationSource` and depends only on the core (`Tessera.Attestations`,
`Tessera.Core`) plus **NBitcoin** (for BIP-137 message recovery). It never touches
`Tessera.Cryptography`'s secp256k1.

## Flow

```
challenge ─sign(wallet)→ signature ─verify→ VerifiedBitcoinAddress ─provider→ facts ─commit→ drafts
```

1. **Challenge** — `BitcoinChallenge.Create(subjectDid, audience, validity)` mints a single-use,
   domain-separated challenge. The holder runs `challenge.ToCanonicalString()` through their wallet's
   `signmessage`.
2. **Verify control** — `BitcoinControlVerifier.VerifyAsync(challenge, audience, address, signature, network)`
   checks the audience, the expiry (with clock skew), the signature, and nonce freshness, and (when a
   store is supplied) records the `VerifiedBitcoinAddress`.
3. **Facts → drafts** — `BitcoinAttestationSource.ResolveForAsync(subject, verifiedAddresses)` queries
   the provider, computes facts, and returns drafts, the Pedersen openings, and the facts. (The
   `IAttestationSource.ResolveAsync` pipeline path reads verified addresses from an
   `IBitcoinControlStore` and exposes the openings via `TryGetOpenings`.)

## Address-type support matrix

Control is proven by **BIP-137 `signmessage`** recovery (header byte → recovery id → recovered key,
matched against the claimed address's output script — header-tolerant: a legacy-range header on a
segwit key still verifies).

| Address type | Prefix (main / test) | Supported | Notes |
|---|---|---|---|
| P2PKH (legacy) | `1…` / `m…`,`n…` | ✅ | Both compressed and uncompressed keys. |
| P2SH-P2WPKH (nested segwit) | `3…` / `2…` | ✅ | Only P2SH **wrapping P2WPKH**; other P2SH scripts (multisig, …) are not recoverable from a single signature → `address_mismatch`. |
| P2WPKH (native segwit) | `bc1q…` / `tb1q…` | ✅ | |
| P2TR (Taproot) | `bc1p…` / `tb1p…` | ❌ | Requires **BIP-322**; NBitcoin exposes no clean "simple" BIP-322 verification, so a P2TR address returns `IsValid=false`, reason `taproot_bip322_unsupported`. Not silently failed. |
| P2WSH / bare multisig / non-standard | — | ❌ | `unsupported_address_type`. |

No silent partial support: every unsupported type returns an explicit reason code.

## Challenge canonical string (byte-exact)

The holder signs exactly this UTF-8 string — six lines joined by a single `\n` (`0x0A`), no trailing
newline, fixed field order, with a domain-separation prefix so a Tessera challenge can never collide
with another protocol's signed message:

```
tessera-btc-v1\n
sub=<subject DID>\n
aud=<audience>\n
nonce=<lowercase hex of the nonce bytes>\n
iat=<issued-at, Unix seconds>\n
exp=<expires-at, Unix seconds>
```

Example (single line, `\n` shown literally):

```
tessera-btc-v1\nsub=did:tessera:abc\naud=aureus\nnonce=8f3c…\niat=1700000000\nexp=1700000600
```

Anti-replay: the nonce is ≥ 16 bytes and single-use via `INonceStore` (in-memory impl bundled). The
replay token is keyed per `(subject, nonce, address)`, so one challenge may be signed by several of the
holder's addresses while each `(address, signature)` stays single-use; the token lives for the full
acceptance window (`exp + clock skew`).

## Facts computed over the verified addresses

- `total_sats` — Σ confirmed balance across all verified addresses (from the address summary).
- `hodl_age_days` — value-weighted: `Σ(utxo.value × utxo.age_days) / Σ(utxo.value)` over confirmed
  UTXOs (numerator and denominator over the same UTXO set), age from each UTXO's confirming block time.
- `oldest_utxo_age_days` — age of the oldest confirmed UTXO.

**Gameability (be honest):** `hodl_age_days` is a **heuristic, not a guarantee**. Consolidating UTXOs
(spending and re-receiving) resets their confirmation time and so resets the weighted age; the
value-weighting only makes large, long-held outputs dominate. Treat it as a soft signal, not proof of
continuous custody. `total_sats` is a point-in-time confirmed balance and can change between reads.

## Attestation types (registered via `BitcoinSchemas`)

| Type | Payload | Predicate |
|---|---|---|
| `btc_control` | `address_count` claim **only** (no addresses) | boolean: ≥ 1 address proven |
| `btc_balance` | Pedersen commitment to `total_sats` | `ProveBoundMinimum` (e.g. `≥ 1 BTC`) |
| `btc_hodl_age` | Pedersen commitment to `hodl_age_days` | `ProveBoundMinimum` (e.g. `≥ 365 days`) |

These types live in this plugin (`BitcoinAttestationTypes`), not the vendor-neutral core — matching the
X-Road plugin precedent. Register them with `BitcoinSchemas.Register(registry)` or
`BitcoinSchemas.CreateStandardWithBitcoin()`.

### Privacy invariant (hard rule)

No address, txid, script, or plaintext amount ever appears in an attestation payload or schema.
Balances and ages are Pedersen-committed; `btc_control` carries the address **count**, not the
addresses. The plaintext facts and the commitment openings are returned to the issuer/holder out of
band and are never serialized into an attestation. A test serializes every draft (and a built
attestation's canonical bytes) and asserts no address/txid/amount/block-time leaks.

## Satoshi range (no clamp needed)

Predicate proofs use the 64-bit Bulletproof range (`[0, 2^64)`), so **every satoshi balance fits with
room to spare**: 100 BTC ≈ 2^33, the entire 21,000,000-BTC supply ≈ 2^51, and the practical ceiling is
2^64 − 1 sats ≈ 1.84 × 10^19 (~184 billion BTC). No clamping or scaling is applied — balances are
committed and proven in **full satoshis**.

## Provider

`IBitcoinProvider` abstracts chain data; `EsploraBitcoinProvider` implements it over the Esplora REST
API (mempool.space / blockstream.info / self-hosted). Base URL is configurable; `BitcoinNetwork`
selects Mainnet / Testnet / Signet defaults. Reads retry on transient faults (HTTP 5xx / 429 / network);
the provider never writes. Unit tests mock the provider; a live mempool.space testnet read is exercised
by an integration test gated behind `TESSERA_BITCOIN_E2E=1`.

> **Audit status:** the predicate proofs rest on `Tessera.Cryptography`, a from-scratch,
> **not constant-time** implementation pending external review — see
> [docs/security-audit-readiness.md](../../docs/security-audit-readiness.md).
