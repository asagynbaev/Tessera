# Security audit readiness (A6)

This document is the dossier an external auditor should start from. It scopes the
security-critical surface, states the threat model, lists known limitations and the
deterministic test artifacts that pin behavior, and records what is explicitly deferred.

## In scope for audit

1. **`Tessera.Cryptography`** — from-scratch primitives, the highest-risk code:
   - `Secp256k1/` — `FieldElement`, `Scalar`, `Point`, `Generators` (curve arithmetic).
   - `PedersenCommitment` — `C = v·G + r·H`.
   - `Bulletproofs/` — `RangeProof`, `InnerProductProof`, `Transcript` (Fiat–Shamir).
2. **On-chain anchors** — `chains/solana` (Anchor), `chains/evm`
   (`IdentityRegistry.sol`, `Allowlist.sol`, reference `PermissionedToken.sol`), and
   `chains/cardano` (Aiken / Plutus V3 `identity_anchor` + `issuer_registry`).
3. **Chain adapters** — `Tessera.Chains.Evm` (`EvmChainAnchor`, `EvmAllowlistGateway`): ABI parity,
   idempotency/race handling, retry classification, single-shot writes. `Tessera.Chains.Cardano`
   (`CardanoChainAnchor`): hand-built Conway / Plutus V3 CBOR (language views, map-form redeemers,
   script-data hash, V3 script witness), single-shot writes; script hash / address / datum CBOR
   cross-checked against the Aiken blueprint.
4. **Verification path** — `AttestationVerifier`, `PresentationVerifier`,
   `Tessera.Sdk.Verifier`, and the declarative `VerificationPolicy` / `PolicyEvaluation`.

## What stays off-chain (invariant)

The chain stores **only** attestation Merkle roots + revocation epochs (and issuer
records: signing key, schema URI, active flag). No PII, no attestation contents, no
proof verification on-chain. Auditors should confirm no code path writes anything else.

## Threat model (headline)

| # | Threat | Mitigation | Audit focus |
|---|--------|------------|-------------|
| 1 | Forged attestation | Issuer Ed25519 signature over canonical bytes; issuer registry resolves active key | `AttestationCanonical`, signature checks |
| 2 | Replay across verifiers / sessions / chains | Presentation bound to `{verifier, session_nonce, as_of_epoch, chain}` | `Verifier.VerifyPresentationAsync` |
| 3 | Stale presentation after revocation | On-chain `revocation_epoch`; policy `RequireCurrentRevocationEpoch` | epoch comparison `current > asOf` |
| 4 | Issuer key compromise | Per-issuer `active` flag + `deactivateIssuer` + short attestation expiries | issuer registry read/write |
| 5 | Allowlist tamper | Restriction contract is agent/owner-gated; gateway only reflects decisions | `Allowlist.sol`, `EvmAllowlistGateway` |
| 6 | EVM write double-submission | Writes are single-shot; only reads are retried | `EvmChainAnchor.SendAsync`, `EvmRetry` |
| 7 | Range/predicate soundness | Bulletproofs range proof; **see Known limitations** | `RangeProof.Verify`, `PolicyEvaluation` |

## Addressed

- **Predicate ↔ attestation binding (was the primary gap).** `CredentialProof.CommitValue` +
  `ProveBoundMinimum`/`ProveBoundRange` + `VerifyBound` bind a range proof to the attestation's
  own commitment: the proof's commitment must equal `C − threshold·G`, where `C` is
  `AttestationPayload.Commitment`. `PolicyEvaluation` verifies predicates BOUND to the disclosed
  attestation, so a holder cannot present a proof about an arbitrary or substituted value. Covered
  by `CredentialProofBindingTests` and the negative cases in `PolicyEvaluationTests`
  (wrong-commitment, unbound-proof, and no-commitment all rejected).
- **Two-sided range proofs.** `ProveBoundRange(value, min, max)` proves BOTH `value − min ≥ 0`
  (commitment `C − min·G`) and `max − value ≥ 0` (commitment `max·G − C`), so the upper bound is
  cryptographically enforced — it is no longer metadata-only. `VerifyBound` checks both proofs
  against the C-derived commitments; the policy's upper-bound comparison is now sound.
- **Claim-value policy rules.** `VerificationPolicy.RequiredClaims` gates on issuer-signed claim
  values (e.g. jurisdiction `country ∈ {KZ}`). Claims are part of the signed canonical attestation,
  so they cannot be tampered post-issuance. The reference scenario now enforces residency this way
  instead of treating any `jurisdiction` attestation as resident.

## Known limitations (do not ship to high-assurance use without addressing)

1. **`Tessera.Cryptography` is not constant-time / not formally reviewed.** Self-implemented
   secp256k1 + Bulletproofs. No claim of side-channel resistance; needs an external crypto audit
   before protecting funds or high-value secrets. The predicate binding and two-sided range proofs
   in §"Addressed" rely on its `Point`/`Scalar` arithmetic being correct.
2. **Solana ↔ EVM parity gap.** The Solana program lacks an issuer-registered event, idempotent
   issuer re-registration, and a `deactivate_issuer` instruction that the EVM contract has.
   Rebuilding the Anchor program requires the Anchor toolchain (not in the build environment).
3. **Cardano Validator-mode transaction assembly is offline-verified but not yet validated on-chain.**
   Because CardanoSharp 5.1.0 predates Plutus V3, the Conway / V3 transaction (script-data hash,
   execution-unit budgeting, witness layout) is hand-built with `System.Formats.Cbor`. The script
   hash / address / datum / redeemer CBOR are pinned by golden vectors and cross-checked against the
   Aiken blueprint, but a live preprod `register → update → bump` has not yet been run (gated on
   funding a preprod wallet). Do not rely on Validator mode in production until that live run confirms
   the script-data hash + ex-unit budgeting end-to-end. The Aiken validators themselves are covered
   by `aiken check` (18 tests); Metadata mode and all reads are independent of this gap.

## Deterministic test artifacts

Auditors can reproduce these:

- `Tessera.Cryptography.Tests` — primitive correctness (33+ tests), incl. `AuditVectorsTests`:
  Pedersen determinism, additive homomorphism KAT, generator stability, range-proof verify,
  and tamper-evidence (flipping a proof/commitment byte fails verification).
- `Tessera.Chains.Evm.Tests/AbiContractParityTests` — every C# function selector is asserted
  equal to `keccak256(canonicalSignature)[:4]` **and** to the compiled contract ABI
  (`chains/evm/abi/*.json`), so the adapter cannot silently drift from the contract.
- `Tessera.Chains.Cardano.Tests` — script-address / policy-id derivation asserted equal to the Aiken
  blueprint (`aiken blueprint policy/address`); datum/redeemer + Conway/V3 CBOR (language views,
  map-form redeemers, script-data hash) golden vectors and round-trips; retry classification.
- `chains/evm` Hardhat suite + `chains/solana` Anchor tests + `chains/cardano` `aiken check`
  (18 on-chain tests) — on-chain behavior.
- End-to-end: `Tessera.Sdk.Tests/EndToEndFlowTests` and the Layer-3
  `ComplianceFlowTests` (onboard → policy → allowlist → revocation blocks transfers).

## Determinism notes

- Proving uses fresh randomness (`Scalar.Random()` for blinding/`alpha`/`rho`/`s`), so **proof
  bytes are not reproducible** — by design. **Verification is deterministic.** Pedersen
  commitments for fixed `(value, blinding)` are deterministic and round-trip via `Encode`/`Decode`.
- The Fiat–Shamir `Transcript` is the soundness anchor for non-interactivity; auditors should
  verify all public inputs (commitment `V`, `n`, `A`, `S`, `T1`, `T2`) are absorbed before each
  challenge is drawn.

## Deferred (write-down, to finish later)

- Engage an external cryptography auditor for `Tessera.Cryptography`.
- Rebuild + extend the Solana program for full cross-chain parity (limitation 2).
- Run the live Cardano preprod `register → update → bump` and finalize the Validator-mode tx
  builder — script-data hash + ex-unit budgeting (limitation 3).
- Reserve the `Sagynbaev.*` NuGet ID prefix and add `NUGET_USER` + the trusted-publishing policy on
  nuget.org (see README), then cut the first tagged release.
