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
| 2 | Stolen presentation replayed by a non-holder | Presentation is AUTHENTICATED: the binding carries a 32-byte `HolderPublicKey` that must re-derive to `Holder` plus an Ed25519 `HolderSignature` over the canonical `PresentationChallenge` | `PresentationVerifier.VerifyAsync` (holder-auth block), `PresentationChallenge.Compute` |
| 3 | Replay across verifiers / sessions / chains / time | Challenge binds `{holder, verifier, session_nonce, as_of_epoch, chain, created_at, leaf_hashes}`; freshness window (`MaxPresentationAge`/`MaxClockSkew`) always enforced | `Verifier.VerifyPresentationAsync` steps 1–3, 6 |
| 4 | Stale presentation after revocation | Revocation is FAIL-CLOSED: with a chain anchor reachable, an epoch older than the chain's current epoch is always rejected; `RequireCurrentRevocationEpoch` demands a reachable anchor and EXACT epoch match | `Verifier.VerifyPresentationAsync` step 5; `AnchorState.RevocationEpoch` |
| 5 | Issuer key compromise | Per-issuer `active` flag + `deactivateIssuer` (EVM) / `deactivate_issuer` (Solana) + short attestation expiries | issuer registry read/write |
| 6 | DID front-running / wallet- and address-spoofing | EVM `registerDid` requires a controller ECDSA signature bound to `(didHash, root, chainid, contract)`; wallet binding proves the address is controlled by the wallet key (`IWalletControlVerifier`) and consumes a single-use nonce (`INonceStore`) | `EvmRegistrationSigner`, `IdentityRegistry.registerDid`, `DefaultWalletControlVerifier`, `DidService.BindWalletAsync` |
| 7 | Source ↔ subject impersonation | Sumsub requires applicant `externalUserId == subject DID`; X-Road binds the server-asserted national id from the response back to the request; both clients require https | `SumsubAttestationSource`, `XRoadAttestationSource` |
| 8 | Allowlist tamper | Restriction contract is agent/owner-gated; gateway only reflects decisions | `Allowlist.sol`, `EvmAllowlistGateway` |
| 9 | EVM write double-submission | Writes are single-shot; only reads are retried; the adapter checks `receipt.Status` on every write | `EvmChainAnchor.SendAsync`, `EvmRetry` |
| 10 | Range/predicate soundness | Bulletproofs range proof; **see Known limitations** | `RangeProof.Verify`, `PolicyEvaluation` |

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
- **Holder authentication (was: presenter not proven).** A presentation no longer just *claims* a
  holder DID — it proves control of it. `PresentationBinding` carries a required 32-byte
  `HolderPublicKey` (the Ed25519 controller key) and a `HolderSignature` over the canonical
  `PresentationChallenge` (which binds `{holder, verifier, session_nonce, as_of_epoch, chain,
  created_at, disclosed leaf hashes}`). `PresentationVerifier.VerifyAsync` confirms
  `DidId.FromControllerKey(HolderPublicKey) == Holder` and that the signature verifies against that
  key before any other check. Build via `Holder.BuildSignedPresentation(...)` (or
  `BuildPresentationChallenge` + `BuildPresentation(..., holderSignature, createdAt)` for hardware
  signers); `PresentationVerifier`'s constructor is now `(AttestationVerifier, ISignatureVerifier)`.
- **Fail-closed revocation + presentation freshness (was: opt-in / silently skipped).** When a chain
  anchor is reachable, the verifier unconditionally rejects a presentation bound to an epoch older
  than the chain's current epoch; `RequireCurrentRevocationEpoch` further demands a reachable anchor
  and an EXACT epoch match (throws if no anchor is configured — `ExpectedAnchorRoot` no longer
  silently bypasses revocation). A freshness window (`MaxPresentationAge` default 5 min,
  `MaxClockSkew` default 1 min) is always enforced against the holder-signed `CreatedAt`.
  `DidService.GetActiveAsync` enforces `Revoked` on resolve.
- **DID / wallet / source binding.** Wallet binding proves the bound address is controlled by the
  wallet key: `IWalletControlVerifier` (default `DefaultWalletControlVerifier` checks Solana
  `base58(pubkey)` and fails closed on every other chain); `BuildWalletChallenge` binds the wallet
  pubkey; binding nonces are single-use via an `INonceStore`. Channel binding has authenticated
  add/remove overloads. Sumsub requires applicant `externalUserId == subject DID`; X-Road binds the
  server-asserted national id from the response to the request; both HTTP clients reject non-https.
  Pepper providers reject all-zero / grossly low-entropy peppers (`IPepperProvider.Validate`).
- **On-chain anchor authentication (EVM live; others source-level).** EVM
  `IdentityRegistry.registerDid(bytes32 didHash, bytes32 attestationRoot, address controller, bytes signature)`
  requires a controller ECDSA signature over `keccak256(abi.encode(didHash, root, block.chainid,
  address(this)))` (EIP-191), recovered on-chain with low-S enforced; the C# `EvmChainAnchor` signs
  it (`EvmRegistrationSigner`) and checks `receipt.Status` on every write. The full EVM path —
  deploy `IdentityRegistry`, sign + submit `registerDid`/`updateRoot`/`bumpRevocation`, read back —
  is now exercised end-to-end against a live (local Hardhat) chain by the `evm-smoke` CI job. That
  live run caught and fixed a real bug: `EvmRegistrationSigner` built its EIP-191 prefix from the
  literal `"\x19Ethereum…"`, but C#'s variable-length `\x` escape consumed the following `E`
  (`\x19E` → `U+019E`), corrupting the digest so every live `registerDid` reverted
  `InvalidSignature`. Nethereum recovered the bad signature self-consistently (the signer unit test
  passed), so only the on-chain `ecrecover` — i.e. the live test — exposed it. Regression tests now
  pin the registration struct hash to Solidity `abi.encode` and assert EIP-2 low-S. The Solana program gates
  `register_issuer` / `deactivate_issuer` behind a `RegistryConfig` PDA + `initialize(admin)`
  (`has_one = admin`); the adapter fails closed on RPC errors and verifies the account owner program
  + Anchor discriminator. Cardano Metadata-mode reads authenticate the controller (tx input address
  + an embedded Ed25519 signature over `did_hash‖root‖epoch`, `MetadataAttestation.Verify`); the
  Aiken `issuer_registry` is parameterized by an `admin` VKH that must sign. Stellar Soroban
  `attestation-verifier` was redesigned to Ed25519 public-key verification with admin
  `initialize`/`set_issuer` — the HMAC secret is no longer an invocation argument.
  (Anchor / Aiken / Soroban edits are source-level; see Known limitations for the build+redeploy gap.)

## Known limitations (do not ship to high-assurance use without addressing)

1. **`Tessera.Cryptography` is not constant-time / not formally reviewed.** Self-implemented
   secp256k1 + Bulletproofs. No claim of side-channel resistance; needs an external crypto audit
   before protecting funds or high-value secrets. Concretely DEFERRED to that audit:
   `Point.ScalarMul` is still a branch-on-bit double-and-add (NOT constant-time — leaks the scalar
   to SPA/timing), and the claim-canonicalization wire format is length-prefixed but not yet
   type-tagged. Claim canonicalization is now culture-invariant. The predicate binding and two-sided
   range proofs in §"Addressed" rely on the `Point`/`Scalar` arithmetic being correct.
2. **Solana/Cardano contract hardening is source-level; those live networks need a build + redeploy.**
   The admin/governance gates and authentication described in §"Addressed" land in the contract
   sources but only take effect once each toolchain compiles and the artifact is redeployed: the
   Solana `RegistryConfig` + `initialize`/`deactivate_issuer` program needs `anchor build`; the Aiken
   `issuer_registry` admin-VKH gate needs `aiken build` + a regenerated `plutus.json`. These toolchains
   are not in the build environment, so a previously-deployed registry will not enforce the new gates
   until upgraded; the C# adapters already speak those hardened instruction layouts.
   **EVM is no longer in this gap:** the `evm-smoke` CI job runs `hardhat compile`, deploys the
   contracts, and exercises the `EvmChainAnchor` against a live (local) chain on every push — the
   `registerDid` controller signature is verified end-to-end on-chain (which is exactly how the EIP-191
   signer bug in §"Addressed" was caught and is now regression-guarded). The only residual EVM gap is
   that a *public* registry deployed before the v3.2.0 ABI change must be redeployed to enforce the
   controller-signature gate; adapter↔contract correctness itself is now proven live, not assumed.
3. **Stellar Soroban workspace requires a newer Rust than the build environment.** The redesigned
   Ed25519 `attestation-verifier` (admin `initialize`/`set_issuer`, no HMAC argument) targets
   `soroban-sdk` 26.1 / `wasm32v1-none`, which needs rustc ≥ 1.84; the contract is source-complete
   but cannot be compiled/redeployed here. Do not assume the on-chain verifier reflects the new
   design until it is rebuilt and redeployed.
4. **Cardano Validator-mode transaction assembly is offline-verified but not yet validated on-chain.**
   Because CardanoSharp 5.1.0 predates Plutus V3, the Conway / V3 transaction (script-data hash,
   execution-unit budgeting, witness layout) is hand-built with `System.Formats.Cbor`. The script
   hash / address / datum / redeemer CBOR are pinned by golden vectors and cross-checked against the
   Aiken blueprint, but a live preprod `register → update → bump` has not yet been run (gated on
   funding a preprod wallet). Do not rely on Validator mode in production until that live run confirms
   the script-data hash + ex-unit budgeting end-to-end. The Aiken validators themselves are covered
   by `aiken check`; Metadata mode and all reads are independent of this gap. (Metadata-mode reads
   now authenticate the controller — see §"Addressed".)

## Deterministic test artifacts

Auditors can reproduce these:

- `Tessera.Cryptography.Tests` — primitive correctness (33+ tests), incl. `AuditVectorsTests`:
  Pedersen determinism, additive homomorphism KAT, generator stability, range-proof verify,
  and tamper-evidence (flipping a proof/commitment byte fails verification).
- `Tessera.Chains.Evm.Tests/AbiContractParityTests` — every C# function selector is asserted
  equal to `keccak256(canonicalSignature)[:4]` **and** to the compiled contract ABI
  (`chains/evm/abi/*.json`), so the adapter cannot silently drift from the contract.
  `EvmRegistrationSignerTests` pins the `registerDid` struct hash to Solidity `abi.encode` (a
  known-good ethers vector) and asserts EIP-2 low-S — the gap that let the EIP-191 signer bug ship.
- `evm-smoke` CI job — spins up a local Hardhat node, deploys `IdentityRegistry` + `Allowlist`, and
  runs the `EvmChainAnchor` / `EvmAllowlistGateway` smoke tests against it, so the live anchor path
  (sign → submit → read-back, plus allowlist add/revoke) is exercised on every push rather than
  silently skipping. Reproducible locally via `chains/evm/scripts/deploy-local.js`.
- `Tessera.Chains.Cardano.Tests` — script-address / policy-id derivation asserted equal to the Aiken
  blueprint (`aiken blueprint policy/address`); datum/redeemer + Conway/V3 CBOR (language views,
  map-form redeemers, script-data hash) golden vectors and round-trips; retry classification.
- `chains/evm` Hardhat suite + `chains/solana` Anchor tests + `chains/cardano` `aiken check`
  (20 on-chain tests) — on-chain behavior.
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

- Engage an external cryptography auditor for `Tessera.Cryptography`; in scope for that audit:
  constant-time `Point.ScalarMul` (SPA/timing hardening) and a type-tagged claim-canonicalization
  wire format (limitation 1).
- Build + redeploy the hardened Solana/Cardano contracts so the new gates take effect on live
  networks: `anchor build` (Solana `RegistryConfig` / `deactivate_issuer`), `aiken build` +
  regenerated `plutus.json` (Aiken `issuer_registry` admin gate) (limitation 2). EVM is compiled,
  deployed, and live-tested in CI (`evm-smoke`); only a public registry predating the v3.2.0 ABI
  change needs redeploy.
- Compile + redeploy the Stellar Soroban `attestation-verifier` on a toolchain with rustc ≥ 1.84
  (limitation 3).
- Run the live Cardano preprod `register → update → bump` and finalize the Validator-mode tx
  builder — script-data hash + ex-unit budgeting (limitation 4).
- Reserve the `Sagynbaev.*` NuGet ID prefix and add `NUGET_USER` + the trusted-publishing policy on
  nuget.org (see README), then cut the first tagged release.
