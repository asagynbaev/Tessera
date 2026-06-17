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
| 6 | DID front-running / address-spoofing / binding a wallet to a victim DID | EVM `registerDid` requires a controller ECDSA signature bound to `(didHash, root, chainid, contract)`; wallet binding proves the address is controlled by the wallet key (`IWalletControlVerifier`) and consumes a single-use nonce (`INonceStore`); the authenticated `BindWalletAsync` overload additionally requires a DID-controller signature, so a wallet cannot be attached to another principal's DID | `EvmRegistrationSigner`, `IdentityRegistry.registerDid`, `DefaultWalletControlVerifier`, `DidService.BindWalletAsync` |
| 7 | Source ↔ subject impersonation | Sumsub requires applicant `externalUserId == subject DID`; X-Road binds the server-asserted national id from the response back to the request; both clients require https | `SumsubAttestationSource`, `XRoadAttestationSource` |
| 8 | Allowlist tamper | Restriction contract is agent/owner-gated; gateway only reflects decisions | `Allowlist.sol`, `EvmAllowlistGateway` |
| 9 | EVM write double-submission | Writes are single-shot; only reads are retried; the adapter checks `receipt.Status` on every write | `EvmChainAnchor.SendAsync`, `EvmRetry` |
| 10 | Range/predicate soundness | Bulletproofs range proof; **see Known limitations** | `RangeProof.Verify`, `PolicyEvaluation` |
| 11 | Side-channel: secret scalar leaked via timing | secp256k1 field/scalar/point arithmetic is constant-time (limb-based; fixed-iteration branchless `ScalarMul` over complete formulas); cross-checked against BouncyCastle | `FieldElement`, `Scalar`, `Point.ScalarMul`, `OracleCrossCheckTests` |
| 12 | Encoding malleability of commitments/proofs | non-canonical encodings (`x ≥ p`, `s ≥ n`) are rejected on deserialization, not reduced | `FieldElement.FromCanonicalBytes`, `Scalar.FromCanonicalBytes`, `Point.Decode` |
| 13 | Issuer trust-root substitution | the registry refuses to overwrite an existing issuer's public key via upsert | `EfCoreIssuerRegistry.RegisterAsync` |

## Addressed

> **Latest security-hardening pass.** A multi-round review (cryptography, on-chain, external-service,
> and IDOR/race methodology) closed the items below. **No Critical findings were identified in any
> round.** The fixes land across a coordinated set of branches merging into the next release —
> `fix/constant-time-secp256k1` (constant-time crypto + canonical encodings),
> `fix/security-audit-findings` (verification, DID/registry, source-plugin, chain-adapter fixes), and
> `chore/remove-legacy-crypto-duplicate` (legacy-duplicate removal).
>
> - **Constant-time secp256k1 (was Known limitation #1).** `FieldElement` / `Scalar` / `Point` are
>   reimplemented over fixed 4×64-bit limbs (no `BigInteger` in the hot path): pseudo-Mersenne
>   reduction mod p, Barrett reduction mod n, fixed-exponent inversion, and a fixed 256-iteration
>   double-and-add-ALWAYS `ScalarMul` with a branchless point-select over complete add/double
>   formulas — the loop length, per-bit work, and memory access no longer depend on the secret
>   scalar. Correctness is pinned by a NEW independent **BouncyCastle cross-check oracle**
>   (`OracleCrossCheckTests`), since self-consistent round-trip tests cannot catch a reduction bug.
>   *Residual:* still self-implemented managed code (JIT-level constant-timeness is not formally
>   guaranteed) and ~4–8× slower than the prior version — an external crypto audit is still
>   recommended; the legacy `Tessera.Crypto` duplicate stack that shipped a second, variable-time
>   copy of the secp256k1 arithmetic in the meta-package was removed.
> - **Canonical point/scalar encodings.** `Point.Decode` and the Bulletproofs scalar readers now
>   REJECT non-canonical encodings (`x ≥ p`, `s ≥ n`) via `FromCanonicalBytes` instead of reducing
>   them — closing byte-malleability of serialized commitments/proofs. The reducing `FromBytes` is
>   kept only where reduction is correct (Fiat–Shamir challenge squeeze, hash-to-curve).
> - **Controller-authenticated wallet binding (BOLA).** `DidService.BindWalletAsync` gained an
>   authenticated overload requiring a controller signature over `BuildWalletBindAuthChallenge`
>   (binds did + document version + wallet identity); the original overload is now documented
>   trusted-caller-only, so a wallet owner can no longer attach their wallet to another principal's
>   DID. The binding write also bumps the document `Version` (previously it broke the EF store's
>   optimistic-concurrency token and the resurrect-revoked guard).
> - **Issuer trust-root protection.** `EfCoreIssuerRegistry.RegisterAsync` refuses to overwrite an
>   already-registered issuer's public key via the upsert (key rotation must be explicit), closing a
>   trust-anchor substitution / issuer-impersonation path.
> - **Verification hardening.** Optional `MaxAttestationAge` / `RequireExpiry` cap non-expiring
>   credentials; the attestation algorithm tag is matched case-insensitively (empty tag rejected); a
>   cached `ExpectedAnchorRoot` is cross-checked against the live anchor (`anchor_root_stale`) so a
>   root rotation that removed an attestation cannot be replayed against a stale cache;
>   `PresentationVerifier` docs corrected to crypto-content-only (revocation/freshness live in the
>   SDK `Verifier`).
> - **Decoder & input hardening.** Length guards on the hand-rolled length-prefixed decoders
>   (`CredentialProof`, Borsh reader, the example transfer codec); channel handles are NFKC-normalised
>   + length-capped (homoglyph collisions); claim-policy matching reads values with the same
>   invariant formatter the issuer signs with; `Base58.Decode` is length-capped with a zero-byte fix.
> - **Source-plugin & chain-adapter hardening.** Esplora `BaseUrl` is validated (absolute http(s) +
>   host) to block scheme-based SSRF; the Bitcoin control challenge rejects line breaks in
>   subject/audience (canonical-string ambiguity); Cardano metadata-mode reads select the HIGHEST
>   authenticated revocation epoch (no lower-epoch republish can mask a bump); the in-memory nonce
>   store keeps an eviction margin past expiry; the reference `PermissionedToken` gains
>   `increase`/`decreaseAllowance` (ERC-20 approve race).

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

1. **`Tessera.Cryptography` is now constant-time but still self-implemented / not formally reviewed.**
   `Point.ScalarMul` and the field/scalar arithmetic are now constant-time (limb-based, branchless
   ladder — see §"Addressed"), and non-canonical encodings are rejected. It remains from-scratch
   MANAGED code, so an external cryptography audit is still recommended before protecting funds or
   high-value secrets, and JIT-level constant-timeness is not formally guaranteed. Two
   soundness/format items stay DEFERRED because their fixes are BREAKING wire-format changes (see
   §"Deferred"): the Fiat–Shamir `Transcript` does not length-prefix its labels (collision is not
   reachable with the current fixed label set, but it relies on caller discipline), and the Merkle
   tree duplicates the unpaired node (CVE-2012-2459 class, currently mitigated by leaf-hash
   rebinding). The claim-canonicalization wire format is culture-invariant but not yet type-tagged.
   The predicate binding and two-sided range proofs in §"Addressed" rely on the `Point`/`Scalar`
   arithmetic being correct — now cross-checked against BouncyCastle (`OracleCrossCheckTests`).
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

- `Tessera.Cryptography.Tests` — primitive correctness (51 tests), incl. `AuditVectorsTests`
  (Pedersen determinism, additive-homomorphism KAT, generator stability, range-proof verify,
  tamper-evidence) and `OracleCrossCheckTests` — an INDEPENDENT BouncyCastle cross-check of the
  field / scalar / point arithmetic (mul, add, sub, inverse, sqrt, `k·G`, `k·H`, point addition, the
  curve constants) on edge + pseudo-random inputs, plus canonical-encoding rejection. This external
  oracle catches self-consistent reduction bugs that round-trip self-tests cannot.
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

- Engage an external cryptography auditor for `Tessera.Cryptography` (now constant-time, but
  self-implemented). DEFERRED here because the fixes are BREAKING wire-format changes: length-prefix
  the Fiat–Shamir `Transcript` labels; adopt RFC-6962-style Merkle odd-node handling instead of
  duplication (CVE-2012-2459 class); and a type-tagged claim-canonicalization wire format
  (limitation 1).
- Solana issuer-registry hardening (needs `anchor build`): a `set_issuer_active` / reactivation
  instruction (today `deactivate_issuer` is irreversible because `register_issuer` uses `init`), and
  a zero / on-curve guard on the recorded `signing_key`.
- An authenticated controller-key-rotation path in `DidService` — today a compromised or lost
  controller key has no recovery ceremony beyond revoking with that same key.
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
