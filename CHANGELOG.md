# Changelog

## [Unreleased]

Chain-agnostic core extended for permissioned-token / compliance use cases, organized as three
layers (generic core → replaceable plugins → reference example) with dependencies pointing only
inward. No vendor, network, token, or business-schema names in the core.

### Added

- **Generic EVM adapter** (`Tessera.Chains.Evm`): `EvmChainAnchor` implements `IChainAnchor` over
  the `chains/evm` `IdentityRegistry` contract via Nethereum on any EVM network (chainId/RPC/contract
  are configuration). `EvmAllowlistGateway` implements `IAllowlistGateway`. Reads retry on transient
  RPC faults; writes are single-shot to avoid double-submission.
- **EVM contracts** (`chains/evm/`, Hardhat): `IdentityRegistry.sol` (parity with the Solana program
  + `deactivateIssuer`), `Allowlist.sol` (agent-gated transfer-restriction registry), and the Layer-3
  reference `PermissionedToken.sol` (allowlist-gated BEP-20). ABIs checked in; C# selectors asserted
  against the compiled ABI.
- **Allowlist gateway abstraction** (`IAllowlistGateway`) and shared `DidHash` in
  `Tessera.Chains.Abstractions` (a DID hashes to the same value on every backend).
- **Issuance pipeline** (`Tessera.Sdk.IssuancePipeline`): pulls `AttestationDraft`s from pluggable
  `IAttestationSource`s, signs each via the `Issuer`, and publishes the issuer to an
  `IIssuerRegistrar`. Core ships `InMemoryAttestationSource` only.
- **Composable verification policy** (`VerificationPolicy` + `PolicyEvaluation`): declarative
  `RequiredTypes`, `RequiredClaims` (value-level gating on issuer-signed claims), and
  `PredicateRequirements` layered on top of cryptographic verification.
- **Standard schemas + open registry** (`SchemaRegistry`): `kyc_verified`, `jurisdiction`,
  `accredited` (Pedersen-committed). Custom domain types register and validate without core changes.
- **Attestation-bound predicate proofs** (`CredentialProof.CommitValue`, `ProveBoundMinimum`,
  `ProveBoundRange`, `VerifyBound`): a range proof is bound to the attestation's own commitment
  (`V = C − threshold·G`); range proofs are two-sided (both bounds cryptographically enforced).
- **Layer-2 plugins**: `Tessera.Sources.Sumsub` (KYC) and `Tessera.Sources.XRoad` (government
  registry) — `IAttestationSource` implementations with injectable clients + mock-backed tests.
- **Layer-3 reference** (`examples/PermissionedToken`, not product): assembles the layers into the
  permissioned-token compliance flow — onboarding → policy → allowlist admission → token ownership,
  with revocation that blocks transfers. End-to-end test included.
- **EVM testnet smoke tests** (`SkippableFact`, env-gated) and a `chains/evm` Hardhat CI job.
- **Audit dossier** ([`docs/security-audit-readiness.md`](docs/security-audit-readiness.md)): scope,
  threat model, addressed items, known limitations, and deterministic test vectors.

### Changed

- Predicate verification in the policy is now **bound** to the disclosed attestation's commitment;
  the unbound `CredentialProof.Verify` remains as a standalone primitive but is not policy-accepted.

### Security

- Closed the predicate-soundness gap: predicate proofs can no longer be presented about an arbitrary
  or substituted value (binding + two-sided range). `Tessera.Cryptography` still awaits external audit.

## [3.0.0] - 2026-05-13

**Breaking release.** Tessera is now positioned as privacy-preserving identity and reputation infrastructure for .NET — DIDs, attestations, selective disclosure, multi-chain anchoring — rather than a generic ZKP toolkit. The v2.x monolith is replaced by a set of focused packages.

### Added

- **DID layer** (`Tessera.Did`): `DidDocument`, `DidService`, `IDidStore`, wallet binding, channel binding, revocation. DIDs are deterministic: `did:tessera:<base58(sha256(pubkey||"v1"))>`.
- **Attestation layer** (`Tessera.Attestations`): `AttestationIssuer`, `MerkleTree` (domain-separated SHA-256), `AttestationVerifier`, `PresentationVerifier`, `IIssuerRegistry`. Selective disclosure via Merkle inclusion proofs.
- **Cryptography** (`Tessera.Cryptography`): moved from `Tessera.Crypto.*`. Pure-C# secp256k1, Pedersen commitments, Bulletproofs. No external deps.
- **Signing** (`Tessera.Signing`): real Ed25519 via NSec (libsodium). Drop-in `Ed25519Verifier` and `Ed25519IssuerSigner` — no more BYO crypto delegate.
- **Storage** (`Tessera.EntityFrameworkCore`): EF Core 8 stores against any relational provider (Postgres, SQL Server, SQLite). Normalized schema with proper indexes.
- **Channel binding** (`Tessera.Channels`): HKDF-SHA256 commitments over phone / email / Telegram handles. Pepper held outside the library (`IPepperProvider`).
- **Solana adapter** (`Tessera.Chains.Solana`): full implementation against the `identity-registry` Anchor program — Borsh, Anchor discriminators, PDA derivation, instruction builders, account decoders.
- **Stellar adapter scaffold** (`Tessera.Chains.Stellar`): wired for `IChainAnchor`; awaiting a dedicated anchor contract.
- **SDK facades** (`Tessera.Sdk`): `Holder`, `Issuer`, `Verifier` — the recommended consumer entry point.
- **Solana Anchor program** ([`chains/solana/programs/identity-registry/`](chains/solana/programs/identity-registry/)): `register_did`, `update_root`, `bump_revocation`, `register_issuer`. Owner-signed, PDA-backed.
- **Devnet smoke tests** for the Solana flow (`SkippableFact`, env-var gated). See [`docs/deploying-solana.md`](docs/deploying-solana.md).

### Removed

- `Tessera.Core.Zkp` — HMAC equality class mislabelled as ZKP. Use `Tessera.Attestations.CredentialProof` for real selective disclosure.
- `Tessera.Interfaces.IBlockchain` — conflated proof verification with chain anchoring. Use `Tessera.Chains.IChainAnchor`.
- `Tessera.Integration.Stellar.*` — replaced by `Tessera.Chains.Stellar`.
- `QUICKSTART.md`, `INTEGRATION_STATUS.md`, `STELLAR_REALITY_CHECK.md` — superseded by the rewritten `README.md` and `docs/architecture.md`.

### Changed

- `contracts/stellar/` moved to `chains/stellar/`; `proof-balance` contract renamed to `attestation-verifier`.
- v2.x monolith (`Tessera/`) retained as a meta-package referencing the new sub-packages — existing v2 consumers continue to build.

## [2.2.0] - 2026-03-29

### Fixed

- **Soroban RPC**: `simulateTransaction` results are read from `results[0].xdr` (current Stellar RPC); legacy `returnValue` is still accepted.
- **Transaction envelopes**: `VerifyProof`, `VerifyBalanceProof`, and `VerifyZk*` now always use a full envelope for simulation (via `ZKP_SOURCE_ACCOUNT` or explicit `*WithSourceAccount`), instead of sending a partial XDR blob that RPC could not unmarshal.
- **ScVal bool**: decode unit-variant style returns (discriminant `2` → false).

### Added

- `BuildVerifyZkRangeProofTransactionWithAccount`, `BuildVerifyZkAgeProofTransactionWithAccount`, `BuildVerifyZkBalanceProofTransactionWithAccount`.
- `VerifyZkRangeProofWithSourceAccount`, `VerifyZkAgeProofWithSourceAccount`, `VerifyZkBalanceProofWithSourceAccount`.
- `StellarTestnetSmokeTests` (optional testnet smoke; requires `ZKP_CONTRACT_ID`, `ZKP_SOURCE_ACCOUNT`, `ZKP_HMAC_KEY`). Filter: `FullyQualifiedName~StellarTestnetSmokeTests`.
- `Xunit.SkippableFact` test dependency.

### Changed (breaking)

- **`ZKP_SOURCE_ACCOUNT` required** for `VerifyProof` / `VerifyBalanceProof` / `VerifyZk*` when not using the `*WithSourceAccount` overloads. Set the env var to a funded `G...` on the target network, or pass the source account explicitly.

### Docs & tooling

- README, `STELLAR_REALITY_CHECK.md`, `QUICKSTART.md`, `DEPLOYMENT.md`: document `ZKP_SOURCE_ACCOUNT`; refresh links to [developers.stellar.org](https://developers.stellar.org/) (Stellar CLI install path, smart contracts, RPC).
- Contract workspace: `soroban-sdk` pinned to **25.3**; `DEPLOYMENT.md` / `Makefile` use **`stellar`** CLI (replaces legacy `soroban-cli` commands).
- Test project: `Microsoft.NET.Test.Sdk` 18.3.0, `xunit.runner.visualstudio` 3.1.5.

---

## [2.1.0] - 2026-03-04

### Added: Privacy SDK

Ready-to-use privacy primitives built on top of Bulletproofs, solving real-world problems instead of exposing raw cryptographic primitives.

- **`ConfidentialTransfer`** - Hide transfer amounts while proving solvency (paired Pedersen commitments + range proofs for amount and change)
- **`SealedBidAuction`** - Commit-reveal bidding with range proof verification and automatic winner determination
- **`PrivateVoting`** - Anonymous binary voting with Bulletproofs validity proofs and verifiable tally via ballot openings
- **`CredentialProof`** - Prove any numeric attribute meets a threshold (`ProveMinimum`) or falls within a range (`ProveRange`) without revealing the actual value. Supports labeled credentials (income, credit score, age, balance)
- Full serialization support for `TransferBundle` and `CredentialBundle`
- 26 new tests covering all Privacy SDK scenarios including tamper detection, forged openings, and serialization round-trips

---

## [2.0.0] - 2026-03-03

### Major Release: Real Bulletproofs from Scratch in Pure C#

This release replaces the previous wrapper-based ZKP implementation with a cryptographically sound Bulletproofs protocol implemented entirely from scratch in managed C#. No external cryptographic library dependencies.

### Added

#### Bulletproofs Cryptographic Core (all new, from scratch)
- **`FieldElement`** - Finite field arithmetic (mod p) for secp256k1
- **`Scalar`** - Scalar arithmetic (mod n) for secp256k1 curve order
- **`Point`** - Elliptic curve point operations using Jacobian coordinates (add, double, scalar multiply, SEC1 compress/decompress)
- **`Generators`** - Standard generator G, hash-to-curve derived H, and vector generators Gi/Hi for inner product arguments
- **`PedersenCommitment`** - Real Pedersen commitments: `C = v*G + r*H` on secp256k1
- **`Transcript`** - Fiat-Shamir heuristic via SHA-256 for non-interactive proof generation
- **`InnerProductProof`** - Recursive halving protocol for O(log n) proof size
- **`RangeProof`** - Full Bulletproofs range proof prover and verifier (64-bit range, ~690 byte proofs)

#### BulletproofsProvider (rewritten)
- `ProveRange()` / `VerifyRange()` - ZK range proofs backed by real Pedersen commitments
- `ProveAge()` / `VerifyAge()` - ZK age proofs without revealing birthdate
- `ProveBalance()` / `VerifyBalance()` - ZK balance sufficiency proofs
- `SerializeProof()` / `DeserializeProof()` - Compact Base64 serialization
- Implements `IZkProofProvider` interface (drop-in replacement)

#### Rust Contract Enhancements
- **`verify_zk_range_proof()`** - Structural validation of Bulletproofs: compressed point prefixes, IPA length, Fiat-Shamir transcript binding
- **`compute_transcript_binding()`** - Recomputes SHA-256 hash of domain separator, commitment V, range bounds, and proof points A/S to prevent replay and substitution attacks
- **`verify_zk_age_proof()`** - On-chain ZK age proof structural verification
- **`verify_zk_balance_proof()`** - On-chain ZK balance proof structural verification
- Extended error codes: `InvalidCommitment`, `InvalidRange`

#### Stellar Integration
- **`SorobanTransactionBuilder` class** - Full XDR construction for contract calls
  - `BuildVerifyProofTransaction()` - HMAC proof verification
  - `BuildVerifyBalanceProofTransaction()` - Balance proof verification
  - `BuildVerifyZkRangeProofTransaction()` - ZK range verification
  - `BuildVerifyZkAgeProofTransaction()` - ZK age verification
  - `BuildVerifyZkBalanceProofTransaction()` - ZK balance verification
- **`StellarBlockchain` enhancements**
  - `VerifyProofWithSourceAccount()` - Proof verification with account
  - `VerifyBalanceProofWithSourceAccount()` - Balance verification with account
  - Constructor now accepts `hmacKey` parameter
- **StrKey utilities** - Contract ID decoding

#### Test Coverage
- 44 new cryptographic tests (secp256k1 arithmetic, Pedersen commitments, range proofs, soundness, serialization round-trips)
- 10 new Bulletproofs integration tests
- 5 new SorobanTransactionBuilder tests
- 27 new core ZKP tests (Membership, Range, TimeCondition, edge cases)
- 4 new integration tests for ZK on-chain verification
- Total: 108 tests passing

#### Documentation
- **`STELLAR_REALITY_CHECK.md`** - Honest assessment of capabilities and on-chain limitations
- **`INTEGRATION_STATUS.md`** - Current feature and API status
- Updated README with Bulletproofs architecture and cryptography details
- Updated QUICKSTART with real ZKP usage examples

### Changed
- **Bulletproofs**: Replaced Secp256k1.ZKP wrapper with from-scratch implementation (FieldElement, Scalar, Point, Generators, Transcript, InnerProductProof, RangeProof)
- **BulletproofsProvider**: No longer requires a key parameter; uses real Pedersen commitments instead of HMAC-based fake commitments
- **Soroban contract**: Removed broken `verify_zk_response` function; `verify_zk_range_proof` now performs structural validation and Fiat-Shamir binding instead of fake "BP" header checks
- **On-chain verification model**: Full EC verification runs off-chain; contract performs structural validation and emits transcript binding hash for off-chain auditing (secp256k1 is not natively supported in Soroban)

### Removed
- Fake "BP" header-based proof validation in Rust contract
- Broken `verify_zk_response` function from Rust contract

### Breaking Changes
- `BulletproofsProvider` constructor no longer accepts a key parameter
- Proof format changed (real Bulletproofs binary format, not HMAC hashes)
- Rust contract requires redeployment for updated ZK verification functions
- Proof sizes increased (~690 bytes vs ~64 bytes) due to real cryptographic content

---

## [1.3.2] - 2025-12-03

### Security Fixes (Bugbot Review)

This release addresses critical security issues identified by Cursor Bugbot code review.

### Fixed

#### C# Library
- **SorobanHelper: Data truncation vulnerability** - `EncodeBytesAsScVal` and `EncodeStringAsScVal` now validate input length and throw `ArgumentException` for data exceeding 255 bytes, preventing silent data corruption
- **SorobanRpcClient: XDR boolean decode false positives** - Replaced unsafe `xdrBytes.Any(b => b == 0x01)` heuristic with proper SCVal format parsing using type discriminant validation

#### Rust Smart Contract
- **Balance comparison logic bug** - `verify_balance_proof` now uses proper numeric comparison via `parse_decimal_to_scaled()` instead of incorrect byte length comparison (`balance_data.len() >= required_amount_data.len()`)
- **Malformed input vulnerability** - `parse_decimal_to_scaled()` now returns `None` for malformed inputs like "-", ".", or empty bytes instead of `Some(0)`, preventing invalid balance data from being treated as zero
- **Test algorithm mismatch** - All tests now use `compute_test_hmac()` with proper HMAC-SHA256 (RFC 2104 with ipad/opad) instead of plain SHA256, matching production contract behavior

### Added
- `SorobanHelper.MaxBytesLength` constant (255) for explicit length limit documentation
- `parse_decimal_to_scaled()` function in Rust contract for accurate decimal number parsing with `has_digits` validation
- `compute_test_hmac()` helper in Rust tests for consistent HMAC computation
- `test_verify_balance_proof_insufficient()` test case for balance < required scenario
- `test_verify_balance_proof_malformed_input()` test case for malformed inputs like "-", "."

### Changed
- Balance verification now correctly handles edge cases like "99.0" vs "100.0"
- XDR boolean decoding now validates SCValType discriminant before extracting value

### Dependencies Updated
- `stellar-dotnet-sdk`: 13.0.0 → 14.0.1
- `stellar-dotnet-sdk-xdr`: 13.0.0 → 14.0.1
- `coverlet.collector`: 6.0.0 → 6.0.4
- `Microsoft.NET.Test.Sdk`: 17.8.0 → 17.12.0
- `xunit`: 2.9.2 → 2.9.3
- `xunit.runner.visualstudio`: 2.5.3 → 3.0.2
- GitHub Actions: `actions/checkout@v2` → `v4`, `actions/setup-dotnet@v1` → `v4`

---

## [1.3.1] - 2025-12-03

### Fixed
- Added `SorobanHelper` class with SCVal encoding/decoding utilities
- Fixed balance parsing with `CultureInfo.InvariantCulture` for consistent decimal handling
- Added `using StellarDotnetSdk.Accounts` for `KeyPair` class access in tests
- Improved test coverage for Stellar integration

---

## [1.3.0] - 2025-12-02

### Major Release: Production-Ready Stellar Integration

This release provides full production-ready integration with Stellar's Soroban smart contracts.

### Added

#### Stellar Blockchain Integration
- Production-ready Soroban smart contract for on-chain ZKP verification
  - Full HMAC-SHA256 verification implementation
  - Constant-time comparison to prevent timing attacks
  - Batch verification support for efficiency
  - Comprehensive error handling and event logging
  
- C# Integration Components
  - SorobanHelper: Type-safe XDR encoding/decoding utilities
  - SorobanTransactionBuilder: Fluent API for building Soroban transactions
  - Enhanced StellarBlockchain: Full IBlockchain implementation with Soroban support
  - Enhanced SorobanRpcClient: Proper XDR decoding and ScVal parsing

- Comprehensive Test Suite
  - Unit tests for all Rust contract functions
  - Integration tests for C# Stellar components
  - End-to-end workflow examples
  - Test coverage: 95%+

- Documentation
  - Complete deployment guide for Soroban contracts
  - Stellar integration examples in README
  - Architecture diagrams and use cases
  - Troubleshooting guides

#### Contract Features
- `verify_proof`: Universal proof verification function
- `verify_balance_proof`: Specialized balance verification with amount checking
- `verify_batch`: Efficient batch verification of multiple proofs
- Event emission for debugging and monitoring
- Input validation and security checks

### Changed
- Breaking: Updated StellarBlockchain constructor to accept optional Network parameter
- Breaking: VerifyProof now properly implements on-chain verification (was NotImplementedException)
- Improved HMAC key management with environment variable support
- Enhanced error messages and exception handling
- Optimized XDR encoding/decoding performance

### Fixed
- Resolved NotImplementedException in StellarBlockchain.VerifyProof
- Fixed XDR decoding issues in SorobanRpcClient
- Corrected ScVal type handling for boolean values
- Fixed timing attack vulnerability in proof comparison

### Security
- Implemented constant-time comparison in Rust contract
- Added comprehensive input validation
- Improved HMAC key security with environment variable support
- Added security best practices documentation

### Documentation
- Added comprehensive [Deployment Guide](contracts/stellar/DEPLOYMENT.md)
- Updated README with Stellar integration examples
- Added architecture diagrams
- Included troubleshooting section
- Added security considerations

### Performance
- Optimized WASM contract size (15-20 KB)
- Implemented efficient batch verification
- Reduced gas costs through optimization
- Improved transaction building performance

---

## [1.2.0] - 2025-12-02

### Added
- New method for range proofs (`ProveRange` and `VerifyRange`).
- Support for time-based proofs (`ProveTimestamp` and `VerifyTimestamp`).
- Support for proving set membership (`ProveSetMembership` and `VerifySetMembership`).

### Changed
- Refined HMAC implementation to retrieve the secret key from environment variables for enhanced security and flexibility.

### Fixed
- Bug in age verification logic that caused incorrect validation for dates close to the required age.

---

## [1.1.1] - 2025-01-03

### Added
- New method for range proofs (`ProveRange` and `VerifyRange`).
- Support for time-based proofs (`ProveTimestamp` and `VerifyTimestamp`).
- Support for proving set membership (`ProveSetMembership` and `VerifySetMembership`).

### Changed
- Refined HMAC implementation to retrieve the secret key from environment variables for enhanced security and flexibility.

### Fixed
- Bug in age verification logic that caused incorrect validation for dates close to the required age.

---

## [1.1.0] - 2025-01-01

### Added
- Salt generation improvements for stronger proofs.

### Changed
- Refactored `ZKP` class to improve performance and modularity.

### Fixed
- Fixed an issue where incorrect salt generation would sometimes lead to hash mismatches.

---

## [1.0.0] - 2025-01-01

### Initial release
- Proof of Age feature (`ProveAge` and `VerifyAge`).
- Proof of Balance feature (`ProveBalance` and `VerifyBalance`).