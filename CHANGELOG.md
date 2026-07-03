# Changelog

## [Unreleased]

## [5.0.0] - 2026-07-03

> 🔒 **Security-hardening round 2 (breaking).** A second full pre-production audit — cryptography,
> attestation/proof verification, chain adapters + contracts, and external sources — followed by
> adversarial re-verification of every fix. **No Critical findings and no committed secrets.** The
> headline is a **cross-attribute predicate-substitution fix** (a holder could satisfy an "income ≥ X"
> requirement with a *different* attestation's commitment) and **surfacing the on-chain anchor owner**
> so verifiers can finally detect anchor substitution / squatting. Major version because several
> defaults now **fail closed** and one constructor signature changed (see Breaking). Still
> self-implemented managed crypto — an external cryptographic audit remains recommended.

### ⚠ Breaking

- **Predicate requirements bind to the issuer-signed attestation `Type`.** `PredicateRequirement`
  gains a required `Type`; a predicate whose `Type` is `null` now **fails closed**, and a bound proof
  is matched only against the commitment of a disclosed attestation whose issuer-signed `Type`
  matches (the holder-set `Label` is no longer authoritative for attribute identity). Existing
  predicate policies must set `Type` to the source attestation type (e.g. `AttestationTypes.Accredited`).
  Closes cross-attribute substitution (a reputation-score commitment satisfying an income predicate).
- **Offline / cached-root verification no longer skips revocation silently.** With no live
  `ChainAnchor` and no `VerificationPolicy.ExpectedRevocationEpoch`, verification now returns
  `revocation_unverifiable` instead of passing. Offline callers must supply a trusted
  `ExpectedRevocationEpoch`.
- **`BitcoinControlVerifier` requires an explicit `INonceStore`.** The first constructor parameter is
  now mandatory (was an implicit process-local `InMemoryNonceStore`), so a non-durable replay store is
  a visible choice at the call site. Single-node/test callers pass `new InMemoryNonceStore()`;
  production passes a shared, durable store.
- **Bitcoin balance facts require confirmation depth.** `BitcoinSourceOptions.MinConfirmations`
  (default **6**) — shallow UTXOs no longer count toward `btc_balance` / `btc_hodl_age`, blocking a
  flash-fund-then-move balance attestation. Set it to `1` to restore the prior behaviour.
- **New `issuers.Version` column.** The EF `issuers` table gains an optimistic-concurrency token;
  consumers must migrate (`dotnet ef migrations add …`) the `Version INTEGER NOT NULL DEFAULT 1` column
  before deploying.
- **`CredentialProof.Verify` is deprecated.** Renamed to `VerifyAgainstOwnCommitment` (it proves
  nothing about any attestation — a footgun); `Verify` remains as an `[Obsolete]` forwarding alias.
- **Channel handles are length-capped *after* NFKC.** A handle whose normalized form exceeds the cap
  is now rejected (previously only the raw input was capped). No effect on ordinary handles.

### Security

- **Cross-attribute predicate substitution closed (High).** See Breaking — the predicate's attribute
  identity now comes from issuer-signed canonical data, not the holder-chosen bundle label.
- **On-chain anchor owner is now surfaced and checkable.** `AnchorState.Owner` carries the chain-native
  owner (EVM EIP-55 address, Solana base58 pubkey, Cardano controller-key hex, Stellar account id) on
  all four adapters, and `VerificationPolicy.ExpectedAnchorOwner` + the verifier's owner-check reject a
  substituted / squatted anchor (`anchor_owner_mismatch`), failing closed when the owner cannot be
  observed (`anchor_owner_unverifiable`). This is the off-chain defense the Solana/Cardano designs
  always assumed but no consumer could perform, since the owner was previously discarded.
- **Cardano validator-mode reads fail closed on conflicting anchors.** The adapter no longer returns an
  arbitrary `utxos[0]` when more than one `(policyId, did_hash)` thread token exists; it selects the
  UTxO whose datum controller matches the expected controller and throws on an unresolvable conflict.
- **Bulletproofs prover is now constant-time end to end.** Secret-dependent point accumulation in the
  range proof and inner-product argument uses the branchless complete-addition `Point.AddCt` (a 0 bit
  no longer short-circuits on the point at infinity), `DecomposeBits` reads the witness from the
  scalar's fixed 4-limb representation with the range check moved after a fixed-length scan (no
  `BigInteger`, no data-dependent throw), the bit→scalar select is branchless, and
  `PedersenCommitment.Commit` uses `AddCt` too. Proof bytes and verification are **unchanged** (pinned
  by the BouncyCastle oracle + round-trip tests).
- **Single-use presentation nonces.** An optional `VerifierOptions.NonceStore` atomically consumes the
  `(holder, session nonce)` pair after the holder signature is verified (`presentation_replayed` on a
  replay). A configured store also rejects an empty session nonce (`session_nonce_required`) so enabling
  it is by itself sufficient replay protection.
- **DID-level revocation on the read path.** An optional `VerifierOptions.DidStore` fails closed when
  the holder (`holder_did_revoked`) or any disclosed issuer (`issuer_did_revoked`) DID is revoked.
- **Source & persistence hardening.** Custom auth headers no longer follow HTTP redirects (Sumsub
  `X-App-Token` / X-Road `X-Road-Client` leak — `AllowAutoRedirect = false` handler factories); the
  `issuers` trust root gets an optimistic-concurrency token with retry, closing a lost-deactivation
  race.

### Added

- `AnchorState.Owner`; `VerificationPolicy.ExpectedAnchorOwner` / `ExpectedRevocationEpoch`;
  `PredicateRequirement.Type`; `VerifierOptions.NonceStore` / `DidStore`;
  `BitcoinSourceOptions.MinConfirmations`; `SumsubHttpClient.CreateHardenedHandler()` /
  `CreateHardenedHttpClient()`, `XRoadHttpClient.CreateHardenedHandler()`;
  `CredentialProof.VerifyAgainstOwnCommitment`; `Point.AddCt` (now public).
- New verification failure reasons: `anchor_owner_mismatch`, `anchor_owner_unverifiable`,
  `revocation_unverifiable`, `holder_did_revoked`, `issuer_did_revoked`, `presentation_replayed`,
  `session_nonce_required`.

### Known limitations (tracked; some require an on-chain redeploy)

- **Solana registration squatting is a DoS, not a substitution risk.** The `owner` is verified
  off-chain via `ExpectedAnchorOwner` (substitution is caught), but the per-`did_hash` PDA can still be
  occupied by a front-runner, leaving that DID unanchorable on Solana until a controller-signature-gated
  registration or admin-reclaim path is added — a **contract change requiring redeploy** (the live
  devnet program is unchanged in this release).
- **Stellar `attestation-verifier` message framing.** `verify_proof` / `verify_balance_proof` sign a
  bare `data ‖ salt` concatenation without a length prefix (boundary-shift malleability). The .NET
  adapter does not call these paths; a length-prefixed framing is a **Soroban contract change requiring
  redeploy**. Tracked in `docs/security-audit-readiness.md`.
- **The anchor owner-check is opt-in.** It only enforces when `ExpectedAnchorOwner` is set — set it on
  chains without globally-unique anchor keys (Solana, Cardano). Pin the owner in exactly the adapter's
  emitted format (EVM is EIP-55 checksummed; the compare is case-sensitive). Cardano metadata-mode owner
  is controller-scoped (usable for the adapter's own DIDs, not third-party substitution detection), a
  validator-mode conflict fails closed (a third party can grief reads of a squatted `did_hash`), and the
  Stellar owner read is not yet covered by a live-testnet assertion.

## [4.1.0] - 2026-06-24

> 🌐 **All four chain anchors are now validated live on public testnets** — the full adapter ↔
> on-chain smoke suite (register / update-root / bump-revocation / reads) passes against a deployed
> anchor on each, not just local nodes: **Solana** devnet (5/5), **EVM** BNB testnet (6/6),
> **Cardano** preprod (5/5), **Stellar** testnet (5/5).

### Added

- **Stellar anchor is feature-complete.** New `attestation-anchor` Soroban contract (`anchor_root` /
  `bump_revocation` / `get_anchor`, mirroring the Solana/EVM data model) and a fully-wired
  `StellarChainAnchor` (simulate → assemble → sign → send → confirm for writes; simulation for reads)
  with env-gated testnet smoke tests. Replaces the previous scaffold that threw `NotImplementedException`.
- **EVM `deploy.js` now deploys both `IdentityRegistry` + `Allowlist`** and writes `deployed.<network>.json`,
  so the testnet smoke suite (anchor + allowlist) runs from one deploy.

### Fixed

- **EVM writes work on BNB Chain.** Added legacy (type-0) gas pricing (auto-enabled for chainId 56/97,
  which reject zero-priority-fee EIP-1559 txs) and a 1.5× buffer on gas estimates (a bare estimate can
  run out of gas under public-RPC read-after-write lag). Also pins a local monotonic nonce for
  back-to-back writes. `EvmChainAnchorOptions.UseLegacyGasPricing`.
- **Cardano back-to-back writes survive provider lag.** The adapter now rebuilds against fresh UTxOs and
  resubmits when a write hits an already-spent input (Blockfrost's address-UTxO index lags confirmation).

### Changed

- **`StellarChainAnchor` now takes a `StellarAnchorOptions`** (RPC URL, contract id, signing-key seed,
  network passphrase) instead of the previous positional constructor. This replaces the v4.0.0 *scaffold*
  constructor — which could not anchor (all writes threw `NotImplementedException`) and took only a public
  source-account id with no signing key — so it is treated as completing a non-functional surface rather
  than a breaking API change. Any caller of the old constructor switches to the options object.

## [4.0.0] - 2026-06-17

> 🔒 **The security-hardening release.** A multi-round security audit — cryptography, on-chain
> contracts, external-service plugins, and IDOR / race-condition methodology — swept the whole stack
> and closed **every finding it surfaced**, with **no Critical issues in any round**. Headline:
> `Tessera.Cryptography` is now **constant-time**, pinned against an independent **BouncyCastle**
> cross-check oracle. Major version because the legacy duplicate crypto stack is removed from the
> published meta-package (see Breaking).

### ⚠ Breaking

- **Removed the legacy `Tessera.Crypto.*` / `Tessera.Security.*` duplicate.** The `Sagynbaev.Tessera`
  meta-package shipped a *second, variable-time* copy of the secp256k1 / Bulletproofs / Pedersen
  primitives (left over from the v3 split) alongside `Tessera.Cryptography`. It is gone — use
  `Tessera.Cryptography` (`…Secp256k1`, `…Bulletproofs`, `PedersenCommitment`). The meta-package is
  now pure (sub-package references only, no compiled source) and the legacy `Tessera.Tests` project
  was retired with it.
- **Channel-handle normalisation now applies Unicode NFKC.** Commitments for **non-ASCII** channel
  handles change (ASCII handles are unaffected); the normaliser is part of the on-disk format, so
  re-derive any stored non-ASCII channel commitments. Closes a homoglyph / confusable collision where
  two visually-identical handles produced different commitments.
- **Stricter input rejection.** Non-canonical point/scalar encodings (`x ≥ p`, `s ≥ n`) are now
  REJECTED instead of silently reduced; `EfCoreIssuerRegistry.RegisterAsync` refuses to overwrite an
  existing issuer's public key; `EsploraBitcoinProvider` rejects a non-http(s) `BaseUrl`. Each closes
  a real issue but may reject an input a prior version accepted.

### Security

- **Constant-time secp256k1.** `FieldElement` / `Scalar` / `Point` are reimplemented over fixed
  4×64-bit limbs (no `BigInteger` in the hot path): pseudo-Mersenne reduction mod p, Barrett
  reduction mod n, fixed-exponent inversion, and a fixed 256-iteration double-and-add-**always**
  `ScalarMul` with a branchless point-select over complete add/double formulas. The loop length,
  per-bit work, and memory access no longer depend on the secret scalar, so blinding factors and
  range-proof witnesses no longer leak through timing. (Still self-implemented managed code — an
  external cryptography audit remains recommended; see `docs/security-audit-readiness.md`.)
- **Independent BouncyCastle cross-check oracle** (`OracleCrossCheckTests`) pins the field / scalar /
  point arithmetic — mul, add, sub, inverse, sqrt, `k·G`, `k·H`, point addition, the curve constants —
  against BouncyCastle on edge + pseudo-random inputs. Round-trip self-tests cannot catch a
  self-consistent reduction bug; the external oracle can.
- **No encoding malleability.** Point and Bulletproofs-scalar deserialisation rejects non-canonical
  encodings, so a commitment / proof has exactly one valid byte form.
- **Controller-authenticated wallet binding (BOLA).** `DidService.BindWalletAsync` gains an
  authenticated overload requiring a DID-controller signature (`BuildWalletBindAuthChallenge`), so a
  wallet owner can no longer attach their wallet to another principal's DID document.
- **Issuer trust-root protection.** The issuer registry refuses to overwrite an existing issuer's
  public key via upsert — closing a trust-anchor-substitution / issuer-impersonation path.
- **SSRF / canonicalisation / replay hardening.** Esplora `BaseUrl` is validated (blocks scheme-based
  SSRF); the Bitcoin control challenge rejects line breaks in subject/audience; Cardano metadata-mode
  reads select the **highest** authenticated revocation epoch (no lower-epoch republish can mask a
  bump); the in-memory nonce store keeps an eviction margin past expiry; a cached `ExpectedAnchorRoot`
  is cross-checked against the live anchor (`anchor_root_stale`).

### Added

- `FieldElement.FromCanonicalBytes` / `Scalar.FromCanonicalBytes` — reject non-canonical encodings on
  deserialisation (the reducing `FromBytes` is kept for the Fiat–Shamir challenge squeeze and
  hash-to-curve, where reduction is correct).
- Authenticated `BindWalletAsync(did, request, controllerSignature)` + `BuildWalletBindAuthChallenge`.
- `AttestationVerifier` / `VerifierOptions`: optional `MaxAttestationAge` and `RequireExpiry` to cap
  credentials whose issuer set no `ExpiresAt`.
- Reference `PermissionedToken`: `increaseAllowance` / `decreaseAllowance` (ERC-20 approve race).

### Fixed

- Length guards on the hand-rolled length-prefixed decoders (`CredentialProof`, the Solana Borsh
  reader, the example transfer codec) — a malformed length prefix no longer crashes the verifier.
- `BindWalletAsync` now bumps the document `Version` like every other mutation (it previously broke
  binding on the EF store's optimistic-concurrency token and the resurrect-revoked guard).
- Claim-policy matching reads claim values with the same culture-invariant formatter the issuer signs
  with, so a gate cannot be satisfied by a value the issuer never canonically signed.
- `Base58.Decode` is length-capped (bounds the O(n²) decode) with an all-`'1'` zero-value fix.
- `PresentationVerifier` documentation corrected to crypto-content-only (revocation / freshness live
  in the SDK `Verifier`); the attestation algorithm tag is matched case-insensitively (`Ed25519` no
  longer silently rejects an issuer's attestations).

## [3.3.1] - 2026-06-17

### Added

- **Solana devnet deploy path** (`chains/solana/`): `scripts/deploy-devnet.sh` takes a clean
  checkout to a deployed devnet program — generate the program keypair, patch `declare_id!` +
  `Anchor.toml` to it, `anchor build --no-idl`, and `anchor deploy` — then prints the program id
  and an explorer link. Idempotent (re-running upgrades the same id) and fails loudly if the
  Solana/Anchor toolchain is missing. With the deployed id exported as `TESSERA_SOLANA_PROGRAM_ID`
  (plus `TESSERA_SOLANA_RPC` / `TESSERA_SOLANA_PAYER_KEYPAIR`), the env-gated
  `SolanaDevnetSmokeTests` run **live** against the program instead of skipping. The C# client
  resolves the program id from `TESSERA_SOLANA_PROGRAM_ID`, so no client rebuild follows a deploy;
  only the Rust side carries a hardcoded id (committed as a placeholder, patched locally at deploy
  time). Adds optional `scripts/initialize-devnet.sh` (runs `initialize(admin)` for the admin-gated
  issuer flows; not needed by the smoke tests), a committed `chains/solana/Cargo.lock` for a
  reproducible build on the pinned toolchain, and `chains/solana/DEPLOYMENT.md` recording the
  verified deployment (program id `FRHDcMs7MKDi87TPtcRZBovLrb6Kj2Aa1SL5iqvm1nEi`, sample
  `register_did` / `bump_revocation` tx links, 5/5 smoke pass).

### Fixed

- **Solana keypair loading + write confirmation** (`Tessera.Chains.Solana`): three latent bugs in
  the env-gated devnet path — never run, since the smoke tests skip without `TESSERA_SOLANA_*` (the
  same class as the v3.2.0 EVM `registerDid` bug). (1) The smoke config parsed the Solana CLI
  keypair with `JsonSerializer.Deserialize<byte[]>`, but System.Text.Json maps `byte[]` to a
  Base64 *string* and cannot read the standard int-array keypair (`[25,24,8,…]`) — now deserialized
  through `List<byte>`. (2) `SolanaChainAnchor` built the Solnet `Account` from the 32-byte seed
  (`payerKeypair[..32]`), but Solnet's `PrivateKey` needs the full 64-byte secret key (the 32-byte
  form throws "invalid key length") — now passes the full keypair. (3) `SubmitAsync` returned right
  after `SendTransaction` without awaiting confirmation, so a read-back or dependent instruction
  raced devnet propagation (surfacing as `AccountNotInitialized` on the next tx, or a null/stale
  read) — now waits for the signature to reach `confirmed`. The five `SolanaDevnetSmokeTests` pass
  live against the deployed devnet program (5/5); all 56 Solana unit tests still pass.
- **Solana program builds on its pinned toolchain** (`chains/solana/`): the committed `Anchor.toml`
  carried an invalid-base58 placeholder program id (`ZkpId1111…` — `I` is not a base58 character),
  failing `anchor build` at manifest parse; replaced with the valid all-ones placeholder. A
  committed `Cargo.lock` pins transitive crates (blake3, borsh, proc-macro-crate, jobserver,
  indexmap, …) to the last versions buildable on the Anchor 0.30.1 image (Rust 1.79 / platform-tools
  rustc 1.75) — newer releases require `edition2024` / rustc > 1.75. The deploy builds `--no-idl`
  (the IDL is unused by the C# client and its generation hits anchor-syn 0.30.1's removed
  `proc_macro2::Span::source_file()`).

## [3.3.0] - 2026-06-14

Stable cut of the v3.3 line (previews `3.3.0-preview.1` / `.2`): point-in-time snapshot binding and
homomorphic predicate helpers, plus the Cardano (Metadata + Validator) and EVM `registerDid`
anchor-flow fixes the previews surfaced — all verified end-to-end (Cardano preprod with real submits;
a local EVM node).

### Fixed

- **Cardano Metadata-mode transactions were always rejected (TTL = 0)** (`Tessera.Chains.Cardano`):
  `MetadataTxBuilder` computed `ttl = tip.Slot + 7200` but the inner builder hardcoded `ttl: 0`, so
  every submitted tx carried `invalidHereafter = 0` and the node rejected it with
  `OutsideValidityIntervalUTxO`. The computed TTL is now threaded through; a regression test decodes the
  submitted body and asserts the TTL tracks the chain tip.
- **Cardano Validator-mode transactions were undecodable (inline datum)** (`Tessera.Chains.Cardano`):
  an output's inline datum was serialized as `[1, <raw plutus_data>]`, but the Conway CDDL requires
  `datum_option = [1, #6.24(bytes .cbor plutus_data)]` — the plutus_data wrapped in a tag-24 byte
  string. The raw form made the `post_alonzo_transaction_output` undecodable, so the node rejected the
  validator tx before phase-1. Now tag-24-wrapped (regression test added). The script-data hash,
  language views, Conway map-form redeemers, multiasset value, and collateral fields were verified
  correct against the authoritative `conway.cddl`.
- **Cardano submit errors were truncated, hiding the real ledger failure** (`BlockfrostCardanoProvider`):
  a ledger error longer than 300 chars (the real Conway error trails a legacy-decoder preamble) was cut
  off, surfacing only the misleading preamble. Submit (`tx/submit`) errors are no longer truncated.
- **Cardano Metadata-mode transactions were rejected (`InvalidMetadata`)** (`Tessera.Chains.Cardano`):
  the 64-byte Ed25519 signature was written into the metadata as a single 128-char hex string, but
  Cardano transaction metadata caps every string at 64 bytes, so the node rejected the tx with
  `ConwayUtxowFailure InvalidMetadata`. The signature hex is now split into a list of ≤64-char chunks
  (rejoined on read); a regression test asserts every metadata string is within the cap.
- All four Cardano fixes above were verified **end-to-end on preprod with real submits**: a
  Validator-mode `register` (Plutus V3 mint) and a Metadata-mode `register` + read-back both confirm
  on-chain.
- **EVM `registerDid` controller signature was always rejected** (`Tessera.Chains.Evm`): the
  registration signer built its EIP-191 prefix from the literal `"\x19Ethereum…"`, but C#'s `\x`
  escape is variable-length — `\x19E` parses as the single char `U+019E` (E is a hex digit) and
  corrupts the prefix. The signature was made over the wrong digest; Nethereum recovered it
  self-consistently (so the signer unit test passed) while the contract's `ecrecover` used the correct
  prefix and recovered a different signer, reverting `InvalidSignature` on every live `registerDid`.
  Net effect: live EVM DID registration (anchoring a not-yet-registered DID) was broken in 3.2.0,
  masked because the smoke tests are env-gated and skipped. Fixed by building the prefix as explicit
  bytes (`0x19 ++ "Ethereum Signed Message:\n32"`); added regression tests asserting the struct hash
  matches Solidity `abi.encode` and the signature is low-S per EIP-2.

### Added

- **Live EVM smoke tests in CI**: a new `evm-smoke` GitHub Actions job spins up a local Hardhat node,
  deploys `IdentityRegistry` + `Allowlist`, and runs the `EvmChainAnchor` / `EvmAllowlistGateway`
  smoke tests against it — so the on-chain anchor path is exercised on every push/PR instead of
  silently skipping. `chains/evm/scripts/deploy-local.js` + `chains/evm/.env.local.example` make the
  same run reproducible locally (it caught the `registerDid` regression above).
- **Point-in-time snapshot binding** (`Tessera.Sources.Bitcoin` + `Tessera.Attestations`): every
  Bitcoin attestation now binds a chain snapshot — best-block height, hash, and time — captured once
  per fact computation via the new `IBitcoinProvider.GetChainTipAsync` (`EsploraBitcoinProvider` reads
  `/blocks/tip/height` + `/blocks/tip/hash` and the tip block's time). The snapshot rides in each
  payload's claims via the generic `Tessera.Attestations.ChainSnapshot` (public chain data — no
  address/txid/amount, so the privacy invariant holds; the leak test now asserts the snapshot is
  present while secrets stay absent). Honest scope: it records the tip at issuance time, not historical
  verification at a past height (that needs an indexer).
- **`SnapshotFreshness` verification rule** (`Tessera.Sdk`): opt-in (default off)
  `SnapshotFreshnessRequirement` on `VerificationPolicy` fails a presentation whose snapshot is older
  than a max age in time (`MaxAge`) and/or in blocks (`MaxAgeBlocks` + the verifier's
  `CurrentBlockHeight`), with reason `snapshot_stale:{type}`. `VerifierOptions.Clock` (a `TimeProvider`)
  drives the time check; read a snapshot off any disclosure with `ChainSnapshot.TryFrom(payload)`.
- **Homomorphic predicate helpers** (`Tessera.Attestations.CredentialProof`): `CombineCommitments` and
  `CombineOpenings` expose the additive homomorphism of Pedersen commitments, so a bound predicate over
  a sum or difference of commitments (`C₁ ± C₂ ± … ≥ threshold`) is provable with the existing
  range-proof math — no proof-math change. The prover combines openings + value and calls
  `ProveBoundMinimum`; the verifier combines commitments and calls `VerifyBound`.

## [3.2.0] - 2026-06-13

Chain-agnostic core extended for permissioned-token / compliance use cases, organized as three
layers (generic core → replaceable plugins → reference example) with dependencies pointing only
inward. No vendor, network, token, or business-schema names in the core.

### Added

- **Bitcoin attestation source** (`Tessera.Sources.Bitcoin`): turns proven control of Bitcoin
  addresses into attestations — the basis for "private proof-of-Bitcoin". A holder proves control by
  signing a domain-separated, anti-replay challenge (`BitcoinChallenge` + `INonceStore`); BIP-137
  `signmessage` recovery (P2PKH / P2SH-P2WPKH / P2WPKH via NBitcoin — Taproot/BIP-322 documented as
  unsupported) verifies it. Over the verified addresses it computes confirmed balance and
  value-weighted holding age and emits three new attestation types — `btc_control` (address count
  only), and Pedersen-committed `btc_balance` and `btc_hodl_age`. Pluggable `IBitcoinProvider` +
  `EsploraBitcoinProvider` (mempool.space / blockstream.info Esplora API); reads retry on transient
  faults. No address, txid, script, or plaintext amount ever enters an attestation payload — enforced
  by a serialization test. The 64-bit range proof holds any satoshi balance (the whole 21M-BTC supply
  is ≈ 2^51), so no clamp or scaling is needed.
- **BitcoinCreditLine example** (`examples/BitcoinCreditLine`): prove control of a testnet BTC address
  → commit the confirmed balance (Pedersen) → anchor the Merkle root on Cardano preprod → prove
  `btc_balance ≥ 1 BTC` with a Bulletproof bound to that commitment → verify the presentation against
  the on-chain root + revocation epoch.
- **Midnight adapter scaffold** (`Tessera.Chains.Midnight`): `MidnightChainAnchor` implements
  `IChainAnchor` at the Stellar scaffold's honesty level — reads report "no anchor" (null / false),
  writes throw `NotSupported`. The Compact contract and transaction layer are roadmap; Midnight
  mainnet is live.
- **Cardano adapter** (`Tessera.Chains.Cardano`): `CardanoChainAnchor` implements `IChainAnchor` on
  Cardano (preprod) via CardanoSharp + Blockfrost, with two `AnchorMode`s — `Validator` (full Plutus
  V3 flow against the Aiken `identity-registry` validators) and `Metadata` (transaction-metadata
  fallback). Because CardanoSharp 5.1.0 is Babbage-era, the Conway / Plutus V3 CBOR it cannot emit
  (language views, map-form redeemers, script-data hash, V3 script witness under key 7) is built with
  the BCL `System.Formats.Cbor`. Pluggable `ICardanoProvider` + `BlockfrostCardanoProvider`; reads
  retry on transient faults, writes are single-shot.
- **Cardano contracts** (`chains/cardano/`, Aiken / Plutus V3): a multi-purpose `identity_anchor`
  validator (minting policy + spending validator sharing one script hash) using the state-thread
  token pattern, plus a register-only `issuer_registry`. Parity with the Solana program
  (`register_did` / `update_root` / `bump_revocation` / `register_issuer`); `aiken check` green
  (20 on-chain tests), `plutus.json` blueprint checked in. A `cardano-contract` CI job runs
  `aiken check` + `aiken build` + a blueprint-up-to-date diff.
- **CardanoCreditLine example** (`examples/CardanoCreditLine`): income attestation carrying a Pedersen
  commitment → anchor the Merkle root on Cardano preprod (Validator mode) → Bulletproof predicate
  (`income ≥ 50,000`) → verify the presentation against the on-chain root + revocation epoch.
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
- **NuGet packaging + Trusted Publishing**: product packages are packable with shared metadata
  (`src/Directory.Build.props`/`.targets`), symbols (`snupkg`), and embedded README. A
  `.github/workflows/publish.yml` publishes to nuget.org via Trusted Publishing (OIDC, no stored
  API key). Package IDs use the owner-scoped, reservable **`Sagynbaev.`** prefix (the bare
  `Tessera`/`Tessera.*` IDs are owned by other authors); assembly names and namespaces stay `Tessera.*`.

### Changed

- Predicate verification in the policy is now **bound** to the disclosed attestation's commitment;
  the unbound `CredentialProof.Verify` remains as a standalone primitive but is not policy-accepted.
- **Behavioral (review the migration notes below before upgrading):**
  - `PresentationBinding` now carries a required `HolderPublicKey`, and `Verifier`/`PresentationVerifier`
    now **enforce** the holder signature. Build presentations with the new
    `Holder.BuildSignedPresentation(...)` (or `BuildPresentationChallenge` + `BuildPresentation(..., createdAt)`).
    `PresentationVerifier`'s constructor now also takes an `ISignatureVerifier`.
  - Revocation freshness is **fail-closed**: `RequireCurrentRevocationEpoch` now requires a reachable
    chain anchor and an exact match to the current epoch, and a configured chain anchor always rejects
    presentations older than the current epoch. A presentation freshness window (`MaxPresentationAge`,
    `MaxClockSkew`) is now enforced.
  - `DidService.BuildWalletChallenge` now binds the wallet public key, and `BindWalletAsync` rejects an
    `Address` not provably controlled by `WalletPublicKey` (default verifier covers key-as-address chains
    such as Solana and fails closed elsewhere — supply an `IWalletControlVerifier` for EVM/Bitcoin).
  - Attestation claim values are canonicalized culture-invariantly (string-valued claims are unaffected).

### Security

This release is a security-hardening pass over the whole stack (off-chain SDK + chain adapters + the
on-chain contracts). Headline fixes:

- **Holder presentations are now authenticated (was: unauthenticated → impersonation/replay).** The
  `PresentationBinding.HolderSignature` is verified over a canonical `PresentationChallenge`
  (verifier + session nonce + revocation epoch + chain + timestamp + disclosed leaf hashes) against the
  key the holder DID derives from. Closes cross-verifier replay, session replay and stale-revocation
  replay, which were unenforced because the binding was never checked.
- **Revocation can no longer be bypassed:** holder-controlled `AsOfRevocationEpoch` is constrained to the
  chain's current epoch (fail-closed), and `policy.ExpectedAnchorRoot` no longer silently skips the
  revocation check.
- **DID wallet binding** now proves the bound address is controlled by the wallet key (was: any keypair
  could claim any address); wallet-binding nonces are single-use when an `INonceStore` is supplied;
  channel bindings gained authenticated add/remove overloads; `GetActiveAsync` enforces revocation on
  resolve; pepper providers reject all-zero / low-entropy peppers.
- **External sources are bound to the subject DID:** Sumsub KYC requires the applicant `externalUserId`
  to equal the subject DID (closes KYC "identity transplant"); X-Road uses server-asserted identifiers
  and verifies them against the request; both clients require `https`.
- **On-chain trust anchors are authenticated:**
  - EVM `IdentityRegistry.registerDid` now requires a controller ECDSA signature bound to
    `(didHash, attestationRoot, chainid, contract)` (closes DID squatting / root poisoning); the C#
    adapter signs it and now checks `receipt.Status` on every write (a reverted tx is no longer reported
    as success).
  - Solana `register_issuer` is gated by a `RegistryConfig` admin (was: any signer could register a
    trusted issuer key); the C# adapter fails closed on RPC errors and verifies account owner/discriminator.
  - Cardano metadata-mode reads authenticate the controller (input address + embedded controller
    signature over `did_hash‖root‖epoch`); the Aiken `issuer_registry` is governance-gated.
  - Stellar Soroban `attestation-verifier` was redesigned to Ed25519 public-key verification — the secret
    is no longer a public function argument (it previously authenticated nothing and leaked on-ledger).
- **Range-proof misuse fixed in the reference apps:** `PrivateVoting`, `SealedBidAuction` and
  `ConfidentialTransfer` now use bounded / conservation-checked proofs instead of the unbound
  `RangeProof.Verify`, so ballots are `{0,1}`, bids respect the max, and transfers conserve value.
- **Hardening:** Bulletproof `FromBytes` validates declared lengths before allocating (DoS);
  EF Core DID store uses optimistic concurrency (a concurrent write can no longer resurrect a revoked
  DID); the NuGet publish workflow no longer interpolates the dispatch input into a shell script and
  third-party Actions are pinned to commit SHAs.
- Closed the predicate-soundness gap: predicate proofs can no longer be presented about an arbitrary
  or substituted value (binding + two-sided range).

> **Deferred to the planned external cryptography audit:** `Tessera.Cryptography` constant-time / SPA
> side-channel hardening (variable-time `Point.ScalarMul`), and a type-tagged claim-canonicalization
> wire format. On-chain contract changes for Solana (Anchor) and Cardano (Aiken) are source-level and
> require `anchor build` / `aiken build` + regenerated artifacts (and the EVM contract change requires
> redeploying `IdentityRegistry` and re-pointing the ABI) before they take effect on a live network.

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