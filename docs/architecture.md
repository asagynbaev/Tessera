# Architecture

## What this is

Privacy-preserving identity and reputation infrastructure for our own product. Concretely:

- A DID layer where one human → one DID, multi-wallet, multi-channel.
- Generic attestation envelopes (issuer-signed, type-tagged, expiring).
- Selective-disclosure presentations with Merkle inclusion proofs.
- A minimal on-chain anchor — Merkle root + revocation epoch — chain-agnostic via `IChainAnchor`.
  Solana (devnet), generic-EVM (BNB testnet), Cardano (Aiken / Plutus V3, preprod), and Stellar
  (Soroban, testnet) adapters are complete and **validated live on their public testnets** (the
  full adapter ↔ on-chain smoke suite passes against a deployed anchor on each); the Midnight
  adapter is a scaffold.
- A from-scratch Bulletproofs-on-secp256k1 library, used for selective disclosure
  over committed values.

## What this is not

- Not a generic ZKP playground.
- Not a zkVM, not a new chain, not a token, not a governance system.
- Not a payments / DeFi / prediction-market toolkit.
- Not a research-only cryptography experiment.

## Boundary: on-chain vs off-chain

Hard rule: the chain is for **audit**, not for **storage**.

```
+--------------------------------+      +------------------------------+
|         OFF-CHAIN              |      |          ON-CHAIN            |
|                                |      |                              |
|  DID documents (signed)        |      |  IdentityRegistry program    |
|  Wallet bindings (sig'd chal.) |  ->  |   - did_anchor accounts:     |
|  Attestations (issuer-signed)  |      |       attestation_root (32B) |
|  Merkle bundles + presentation |      |       revocation_epoch (u64) |
|  Reputation scores (computed)  |      |       owner pubkey           |
|  Bulletproof verification      |      |   - issuer accounts:         |
|  Issuer registry (auth source) |      |       schema_uri, active     |
|                                |      |                              |
+--------------------------------+      +------------------------------+
```

The chain answers: *was the holder's attestation root R at revocation_epoch E, and is
issuer X registered as active?* It does no cryptographic proof verification.

### eUTXO model (Cardano)

The same audit boundary holds under Cardano's eUTXO model, but the *shape* differs from
Solana's account model. Instead of one program-owned account per DID, there is **one
script-locked UTxO per DID**, carrying an inline datum and a unique **state-thread (beacon)
token**. A single multi-purpose Aiken validator acts as *both* the minting policy and the
spending validator, so `policy_id == script_hash == script-address payment credential`. The
thread token is named by the `did_hash`; registration mints it, and `update_root` /
`bump_revocation` spend-and-recreate the UTxO under the controller's signature, preserving the
token and the immutable fields. The validator enforces the controller signature, monotonic
epochs, immutable `did_hash`/`controller`, exactly one continuing output (the
double-satisfaction guard), and token conservation.

#### Solana ↔ Cardano semantics mapping

| Concept | Solana (Anchor program) | Cardano (Aiken / Plutus V3) |
|---|---|---|
| State container | `did_anchor` PDA account | script-locked UTxO + thread token |
| Uniqueness key | PDA seeds `[b"did", did_hash]` | beacon asset name = `did_hash` (under the validator's own policy) |
| Owner / authority | `owner: Pubkey` in the account | `controller: VerificationKeyHash` in the datum |
| `register_did` | `init` the PDA, set fields | `mint` redeemer `RegisterDid`: mint the beacon, create the UTxO (`epoch = 0`) |
| `update_root` | `update_root` ix, owner-signed | `spend` redeemer `UpdateRoot { new_root }`, controller-signed |
| `bump_revocation` | `bump_revocation` ix, `checked_add(1)` | `spend` redeemer `BumpRevocation`, `epoch_out == epoch_in + 1` |
| `register_issuer` | `init` the issuer PDA, admin-gated via a `RegistryConfig` PDA (`initialize(admin)` / `deactivate_issuer`) | `mint` on the `issuer_registry` validator, governance-gated by a parameterized `admin` VKH (`admin ∈ tx.extra_signatories`) |
| Mutation auth | `require_keys_eq!(owner, signer)` | `controller ∈ tx.extra_signatories` |
| Epoch overflow | `EpochOverflow` (u64 checked) | not applicable — Plutus `Int` is arbitrary precision |
| Anti-fork | one PDA per hash (re-init fails) | thread-token continuity: exactly one continuing output, no stray mint/burn |
| Global uniqueness | guaranteed by the PDA | not enforceable on-chain by a single policy; the adapter reads-then-registers/updates (documented eUTXO boundary) |
| Read path | fetch account, Borsh-decode | query the thread-token UTxO, decode the inline datum (CBOR) |

The C# adapter (`Tessera.Chains.Cardano`) drives this via CardanoSharp + Blockfrost, with a
metadata-mode fallback (root/epoch written as tx metadata) for demos where the validator flow is
not needed. `didHash = SHA-256(utf8(did))` is identical across every backend. Native **Midnight**
integration (zkSNARK stack, selective disclosure on Midnight) is **a scaffold** (`Tessera.Chains.Midnight`
implements `IChainAnchor`; reads report no anchor, writes throw `NotSupported`) — the Compact anchor
contract and the Midnight transaction layer are pending.

## Repository layout

```
Tessera/
├── src/
│   ├── Tessera.Core/                       DidId, Base58 — dependency-free
│   ├── Tessera.Did/                        DidDocument, DidService, IDidStore, wallet/channel binding, revocation
│   ├── Tessera.Did.Tests/
│   ├── Tessera.Attestations/               Attestations + Merkle + PresentationVerifier + CredentialProof
│   ├── Tessera.Attestations.Tests/
│   ├── Tessera.Cryptography/               secp256k1, Pedersen, Bulletproofs (pure C#)
│   ├── Tessera.Cryptography.Tests/
│   ├── Tessera.Channels/                   HKDF-SHA256 channel-binding commitments (pepper-salted)
│   ├── Tessera.Channels.Tests/
│   ├── Tessera.Signing/                    Ed25519 over NSec (libsodium)
│   ├── Tessera.Signing.Tests/
│   ├── Tessera.EntityFrameworkCore/        EF Core IDidStore + IIssuerRegistry (any relational provider)
│   ├── Tessera.EntityFrameworkCore.Tests/
│   ├── Tessera.Chains.Abstractions/        IChainAnchor + state types — chain-agnostic
│   ├── Tessera.Chains.Solana/              Solana adapter (Solnet, identity-registry program)
│   ├── Tessera.Chains.Solana.Tests/
│   ├── Tessera.Chains.Cardano/             Cardano adapter (CardanoSharp + Blockfrost, Aiken Plutus V3)
│   ├── Tessera.Chains.Cardano.Tests/
│   ├── Tessera.Chains.Evm/                 Generic EVM adapter (Nethereum) + allowlist gateway
│   ├── Tessera.Chains.Evm.Tests/
│   ├── Tessera.Chains.Stellar/             Stellar adapter (StellarDotnetSdk, Soroban; complete)
│   ├── Tessera.Chains.Stellar.Tests/
│   ├── Tessera.Chains.Midnight/            Midnight adapter scaffold (Compact + tx layer pending)
│   ├── Tessera.Sdk/                        Holder, Issuer, Verifier facades + IssuancePipeline
│   ├── Tessera.Sdk.Tests/
│   ├── Tessera.Sources.Sumsub/             Layer-2 plugin: Sumsub KYC → AttestationDrafts
│   ├── Tessera.Sources.Sumsub.Tests/
│   ├── Tessera.Sources.XRoad/              Layer-2 plugin: X-Road government registry → drafts
│   ├── Tessera.Sources.XRoad.Tests/
│   ├── Tessera.Sources.Bitcoin/            Layer-2 plugin: proven Bitcoin control + balance/hodl-age (NBitcoin)
│   └── Tessera.Sources.Bitcoin.Tests/
│
├── chains/
│   ├── solana/                              Anchor IdentityRegistry program (adapter: complete)
│   │   ├── Anchor.toml
│   │   ├── Cargo.toml
│   │   └── programs/identity-registry/
│   ├── evm/                                 Hardhat IdentityRegistry + Allowlist (adapter: complete)
│   │   ├── contracts/                       IdentityRegistry.sol, Allowlist.sol, PermissionedToken.sol
│   │   ├── abi/                             checked-in ABIs the C# adapter targets
│   │   └── test/                            contract unit tests
│   ├── cardano/                             Aiken identity-registry (Plutus V3, preprod; adapter: complete)
│   │   ├── Makefile  README.md  DEPLOYMENT.md
│   │   └── contracts/identity-registry/     validators + plutus.json blueprint (checked in)
│   └── stellar/                             Soroban attestation-anchor + verifier (adapter: complete)
│       ├── Cargo.toml  README.md  DEPLOYMENT.md
│       └── contracts/                       attestation-anchor (DID anchor), attestation-verifier
│
├── Tessera/                                v2.x monolith — meta-package referencing the splits
├── Tessera.Tests/                          Tests for the legacy monolith APIs
│
├── examples/
│   ├── PrivacyApps/                         ConfidentialTransfer, SealedBidAuction, PrivateVoting
│   ├── PrivacyApps.Tests/
│   ├── PermissionedToken/                   Layer-3 reference: permissioned BEP-20 compliance flow
│   ├── PermissionedToken.Tests/             end-to-end: onboard → policy → allowlist → revocation
│   ├── CardanoCreditLine/                   income attestation → anchor on Cardano preprod → verify
│   └── BitcoinCreditLine/                   proof of Bitcoin balance → anchor → verify
│
└── docs/
    ├── architecture.md                      ← this file
    ├── security-audit-readiness.md          A6 audit dossier + known limitations + test vectors
    └── deploying-solana.md                  Solana program deployment guide
```

## Packages and dependencies

```
                            ┌───────────────────────┐
                            │   Tessera.Core        │
                            └────────┬──────────────┘
                                     │
                ┌────────────────────┼────────────────────────┐
                │                    │                        │
        ┌───────▼─────────┐  ┌───────▼────────────┐  ┌────────▼──────────────┐
        │  Tessera.Did    │  │ Tessera.           │  │ Tessera.              │
        │                 │  │ Attestations       │  │ Cryptography          │
        └────────┬────────┘  └─────────┬──────────┘  └───────────────────────┘
                 │                     │                       ▲
                 │                     │                       │
                 │             ┌───────┴───────┐               │
                 │             │               │               │
                 │             │   used by Tessera.Attestations.CredentialProof
                 │             │
                 │      ┌──────▼─────────────────┐
                 └──────► Tessera.Signing        │  (Ed25519, NSec)
                        └────────────────────────┘
                                                  
        ┌───────────────────────────┐
        │ Tessera.                  │
        │ Chains.Abstractions       │  (IChainAnchor, IAllowlistGateway, DidHash)
        └─────────────┬─────────────┘
                      │
        ┌─────────────┼─────────────────┐
        │             │                 │
 ┌──────▼───────┐ ┌───▼──────────┐ ┌────▼──────────┐ ┌────▼─────────┐
 │ Tessera.     │ │ Tessera.     │ │ Tessera.      │ │ Tessera.      │
 │ Chains.Solana│ │ Chains.Evm   │ │ Chains.Cardano│ │ Chains.Stellar│
 └──────────────┘ └──────────────┘ └───────────────┘ └──────────────┘
                  (Cardano: CardanoSharp + Blockfrost, Aiken Plutus V3)

        ┌────────────────────────────────────┐
        │ Tessera.Sources.Sumsub / .XRoad    │  (Layer-2 plugins; depend on Attestations + Core)
        └────────────────────────────────────┘

        ┌────────────────────────────────────┐
        │ Tessera.EntityFrameworkCore        │  (EF Core stores; depends on Did + Attestations)
        └────────────────────────────────────┘

        ┌────────────────────────────────────┐
        │ Tessera.Sdk                        │  (Holder/Issuer/Verifier facades; depends on
        └────────────────────────────────────┘   Did, Attestations, Chains.Abstractions)
```

Hard invariants:
- `Core` has zero external dependencies and zero references to chains or crypto stacks.
- `Did` and `Attestations` reference only `Core` (+ `Cryptography` for CredentialProof). They never know which chain backs anchoring.
- Chain adapter packages implement `IChainAnchor` from `Chains.Abstractions`.
- `Sdk` is the consumer-facing surface; lower-level packages stay accessible for advanced use.

## Layering: core / plugins / reference

The codebase is organized in three layers with dependencies pointing only inward:

- **Layer 1 — core (generic, reusable).** Interfaces and domain-neutral implementations. No
  provider, network, token, or business schema names. The chain adapters
  (`Tessera.Chains.Evm`, `Tessera.Chains.Solana`, `Tessera.Chains.Cardano`) are core: they are
  vendor-network-agnostic via configuration (chainId/RPC/network/contract are config, not code).
- **Layer 2 — plugins (satellite packages).** Concrete `IAttestationSource` implementations
  for specific KYC providers / registries. Depend on core; replaceable without touching it.
  Shipped: `Tessera.Sources.Sumsub` (KYC → `kyc_verified` + `jurisdiction`) and
  `Tessera.Sources.XRoad` (government registry → `jurisdiction`/`property_right`/`encumbrance`).
  Each takes an injectable client interface (production HTTP client + fakes for tests).
- **Layer 3 — reference (example, not product).** `examples/PermissionedToken` assembles Layers
  1–2 into the target scenario: a permissioned BEP-20 (`chains/evm/PermissionedToken.sol`) whose
  transfers are gated by the `Allowlist`. The end-to-end test walks KYC/registry onboarding →
  DID + attestations → presentation → compliance policy → allowlist admission → token ownership,
  then revokes KYC and shows the stale presentation removes the address and blocks transfers.

## Permissioned-token building blocks

Generic pieces that let any permissioned EVM token gate ownership on Tessera identity, with
zero token/provider specifics in the core:

- **Generic EVM anchor** (`Tessera.Chains.Evm.EvmChainAnchor`). `IChainAnchor` over the
  `chains/evm` `IdentityRegistry` contract via Nethereum, on any EVM network. Strict parity
  with the Solana program: `registerDid` / `updateRoot` / `bumpRevocation` / `registerIssuer`,
  roots + revocation epochs only. `registerDid(didHash, attestationRoot, controller, signature)`
  requires a controller **ECDSA signature** bound to `(didHash, root, chainid, contract)` — only the
  DID controller can create the anchor (no squatting); the adapter signs this with the configured
  controller key, and `updateRoot` / `bumpRevocation` stay owner-gated by `msg.sender`. `DidHash.Compute`
  (in `Tessera.Chains.Abstractions`) gives a DID the same hash on every chain. Reads retry on
  transient RPC faults; writes are single-shot to avoid double-submission, and the adapter checks
  `receipt.Status` on every write (failed transactions throw rather than being treated as success).
- **Allowlist gateway** (`IAllowlistGateway` in abstractions; `EvmAllowlistGateway` in the EVM
  package). Reflects an off-chain verification decision onto an on-chain transfer-restriction
  contract: `AddAsync` / `RevokeAsync`. Contract address, network, and function names are
  configuration, so it drives the reference `Allowlist` contract or an ERC-3643/T-REX whitelist
  module unchanged. It never decides eligibility — the verifier/policy does.
- **Issuance pipeline** (`Tessera.Sdk.IssuancePipeline`). Pulls `AttestationDraft`s from one or
  more `IAttestationSource`s, signs each via the `Issuer`, and (optionally) publishes the issuer
  to an `IIssuerRegistrar` so verifiers can resolve it. The core ships only
  `InMemoryAttestationSource`; real provider sources are Layer-2 plugins.
- **Composable verification policy** (`VerificationPolicy` + `PolicyEvaluation`). A declarative
  rule set — required attestation types and predicate (range-proof) requirements — layered on
  top of the cryptographic verification, with no business logic baked into the verifier.
- **Standard schemas + open registry** (`AttestationTypes` + `SchemaRegistry`). Narrow-generic
  standard types — `kyc_verified`, `jurisdiction`, `accredited` (Pedersen-committed income) — with
  an open `SchemaRegistry` that any caller extends with custom domain types (e.g. `property_right`,
  `encumbrance`) and validates against, with no core change.

Predicate proofs are **bound to the attestation's committed attribute**: the issuer commits to a
value as `C = v·G + r·H` in `AttestationPayload.Commitment` and hands the holder the opening; the
holder proves `v ≥ threshold` by proving the committed value of `C − threshold·G` is non-negative
(reusing `r`), so the proof's commitment `V == C − threshold·G`. `PolicyEvaluation` recomputes
`C − threshold·G` from the disclosed attestation and checks it equals `V` (`CredentialProof.VerifyBound`),
so a holder cannot attach a proof about a different value or a different attestation. Range
requirements are **two-sided**: the bundle carries a lower proof (`value − min ≥ 0`, commitment
`C − min·G`) and an upper proof (`max − value ≥ 0`, commitment `max·G − C`), so both bounds are
cryptographically enforced.

> **Remaining caveat (crypto audit / A6):** `Tessera.Cryptography` is a from-scratch, not-constant-time
> implementation pending external review. See [security-audit-readiness.md](security-audit-readiness.md).

## DID method

DIDs are derived from the controller key, not chosen by the holder:

```
did:tessera:<base58(sha256(pubkey || "v1"))>
```

`DidService.CreateAsync` enforces this. The caller cannot pick the identifier — this
prevents squatting and ties identity to provable control.

A DID document carries:
- The controller key (`Ed25519VerificationKey2020` by default).
- A list of bound wallets, each with a signature from the wallet itself over
  `{did, chain, address, wallet_pubkey, nonce, expiry}`. `DidService.BindWalletAsync` enforces all
  fields, and separately proves the bound address is controlled by that wallet key via
  `IWalletControlVerifier` (the default covers Solana `base58(pubkey)` and fails closed on chains it
  does not understand). The `nonce` is single-use, tracked through an `INonceStore` to block replay.
- A list of bound off-chain channels (Telegram, phone, email) as HKDF-SHA256 commitments
  over `channel_type || handle` salted with a KMS-held pepper — never plaintext, never salt-only.
- The current Merkle attestation root.

## Attestation flow

1. Issuer holds a signing key and is registered in the on-chain issuer registry
   (program: `chains/solana/programs/identity-registry`).
2. Issuer calls `AttestationIssuer.Issue(type, subject, payload)` to sign an envelope.
3. Holder collects attestations into an `AttestationBundle`. The bundle's `Root`
   is anchored on-chain via `IChainAnchor.AnchorRootAsync`.
4. Verifier asks for a presentation and issues a session nonce. The holder builds an
   **authenticated** presentation, signing the canonical `PresentationChallenge`
   (`Tessera.Attestations`) with the controller private key:

   ```csharp
   var presentation = holder.BuildSignedPresentation(
       verifierDid,
       new[] { AttestationTypes.KycVerified },   // or explicit indices
       sessionNonce,
       asOfRevocationEpoch: state.RevocationEpoch,
       chain: anchor.ChainId,
       signChallenge: ch => Ed25519.Sign(holderPriv, ch.Span));
   ```

   The challenge covers `{holder, verifier, session_nonce, as_of_revocation_epoch, chain,
   created_at, disclosed_leaf_hashes}`. For hardware / out-of-band signers, split it:
   `BuildPresentationChallenge(...)` → sign → `BuildPresentation(..., holderSignature, createdAt)`
   with the SAME `createdAt`. The resulting `PresentationBinding` carries the
   `HolderSignature` and the 32-byte Ed25519 `HolderPublicKey`.
5. Verifier calls `PresentationVerifier.VerifyAsync(presentation, expectedRoot)`
   (constructed as `new PresentationVerifier(attestationVerifier, signatureVerifier)`),
   or the higher-level `Verifier.VerifyPresentationAsync(presentation, policy)`. Verification
   re-derives `DidId.FromControllerKey(HolderPublicKey)`, confirms it equals `presentation.Holder`,
   and checks the holder signature over the recomputed challenge — so the presenter is *proven* to
   control the holder DID. `expectedRoot` is read from `IChainAnchor.GetAnchorAsync`.

The Merkle tree is domain-separated SHA-256 (leaf tag `0x00`, node tag `0x01`).

### Fail-closed revocation and freshness

Revocation is enforced at verification time, not left optional:

- Whenever a chain anchor is reachable, a presentation bound to an epoch **older** than the
  chain's current `RevocationEpoch` is rejected (`revocation_stale`) — unconditionally.
- `VerificationPolicy.RequireCurrentRevocationEpoch` additionally **fails closed**: it demands a
  reachable chain anchor and an **exact** match (`AsOfRevocationEpoch == chain epoch`), so a holder
  cannot defeat the check by inflating the epoch. Setting only `ExpectedAnchorRoot` no longer skips
  the revocation check.
- A freshness window is always enforced: `CreatedAt` is part of the signed challenge, and the
  verifier rejects presentations older than `MaxPresentationAge` (default 5 min) or future-dated
  beyond `MaxClockSkew` (default 1 min) — `presentation_expired` / `presentation_future_dated`.

## Threat model summary

See [`docs/security-audit-readiness.md`](security-audit-readiness.md) for the full threat model and audit dossier. Headline risks:

1. **Low-entropy channel commitments** (Telegram handle space ~10⁹). Mitigation:
   HKDF with KMS-held pepper.
2. **Wallet-binding spoofing.** Mitigation: challenge–response signed by the wallet itself (the
   challenge binds the wallet pubkey, not just a caller-chosen address); the bound address is proven
   to be controlled by that key via `IWalletControlVerifier` (fails closed on unknown chains), and
   the binding nonce is single-use through an `INonceStore`.
3. **Issuer key compromise.** Mitigation: per-issuer revocation epoch + short attestation expiries.
4. **Replay across verifiers / DIDs / chains.** Mitigation: every presentation is **holder-signed**
   over a canonical challenge covering `{holder, verifier, session_nonce, as_of_revocation_epoch,
   chain, created_at, disclosed_leaf_hashes}`. The verifier re-derives the DID from the embedded
   controller key and checks the signature (authenticated presenter), enforces a freshness window
   (`MaxPresentationAge` / `MaxClockSkew`), and fails closed on stale revocation epochs.
5. **Presentation theft / impersonation.** Mitigation: authentication binds the presentation to the
   holder's controller key — a stolen presentation cannot be re-presented by a party that does not
   hold the private key, and the bound leaf-hash set stops it being re-used over other attestations.

## v3 cut — done

All planned moves from the v2 monolith have been completed:

- `Tessera/Crypto/*` → `src/Tessera.Cryptography/` ✅
- `Tessera/Integration/Stellar/*` → `src/Tessera.Chains.Stellar/` (complete; `attestation-anchor` contract + adapter) ✅
- `Tessera/Privacy/CredentialProof.cs` → `src/Tessera.Attestations/` ✅
- `Tessera/Core/Zkp.cs` + `Tessera/Interfaces/IBlockchain.cs` → deleted ✅

Net adds beyond the original plan:
- `Tessera.Signing` — production Ed25519 (no more BYO-crypto delegate)
- `Tessera.EntityFrameworkCore` — Postgres / SQL Server / SQLite stores
- `Tessera.Channels` — HKDF channel commitments
- `Tessera.Sdk` — high-level Holder/Issuer/Verifier facades
- New: `src/Tessera.Chains.Solana/` — C# adapter against the Anchor program.

## Dual codebase: legacy `Tessera/` monolith

The legacy `Tessera/` directory (and its `Tessera.Tests/` test project) **still
contain working v2-era code**: HMAC `ProofProvider`, `BulletproofsProvider`
wrapper, and a duplicate copy of the Bulletproofs/secp256k1 implementation
under `Tessera/Crypto/*`. They are kept for these reasons:

1. **NuGet backward compatibility.** Anyone who depended on `ZkpSharp` 2.x
   and upgrades to `Tessera` 3.0.0 keeps their existing call sites working.
   The monolith exposes the v2 API surface under the new namespace.
2. **Independent test signal.** `Tessera.Tests/Crypto/*Tests.cs` still
   exercises the legacy crypto implementation. `src/Tessera.Cryptography.Tests/`
   tests the split-package copy independently — divergence between the two
   would be a regression we want to catch.

**Sunset plan.** Once `Tessera` 3.x is published and consumers have migrated
to the split packages, the legacy monolith can be deleted in a single commit:
remove `Tessera/`, `Tessera.Tests/`, and drop them from `TesseraSolution.sln`.
Nothing under `src/Tessera.*/` depends on it.

**Do not deduplicate naïvely.** It is tempting to delete
`Tessera/Crypto/Bulletproofs/` because the same code lives in
`src/Tessera.Cryptography/Bulletproofs/`. Don't — they serve different
consumers (v2 API surface vs v3 split packages), and they may legitimately
diverge if v3 grows new generators or domain separators that v2 must keep
producing the old way.

The v3 cut is a breaking release. Until then, both layouts coexist and tests cover both.
