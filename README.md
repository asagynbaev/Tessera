# Tessera

Privacy-preserving, **chain-agnostic** identity and reputation infrastructure for .NET.
DIDs, signed attestations, selective disclosure via Merkle bundles, Bulletproof-based
predicate proofs over committed values, and on-chain anchoring of attestation roots and
revocation epochs. Plug in any network by implementing `IChainAnchor` — **Solana, Cardano,
EVM, and Stellar** adapters are included — plus generic building blocks for permissioned EVM
tokens gated by identity.

[![NuGet](https://img.shields.io/nuget/v/Sagynbaev.Tessera)](https://www.nuget.org/packages/Sagynbaev.Tessera)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Sagynbaev.Tessera)](https://www.nuget.org/packages/Sagynbaev.Tessera)
[![Build](https://github.com/asagynbaev/Tessera/actions/workflows/dotnet.yml/badge.svg)](https://github.com/asagynbaev/Tessera/actions/workflows/dotnet.yml)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Website:** <https://tessera-website-sepia.vercel.app/>

## What this is for

- Binding humans to decentralized identifiers (`did:tessera:...`).
- Issuing and verifying generic attestations — humanity, phone, wallet control,
  region, reputation score, agent identity.
- Producing presentations a holder can hand to a verifier: Merkle inclusion plus
  selective predicate proofs over committed values.
- Anchoring attestation roots and revocation epochs on-chain without writing any
  identity data on-chain.

## What this is not for

- Not a zkVM, not a proving network.
- Not a token, governance, or DAO toolkit.
- Not a prediction-market or DeFi library.
- Not a research-only cryptography experiment.

## Packages

Published on nuget.org under the `Sagynbaev.` prefix (e.g. the `Tessera.Sdk` assembly ships as
the `Sagynbaev.Tessera.Sdk` package); namespaces remain `Tessera.*`.

| Package (assembly) | Purpose |
|---|---|
| `Tessera.Sdk` | **Entry point for most consumers.** High-level `Holder`, `Issuer`, `Verifier` facades. |
| `Tessera.Core` | `DidId`, `Base58`. Zero external dependencies. |
| `Tessera.Did` | `DidDocument`, `DidService`, `IDidStore`, wallet/channel binding, revocation. |
| `Tessera.Attestations` | `Attestation`, `AttestationIssuer`, `MerkleTree`, `AttestationVerifier`, `PresentationVerifier`, `IIssuerRegistry`, `CredentialProof` (incl. `CombineCommitments`/`CombineOpenings` for predicates over a sum/difference of commitments), `ChainSnapshot`. |
| `Tessera.Cryptography` | Pure-C# secp256k1, Pedersen commitments, Bulletproofs (no external deps). |
| `Tessera.Signing` | Production Ed25519 (NSec / libsodium). Drop-in `Ed25519Verifier` and `Ed25519IssuerSigner`. |
| `Tessera.EntityFrameworkCore` | EF Core `IDidStore` and `IIssuerRegistry` over any relational provider (Postgres, SQL Server, SQLite). |
| `Tessera.Chains.Abstractions` | `IChainAnchor` + `IAllowlistGateway` + `DidHash` — chain-agnostic interfaces. |
| `Tessera.Chains.Solana` | Solana adapter targeting the `identity-registry` Anchor program. |
| `Tessera.Chains.Cardano` | Cardano adapter (CardanoSharp + Blockfrost): `CardanoChainAnchor` targeting the Aiken `identity-registry` Plutus V3 validators (preprod), with a metadata-mode fallback. |
| `Tessera.Chains.Stellar` | Stellar adapter scaffold targeting a Soroban anchor contract. |
| `Tessera.Chains.Midnight` | Midnight adapter **scaffold** — Compact contract + transaction layer pending (reads report no anchor, writes throw `NotSupported`). |
| `Tessera.Chains.Evm` | Generic EVM adapter (Nethereum): `EvmChainAnchor` + `EvmAllowlistGateway`, any chainId/RPC. |
| `Tessera.Sources.Sumsub` | Layer-2 plugin: Sumsub KYC → `kyc_verified` / `jurisdiction` attestations. |
| `Tessera.Sources.XRoad` | Layer-2 plugin: X-Road government registry → residency / property / encumbrance. |
| `Tessera.Sources.Bitcoin` | Layer-2 plugin: proven control of Bitcoin addresses (BIP-137 signed challenge) → `btc_control` (address count only) + Pedersen-committed `btc_balance` / `btc_hodl_age`, each bound to a point-in-time chain snapshot (height/hash/time). Esplora (mempool.space / blockstream.info) provider. |

> **Audit status:** the current release is **3.3.0-preview.2**, built on the v3.2.0
> security-hardening baseline (authenticated holder presentations, fail-closed revocation,
> address-bound wallet binding, authenticated on-chain anchors — see [Security](#security)). `Tessera.Cryptography` remains a
> from-scratch, **not constant-time** implementation pending external review; constant-time
> `Point.ScalarMul` is deferred to that audit. Threat model and known limitations:
> [docs/security-audit-readiness.md](docs/security-audit-readiness.md).

## Repository layout

```
Tessera/
├── src/
│   ├── Tessera.Core/                    DidId, Base58
│   ├── Tessera.Did/                     DID model + service
│   ├── Tessera.Channels/                channel binding (internal, not packaged)
│   ├── Tessera.Attestations/            Attestations + Merkle + CredentialProof + schema registry
│   ├── Tessera.Cryptography/            secp256k1 + Bulletproofs
│   ├── Tessera.Signing/                 Ed25519 (NSec)
│   ├── Tessera.EntityFrameworkCore/     Postgres/SQL Server/SQLite stores
│   ├── Tessera.Chains.Abstractions/     IChainAnchor, IAllowlistGateway, DidHash
│   ├── Tessera.Chains.Solana/           Solana adapter (Solnet)
│   ├── Tessera.Chains.Cardano/          Cardano adapter (CardanoSharp + Blockfrost, Aiken Plutus V3)
│   ├── Tessera.Chains.Evm/              Generic EVM adapter (Nethereum) + allowlist gateway
│   ├── Tessera.Chains.Stellar/          Stellar adapter scaffold
│   ├── Tessera.Chains.Midnight/         Midnight adapter scaffold (Compact + tx layer pending)
│   ├── Tessera.Sdk/                     Holder, Issuer, Verifier, IssuancePipeline, policy
│   ├── Tessera.Sources.Sumsub/          Layer-2 plugin: Sumsub KYC
│   ├── Tessera.Sources.XRoad/           Layer-2 plugin: X-Road government registry
│   └── Tessera.Sources.Bitcoin/         Layer-2 plugin: proof of Bitcoin control + balance (NBitcoin)
│
├── chains/
│   ├── solana/programs/identity-registry/   Anchor program (adapter: complete)
│   ├── evm/                             Hardhat: IdentityRegistry, Allowlist, PermissionedToken
│   ├── cardano/contracts/identity-registry/  Aiken validators (Plutus V3, preprod; adapter: complete)
│   └── stellar/contracts/attestation-verifier/  Soroban contract (adapter: in progress)
│
├── examples/
│   ├── PrivacyApps/                     ConfidentialTransfer, SealedBidAuction, PrivateVoting
│   ├── PermissionedToken/               Layer-3 reference: compliance flow end-to-end
│   ├── CardanoCreditLine/               Income attestation → anchor on Cardano preprod → verify
│   └── BitcoinCreditLine/               Proof of Bitcoin balance ≥ 1 BTC → anchor on Cardano → verify
│
├── Tessera/                             v2.x monolith — kept for backward compat
└── docs/
    ├── architecture.md                 layering, packages, on-chain/off-chain boundary
    └── security-audit-readiness.md     audit dossier, threat model, known limitations
```

See [docs/architecture.md](docs/architecture.md) for the on-chain/off-chain
boundary and the package dependency rules.

## Quick start

The SDK is the entry point. The three facades cover the three roles in any
attestation flow: holder, issuer, verifier.

### Install

> **Package IDs are prefixed `Sagynbaev.`** on nuget.org (the bare `Tessera`/`Tessera.*` IDs are
> owned by other authors). The assembly names and namespaces are unchanged — you still write
> `using Tessera.Sdk;`. The single meta-package is [`Sagynbaev.Tessera`](https://www.nuget.org/packages/Sagynbaev.Tessera).

```bash
dotnet add package Sagynbaev.Tessera.Sdk
dotnet add package Sagynbaev.Tessera.Signing
# pick the chain adapter you need:
dotnet add package Sagynbaev.Tessera.Chains.Cardano  # or Sagynbaev.Tessera.Chains.Solana / .Chains.Evm
# pick a store (or use the in-memory one for tests):
dotnet add package Sagynbaev.Tessera.EntityFrameworkCore
```

### Holder side — create a DID, accept an attestation, present it

```csharp
using Tessera.Sdk;
using Tessera.Signing;
using Tessera.Did;

// One-time keypair for the human/agent who controls this DID.
var (controllerPriv, controllerPub) = Ed25519.GenerateKeypair();

var holder = await Holder.CreateAsync(controllerPub, new HolderOptions
{
    Store              = new InMemoryDidStore(),     // or EfCoreDidStore for Postgres
    SignatureVerifier  = new Ed25519Verifier(),
    ChainAnchor        = solanaAnchor,                // optional; null = offline mode
});

// `holder.Did` is "did:tessera:<base58(sha256(pubkey||"v1"))>" — deterministic, not chosen.

// Later: accept an issuer-signed attestation, anchor the new root on-chain.
holder.AcceptAttestation(attestationFromIssuer);
await holder.AnchorRootAsync();

// Build a presentation for a relying app, disclosing only what it needs.
// The holder AUTHENTICATES it by signing the canonical challenge with the controller
// key; the matching public key is embedded so the verifier re-derives the DID and
// checks the signature with no store lookup.
var presentation = holder.BuildSignedPresentation(
    verifier:             new DidId("did:tessera:my-relying-app"),
    attestationTypes:     new[] { "phone_verified" },
    sessionNonce:         RandomBytes(16),
    asOfRevocationEpoch:  0,
    chain:                "solana",
    signChallenge:        ch => Ed25519.Sign(controllerPriv, ch.Span));
```

### Issuer side — sign attestations, publish your key

```csharp
using var signer = new Ed25519IssuerSigner(issuerPrivateKey);
var issuer = new Issuer(new DidId("did:tessera:my-issuer-service"), signer);

var attestation = issuer.Issue(
    type:     AttestationTypes.PhoneVerified,
    subject:  subjectDid,
    payload:  new AttestationPayload { Method = "twilio_v2" },
    validity: TimeSpan.FromDays(365));

// Register yourself once so verifiers can find you:
await issuerRegistry.RegisterAsync(issuer.BuildRegistryRecord(
    schemaUri: "https://schemas.zkp/attestation/v1"));
```

### Verifier side — check a presentation against a policy

```csharp
var verifier = new Verifier(new VerifierOptions
{
    IssuerRegistry     = issuerRegistry,
    SignatureVerifier  = new Ed25519Verifier(),
    ChainAnchor        = solanaAnchor,
});

var result = await verifier.VerifyPresentationAsync(presentation, new VerificationPolicy
{
    ExpectedVerifier              = new DidId("did:tessera:my-relying-app"),
    ExpectedSessionNonce          = nonceIssuedAtSessionStart,
    RequireCurrentRevocationEpoch = true,
});

if (!result.Valid)
    return Unauthorized(result.Reason);   // e.g. "verifier_mismatch", "revocation_stale"
```

### Predicate proof over a committed attestation value

For attestations carrying a Pedersen commitment, the holder proves a predicate
(e.g. `income ≥ 50,000`) without revealing the value. Bulletproofs on secp256k1,
implemented from scratch. The proof is **bound** to the attestation's commitment, so it
cannot be reused for a different value:

```csharp
using Tessera.Attestations;

var cp = new CredentialProof();

// Issuer commits to the value in the attestation; the holder keeps the opening.
var (commitment, opening) = cp.CommitValue(85_000);
var attestation = issuer.Issue(AttestationTypes.Accredited, subjectDid,
    new AttestationPayload { Method = "payroll", Commitment = commitment });

// Holder proves income ≥ 50,000, bound to that commitment.
var bundle = cp.ProveBoundMinimum(actualValue: 85_000, minimumRequired: 50_000, opening, label: "income");

// Verifier confirms the proof is valid AND about this attestation's committed value.
bool valid = cp.VerifyBound(commitment, bundle);   // learns only "income ≥ 50,000"
```

The verifier policy enforces this declaratively via `PredicateRequirement` (see
[docs/architecture.md](docs/architecture.md)). The unbound `ProveMinimum`/`Verify` remain
available as a standalone primitive but are not accepted by the policy.

## Storage

`IDidStore` and `IIssuerRegistry` are pluggable. Two implementations ship:

- `InMemoryDidStore` / `InMemoryIssuerRegistry` — for tests and offline dev.
- `EfCoreDidStore` / `EfCoreIssuerRegistry` — EF Core 8, provider-agnostic.

Postgres example:

```csharp
services.AddDbContext<TesseraDbContext>(opts =>
    opts.UseNpgsql(connectionString));

services.AddScoped<IDidStore, EfCoreDidStore>();
services.AddScoped<IIssuerRegistry, EfCoreIssuerRegistry>();
services.AddSingleton<ISignatureVerifier, Ed25519Verifier>();
```

Generate migrations against your chosen provider:
```bash
dotnet ef migrations add InitialTessera --project Tessera.EntityFrameworkCore
```

## Chains

The on-chain layer stores **only** Merkle attestation roots and revocation epochs.
DID documents, attestations, and proofs are never written on-chain.

| Chain | Status | Code |
|---|---|---|
| **Solana** | Adapter complete; program needs deployment | [`chains/solana/programs/identity-registry/`](chains/solana/programs/identity-registry/) |
| **EVM** | Adapter complete; contracts + ABI checked in | [`chains/evm/`](chains/evm/) |
| **Cardano** | Adapter complete; Aiken Plutus V3 validators (preprod) — `aiken check` green, blueprint checked in; preprod script addresses in [`chains/cardano/DEPLOYMENT.md`](chains/cardano/DEPLOYMENT.md) | [`chains/cardano/`](chains/cardano/) |
| **Stellar** | Adapter scaffold; anchor contract pending | [`chains/stellar/contracts/attestation-verifier/`](chains/stellar/contracts/attestation-verifier/) |
| **Midnight** | Adapter scaffold; Compact contract + tx layer pending (mainnet is live) | [`src/Tessera.Chains.Midnight/`](src/Tessera.Chains.Midnight/) |

The Solana adapter speaks to a minimal Anchor program whose four core anchoring instructions are
`register_did`, `update_root`, `bump_revocation`, `register_issuer` (plus admin-gated
`initialize` / `deactivate_issuer`). The EVM adapter
(`Tessera.Chains.Evm`) drives the equivalent [`IdentityRegistry.sol`](chains/evm/contracts/IdentityRegistry.sol)
on any EVM network — chainId/RPC/contract are pure configuration. The Cardano adapter
(`Tessera.Chains.Cardano`) drives the same four operations under eUTXO via the Aiken
[`identity-registry`](chains/cardano/contracts/identity-registry/) Plutus V3 validators
(state-thread tokens + inline datums, preprod), with a metadata-mode fallback for demos. Off-chain
verification stays in C#. Native Midnight integration is planned — see [Roadmap](#roadmap).

## Permissioned tokens (reference)

Generic building blocks let any permissioned EVM token gate ownership on Tessera identity,
with zero token/provider specifics in the core:

- `IAllowlistGateway` + `EvmAllowlistGateway` reflect an off-chain verification decision onto an
  on-chain transfer-restriction contract (`Add`/`Revoke`), compatible with a simple allowlist or
  an ERC-3643/T-REX whitelist module via configuration.
- `IssuancePipeline` turns pluggable `IAttestationSource`s (e.g. Sumsub, X-Road, Bitcoin) into signed
  attestations; `VerificationPolicy` declares required types + predicate (range-proof) rules.

[`examples/PermissionedToken`](examples/PermissionedToken/) assembles these into the target
scenario — a permissioned BEP-20 ([`PermissionedToken.sol`](chains/evm/contracts/PermissionedToken.sol))
whose transfers are gated by the allowlist. Its end-to-end test walks KYC/registry onboarding →
DID + attestations → presentation → policy → allowlist admission → token ownership, then revokes
KYC and shows transfers are blocked. See [docs/security-audit-readiness.md](docs/security-audit-readiness.md)
for the audit dossier and known limitations.

## v2 → v3

v3 is a breaking cut from the v2.x monolith. v2.x consumers keep working until
they upgrade.

| v2 type | v3 replacement |
|---|---|
| `Tessera.Core.Zkp` (HMAC equality) | Removed. Use `CredentialProof` for ZK predicates. |
| `Tessera.Interfaces.IBlockchain` | `Tessera.Chains.IChainAnchor`. |
| `Tessera.Integration.Stellar.*` | `Tessera.Chains.Stellar`. |
| `Tessera.Crypto.*` | `Tessera.Cryptography`. |
| `Tessera.Privacy.CredentialProof` | `Tessera.Attestations.CredentialProof`. |

## Security

The current release (**3.3.0-preview.2**) builds on the v3.2.0 security-hardening baseline. The
guarantees that matter at the trust boundary:

- **Authenticated holder presentations.** A presentation carries the holder's controller
  public key (`PresentationBinding.HolderPublicKey`, 32-byte Ed25519) and a signature over a
  canonical `PresentationChallenge` (verifier, session nonce, revocation epoch, chain,
  `CreatedAt`, disclosed leaf hashes). The verifier confirms
  `DidId.FromControllerKey(HolderPublicKey) == Holder` and checks the signature — so audience,
  nonce, epoch and freshness are all holder-authenticated, not just plaintext fields. Build with
  `Holder.BuildSignedPresentation(..., signChallenge: ch => Ed25519.Sign(controllerPriv, ch.Span))`,
  or split via `BuildPresentationChallenge` + `BuildPresentation(..., holderSignature, createdAt)`
  for out-of-band / hardware signers.
- **Fail-closed revocation + freshness.** When a chain anchor is configured, a presentation
  bound to an epoch older than the chain's current epoch is rejected unconditionally.
  `RequireCurrentRevocationEpoch` additionally demands a reachable anchor and an EXACT match to
  the current epoch (it no longer silently skips when `ExpectedAnchorRoot` is supplied). A
  presentation freshness window (`MaxPresentationAge` / `MaxClockSkew`, both authenticated via
  the signed `CreatedAt`) bounds replay.
- **Address-bound wallet binding.** Binding a wallet to a DID proves the bound address is
  controlled by the wallet key via `IWalletControlVerifier` (the default covers Solana
  base58(pubkey) and fails closed on chains it does not understand). `BuildWalletChallenge` binds
  the wallet pubkey, binding nonces are single-use through an `INonceStore`, and
  `DidService.GetActiveAsync` enforces revocation on resolve. Pepper providers reject all-zero /
  low-entropy peppers.
- **Source ↔ DID binding.** Sumsub KYC requires the applicant `externalUserId` to equal the
  subject DID; X-Road uses server-asserted identifiers verified against the request. Both clients
  require HTTPS.
- **Authenticated on-chain anchors.** EVM `IdentityRegistry.registerDid` requires a controller
  ECDSA signature bound to `(didHash, root, chainid, contract)`; the C# adapter signs it and
  checks `receipt.Status` on every write. Solana `register_issuer` is admin-gated via a
  `RegistryConfig` PDA (`initialize(admin)` / `deactivate_issuer`); the adapter fails closed on
  RPC errors and checks the owning program + discriminator. Cardano metadata-mode reads
  authenticate the controller (tx input address + embedded controller signature over
  `did_hash‖root‖epoch`) and the Aiken `issuer_registry` is governance-gated.
- **Soroban Ed25519.** The Stellar `attestation-verifier` was redesigned to Ed25519
  public-key verification with admin `initialize` / `set_issuer`; the trusted issuer key lives in
  contract storage. The HMAC secret is no longer a caller-supplied argument — any `--hmac_key` /
  `ZKP_HMAC_KEY` usage is removed.
- **Reference apps.** In `examples/PrivacyApps`, voting uses a 1-bit range proof ({0,1}); the
  sealed-bid auction enforces both bounds; the confidential transfer checks Pedersen balance
  conservation (`amount + change == sender balance`) in addition to the range proofs.

Caveats: `Tessera.Cryptography` is still **not constant-time** — constant-time `Point.ScalarMul`
and a type-tagged claim-canonicalization wire format are deferred to the planned external
cryptography audit (claim canonicalization is already culture-invariant). The Anchor (Solana),
Aiken (Cardano) and Solidity (EVM) contract changes above are source-level: they require the
respective toolchain build (`anchor build` / `aiken build` + regenerated `plutus.json` / Hardhat
compile) and redeploy to take effect on a live network. See
[docs/security-audit-readiness.md](docs/security-audit-readiness.md) for the full threat model.

## Roadmap

Planned, not yet shipped:

- **Cardano mainnet** — the preprod path is live today (see the [Chains](#chains) table);
  mainnet is the next step.
- **External security audit of `Tessera.Cryptography`** — the audit dossier is already public
  in [docs/security-audit-readiness.md](docs/security-audit-readiness.md).
- **Native Midnight integration** — a zkSNARK stack with selective disclosure on Midnight.
  Does not exist today.

## License

MIT.
