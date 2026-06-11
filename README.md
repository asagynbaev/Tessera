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
| `Tessera.Attestations` | `Attestation`, `AttestationIssuer`, `MerkleTree`, `AttestationVerifier`, `PresentationVerifier`, `IIssuerRegistry`, `CredentialProof`. |
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
| `Tessera.Sources.Bitcoin` | Layer-2 plugin: proven control of Bitcoin addresses (BIP-137 signed challenge) → `btc_control` (address count only) + Pedersen-committed `btc_balance` / `btc_hodl_age`. Esplora (mempool.space / blockstream.info) provider. |

> **Audit status:** `Tessera.Cryptography` is a from-scratch, **not constant-time**
> implementation pending external review. Threat model and known limitations:
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
var presentation = holder.BuildPresentation(
    verifier:             new DidId("did:tessera:my-relying-app"),
    attestationTypes:     new[] { "phone_verified" },
    sessionNonce:         RandomBytes(16),
    asOfRevocationEpoch:  0,
    chain:                "solana",
    holderSignature:      walletSignatureOverBinding);
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

The Solana adapter speaks to a minimal Anchor program with four instructions:
`register_did`, `update_root`, `bump_revocation`, `register_issuer`. The EVM adapter
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
