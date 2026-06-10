# Tessera

Privacy-preserving identity and reputation infrastructure for .NET. DIDs, signed
attestations, selective disclosure via Merkle bundles, Bulletproof-based predicate
proofs over committed values, and multi-chain anchoring — chain-agnostic by design.
Plug in any network by implementing `IChainAnchor`. Solana, Stellar, and generic EVM
adapters included — plus generic building blocks for permissioned EVM tokens gated by identity.

[![NuGet](https://img.shields.io/nuget/v/Tessera)](https://www.nuget.org/packages/Tessera)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Tessera)](https://www.nuget.org/packages/Tessera)
[![Build](https://github.com/asagynbaev/Tessera/actions/workflows/dotnet.yml/badge.svg)](https://github.com/asagynbaev/Tessera/actions/workflows/dotnet.yml)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

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

| Package | Purpose |
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
| `Tessera.Chains.Stellar` | Stellar adapter scaffold targeting a Soroban anchor contract. |
| `Tessera.Chains.Evm` | Generic EVM adapter (Nethereum): `EvmChainAnchor` + `EvmAllowlistGateway`, any chainId/RPC. |
| `Tessera.Sources.Sumsub` | Layer-2 plugin: Sumsub KYC → `kyc_verified` / `jurisdiction` attestations. |
| `Tessera.Sources.XRoad` | Layer-2 plugin: X-Road government registry → residency / property / encumbrance. |

## Repository layout

```
Tessera/
├── src/
│   ├── Tessera.Core/                    DidId, Base58
│   ├── Tessera.Did/                     DID model + service
│   ├── Tessera.Attestations/            Attestations + Merkle + CredentialProof + schema registry
│   ├── Tessera.Cryptography/            secp256k1 + Bulletproofs
│   ├── Tessera.Signing/                 Ed25519 (NSec)
│   ├── Tessera.EntityFrameworkCore/     Postgres/SQL Server/SQLite stores
│   ├── Tessera.Chains.Abstractions/     IChainAnchor, IAllowlistGateway, DidHash
│   ├── Tessera.Chains.Solana/           Solana adapter (Solnet)
│   ├── Tessera.Chains.Evm/              Generic EVM adapter (Nethereum) + allowlist gateway
│   ├── Tessera.Chains.Stellar/          Stellar adapter scaffold
│   ├── Tessera.Sdk/                     Holder, Issuer, Verifier, IssuancePipeline, policy
│   ├── Tessera.Sources.Sumsub/          Layer-2 plugin: Sumsub KYC
│   └── Tessera.Sources.XRoad/           Layer-2 plugin: X-Road government registry
│
├── chains/
│   ├── solana/programs/identity-registry/   Anchor program (adapter: complete)
│   ├── evm/                             Hardhat: IdentityRegistry, Allowlist, PermissionedToken
│   └── stellar/contracts/attestation-verifier/  Soroban contract (adapter: in progress)
│
├── examples/
│   ├── PrivacyApps/                     ConfidentialTransfer, SealedBidAuction, PrivateVoting
│   └── PermissionedToken/               Layer-3 reference: compliance flow end-to-end
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

```bash
dotnet add package Tessera.Sdk
dotnet add package Tessera.Signing
# pick the chain adapter you need:
dotnet add package Tessera.Chains.Solana
# pick a store (or use the in-memory one for tests):
dotnet add package Tessera.EntityFrameworkCore
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
| **Stellar** | Adapter scaffold; anchor contract pending | [`chains/stellar/contracts/attestation-verifier/`](chains/stellar/contracts/attestation-verifier/) |

The Solana adapter speaks to a minimal Anchor program with four instructions:
`register_did`, `update_root`, `bump_revocation`, `register_issuer`. The EVM adapter
(`Tessera.Chains.Evm`) drives the equivalent [`IdentityRegistry.sol`](chains/evm/contracts/IdentityRegistry.sol)
on any EVM network — chainId/RPC/contract are pure configuration. Off-chain verification stays in C#.

## Permissioned tokens (reference)

Generic building blocks let any permissioned EVM token gate ownership on Tessera identity,
with zero token/provider specifics in the core:

- `IAllowlistGateway` + `EvmAllowlistGateway` reflect an off-chain verification decision onto an
  on-chain transfer-restriction contract (`Add`/`Revoke`), compatible with a simple allowlist or
  an ERC-3643/T-REX whitelist module via configuration.
- `IssuancePipeline` turns pluggable `IAttestationSource`s (e.g. Sumsub, X-Road) into signed
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

## License

MIT.
