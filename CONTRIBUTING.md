# Contributing to Tessera

Thanks for your interest in contributing. Tessera is a privacy-preserving, chain-agnostic identity
and reputation library for .NET. This guide covers how to build, test, and submit changes.

By participating you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md). For security
issues, **do not open a public issue** — follow the [Security Policy](SECURITY.md).

## Build & test

Requires the **.NET 8 SDK**.

```bash
dotnet restore
dotnet build TesseraSolution.sln -c Release
dotnet test  TesseraSolution.sln -c Release
```

All tests must pass. Live on-chain integration tests are `[SkippableFact]`-gated on environment
variables and **skip by default** — they only run when you point them at a real (or local) chain:

- **EVM** — see [`chains/evm/README.md`](chains/evm/README.md) → *Local smoke tests*: a local Hardhat
  node (`scripts/deploy-local.js` + `.env.local.example`) plus the `TESSERA_EVM_*` vars. The
  `evm-smoke` CI job runs this on every push.
- **Cardano** — `TESSERA_CARDANO_BLOCKFROST_KEY` + `TESSERA_CARDANO_SKEY` against preprod
  (`TESSERA_CARDANO_MODE` = `validator` | `metadata`).
- **Solana** — `TESSERA_SOLANA_*` against devnet.

## On-chain contracts (optional)

Only needed if you change the contracts under `chains/`. Each has its own toolchain and CI job:

| Chain | Dir | Toolchain |
|---|---|---|
| EVM | `chains/evm` | Node + Hardhat (`npm ci && npx hardhat test`) |
| Cardano | `chains/cardano/contracts/identity-registry` | Aiken (`aiken check && aiken build`) |
| Solana | `chains/solana` | Anchor (`anchor build && anchor test`) |
| Stellar | `chains/stellar` | Rust + Soroban (`cargo build --target wasm32v1-none`) |

Checked-in artifacts (EVM `abi/*.json`, Cardano `plutus.json`) must stay in sync with the sources —
CI fails on drift. The C# adapter selectors/addresses are asserted against these artifacts.

## Architecture rules

Read [`docs/architecture.md`](docs/architecture.md) first. Two hard rules:

1. **Layering, dependencies inward**: generic core → replaceable plugins → reference examples. A
   lower layer never depends on a higher one.
2. **No vendor / product / use-case names in the generic core.** Domain-specific types live in
   their plugin (e.g. `btc_*` in `Tessera.Sources.Bitcoin`), never in `Tessera.Attestations`/`Core`.

New behavior needs tests. Match the surrounding code's style, naming, and comment density.

## Commits & pull requests

- **Conventional Commits**: `type(scope): summary` — e.g. `feat(bitcoin): …`, `fix(cardano): …`,
  `docs: …`, `ci(evm): …`, `test(cardano): …`, `security: …`.
- Update **[CHANGELOG.md](CHANGELOG.md)** under `## [Unreleased]` for any user-visible change.
- Keep PRs focused; ensure `dotnet build` + `dotnet test` are green and the
  [PR checklist](.github/PULL_REQUEST_TEMPLATE.md) is satisfied.
- Releases are cut by pushing a `vX.Y.Z` tag, which publishes to nuget.org via Trusted Publishing.

Open an issue first for large or breaking changes so we can agree on the approach.
