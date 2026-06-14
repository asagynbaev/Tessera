<!--
Thanks for contributing to Tessera! Please fill out the sections below.
See CONTRIBUTING.md for build/test instructions and the architecture rules.
-->

## Summary

<!-- What does this PR change, and why? Link any related issue: Closes #123 -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behavior)
- [ ] Docs / chore / CI only

## Affected area

<!-- e.g. Tessera.Cryptography, Tessera.Attestations, chains/evm, chains/cardano, docs -->

## Checklist

- [ ] `dotnet build TesseraSolution.sln -c Release` is green.
- [ ] `dotnet test TesseraSolution.sln -c Release` is green.
- [ ] New or changed behavior is covered by tests.
- [ ] Commits follow **Conventional Commits** (`type(scope): summary`).
- [ ] **[CHANGELOG.md](../CHANGELOG.md)** updated under `## [Unreleased]` for any user-visible change.
- [ ] No vendor / product / use-case names leaked into the generic core (see [architecture rules](../CONTRIBUTING.md#architecture-rules)).
- [ ] If contracts under `chains/` changed: checked-in artifacts (`abi/*.json`, `plutus.json`) are regenerated and in sync.
- [ ] This PR does **not** contain a security vulnerability fix that should be reported privately first (see [SECURITY.md](../SECURITY.md)).

## Notes for reviewers

<!-- Anything reviewers should pay special attention to: trade-offs, follow-ups, out-of-scope items. -->
