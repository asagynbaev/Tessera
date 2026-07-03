# Security Policy

Tessera is identity- and cryptography-adjacent infrastructure, so security reports are taken
seriously. Thank you for helping keep it and its users safe.

## Supported versions

| Version | Supported |
|---|---|
| 5.0.x (latest) | ✅ Security fixes |
| < 5.0 | ❌ Please upgrade |

Fixes land on the latest release line. Packages are published on nuget.org under the
`Sagynbaev.Tessera*` prefix via Trusted Publishing (OIDC) — no long-lived API key is stored.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately via GitHub's **[Private vulnerability reporting](https://github.com/asagynbaev/Tessera/security/advisories/new)**
(repo → **Security** → **Report a vulnerability**). If that is unavailable, contact the maintainer
[@asagynbaev](https://github.com/asagynbaev) and ask for a private channel before sharing details.

When reporting, please include:

- affected package(s) and version(s) (e.g. `Sagynbaev.Tessera.Cryptography 3.3.0`);
- a description of the issue and its impact;
- a minimal reproduction or proof of concept, if possible.

You can expect an initial acknowledgement within a few days. Coordinated disclosure is preferred:
we will work with you on a fix and a release before any public write-up.

## Known limitations (please read before relying on Tessera for high-assurance use)

The cryptographic core (`Tessera.Cryptography`: from-scratch secp256k1, Pedersen commitments, and
Bulletproofs) is now **constant-time** — both the scalar multiplication and, as of 5.0.0, the
Bulletproofs prover (branchless point accumulation + limb-based bit decomposition) — and is
cross-checked against an independent BouncyCastle oracle, **but it has not had an external
cryptographic audit** and remains self-implemented managed code (JIT-level constant-timeness is not
formally guaranteed). The claim-canonicalization wire format is length-prefixed but not type-tagged.
**Do not use it to protect funds or high-value secrets until an external audit is complete.**

The anchor-owner substitution check (`ExpectedAnchorOwner`) is opt-in, and two on-chain items are
tracked but require a redeploy: a controller-signature-gated / admin-reclaim path for Solana
registration (squatting is currently a per-`did_hash` DoS, not a substitution risk), and
length-prefixed message framing in the Stellar `attestation-verifier`.

The full threat model, what is in/out of scope, the deterministic test vectors, and the deferred
items are documented in **[docs/security-audit-readiness.md](docs/security-audit-readiness.md)** —
the dossier an external auditor should start from. On-chain contract notes (e.g. the EVM `registerDid`
controller-signature ABI change in v3.2.0) are tracked there and in the per-chain READMEs.
