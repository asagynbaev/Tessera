# Solana identity-registry — deployment record

Evidence of the live **devnet** deployment of
[`programs/identity-registry`](programs/identity-registry/). Fill the placeholders below
after a successful `./scripts/deploy-devnet.sh` run and a green smoke pass — this file is
the proof-of-work record, not a how-to. For the step-by-step deploy + smoke instructions
see [`../../docs/deploying-solana.md`](../../docs/deploying-solana.md).

> Unlike the placeholder `declare_id!` committed in `src/lib.rs`, the values here are the
> *real* deployed ones. `deploy-devnet.sh` patches `declare_id!` / `Anchor.toml` locally at
> deploy time; the C# client takes the program id from `TESSERA_SOLANA_PROGRAM_ID`, so this
> record is the single source of truth operators copy that env var from.

## Devnet

| Field | Value |
|---|---|
| Cluster | `devnet` |
| RPC | `https://api.devnet.solana.com` |
| Program id | `<PASTE_PROGRAM_ID>` |
| Deployer / payer pubkey | `<PASTE_DEPLOYER_PUBKEY>` |
| Deploy date (UTC) | `<YYYY-MM-DD>` |
| Anchor / Solana CLI versions | `anchor <x.y.z>` / `solana <x.y.z>` |
| Program explorer | https://explorer.solana.com/address/`<PASTE_PROGRAM_ID>`?cluster=devnet |
| `initialize(admin)` run? | `no` (not needed for smoke tests) / admin = `<PASTE_ADMIN_PUBKEY>` |

## Sample transactions

Signatures from a smoke run against the program above (one register + one revocation bump
is enough to evidence the round-trip). Get them from the test output or
`solana confirm -v <sig> -u devnet`.

| Instruction | Tx signature | Explorer |
|---|---|---|
| `register_did` | `<PASTE_TX_SIG>` | https://explorer.solana.com/tx/`<PASTE_TX_SIG>`?cluster=devnet |
| `bump_revocation` | `<PASTE_TX_SIG>` | https://explorer.solana.com/tx/`<PASTE_TX_SIG>`?cluster=devnet |

## Smoke test result

Paste the summary line from the env-gated suite once the three `TESSERA_SOLANA_*` vars
(see [`../../docs/deploying-solana.md`](../../docs/deploying-solana.md)) point at this
deployment:

```
dotnet test src/Tessera.Chains.Solana.Tests --filter "FullyQualifiedName~Smoke.SolanaDevnetSmokeTests"
<PASTE: Passed!  - Failed: 0, Passed: 5, Skipped: 0, ...>
```
