# Solana identity-registry — deployment record

Evidence of the live **devnet** deployment of
[`programs/identity-registry`](programs/identity-registry/). For the step-by-step deploy +
smoke instructions see [`../../docs/deploying-solana.md`](../../docs/deploying-solana.md);
this file is the proof-of-work record.

> The committed `declare_id!` in `src/lib.rs` stays a placeholder; `deploy-devnet.sh` patches
> `declare_id!` / `Anchor.toml` locally at deploy time. The C# client takes the program id from
> `TESSERA_SOLANA_PROGRAM_ID`, so this record is the single source operators copy that env var from.

## Devnet

| Field | Value |
|---|---|
| Cluster | `devnet` |
| RPC | `https://api.devnet.solana.com` |
| Program id | `FRHDcMs7MKDi87TPtcRZBovLrb6Kj2Aa1SL5iqvm1nEi` |
| ProgramData address | `8oZuMiHM7SrnKLHidb6AhZ5Df3mjWnRtKsebrQ7UdZ91` |
| Upgrade authority / deployer pubkey | `eTXQJbNm6UDpBysT98me3rrWYDQPAfosWvTZzXcLxnc` |
| Deploy slot | `470007781` |
| Program size | `291,896` bytes |
| Deploy date (UTC) | `2026-06-17` |
| Toolchain | `anchor 0.30.1` / `solana 1.18.17` (Rust 1.79; program built `--no-idl`) |
| Program explorer | <https://explorer.solana.com/address/FRHDcMs7MKDi87TPtcRZBovLrb6Kj2Aa1SL5iqvm1nEi?cluster=devnet> |
| `initialize(admin)` run? | `no` — not needed; the smoke tests use owner-signed DID instructions |

## Sample transactions

From the live smoke run against the program above (instruction identified via the Anchor
`Instruction: <Name>` program log).

| Instruction | Tx signature | Explorer |
|---|---|---|
| `register_did` | `4CsCRvbDraaL3BvU23u4au5RTfFRUFPMq99mHAv1PrTyVgor8ib4iJ7A82KfrfPAPVcAhwGjCywKcjj1atEu9qwh` | <https://explorer.solana.com/tx/4CsCRvbDraaL3BvU23u4au5RTfFRUFPMq99mHAv1PrTyVgor8ib4iJ7A82KfrfPAPVcAhwGjCywKcjj1atEu9qwh?cluster=devnet> |
| `bump_revocation` | `3rutBTCKHky38NiEEjbQ4VkK26nGHTsPSF4rFvhRS9CxjyLzGhpkdLA1zhF68h9v18VE9xrawduQQA9iwgwuquVf` | <https://explorer.solana.com/tx/3rutBTCKHky38NiEEjbQ4VkK26nGHTsPSF4rFvhRS9CxjyLzGhpkdLA1zhF68h9v18VE9xrawduQQA9iwgwuquVf?cluster=devnet> |

## Smoke test result

The env-gated suite (the three `TESSERA_SOLANA_*` vars pointed at this deployment; see
[`../../docs/deploying-solana.md`](../../docs/deploying-solana.md)) ran live against the program:

```
dotnet test src/Tessera.Chains.Solana.Tests --filter "FullyQualifiedName~Smoke.SolanaDevnetSmokeTests"
Passed!  - Failed: 0, Passed: 5, Skipped: 0, Total: 5, Duration: 17 s
```
