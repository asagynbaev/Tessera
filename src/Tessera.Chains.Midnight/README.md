# Tessera.Chains.Midnight

**Status: scaffold.** A Midnight `IChainAnchor` implementation whose intended shape mirrors the
other backends — a Compact contract storing `(did_hash → attestation_root, revocation_epoch)` and
nothing else, with all proof verification staying off-chain in C#. **The Compact contract and the
Midnight transaction layer are pending; Midnight mainnet is live, this integration is roadmap.**

It is deliberately honest: the adapter does not pretend to anchor (reads report "no anchor",
writes throw) rather than silently no-op. Midnight is the **only** remaining scaffold — the Solana,
EVM, Cardano, and Stellar adapters are all complete and validated live on their public testnets.

| Member | Behaviour today |
|---|---|
| `GetAnchorAsync` | returns `null` (no anchor deployed) |
| `IsRevokedSinceAsync` | returns `false` |
| `AnchorRootAsync` | throws `NotSupportedException` |
| `BumpRevocationAsync` | throws `NotSupportedException` |

`MidnightAnchorOptions` already carries the endpoints/contract handle a real adapter will need
(`NodeUrl`, `IndexerUrl`, `ContractAddress`, `Network`), so wiring the transaction layer later is an
additive change.

Do **not** rely on this package to anchor identities. Use `Tessera.Chains.Cardano`,
`Tessera.Chains.Solana`, or `Tessera.Chains.Evm` for working anchors.
