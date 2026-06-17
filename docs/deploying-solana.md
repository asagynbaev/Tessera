# Deploying the identity-registry Anchor program

End-to-end guide for deploying [`chains/solana/programs/identity-registry/`](../chains/solana/programs/identity-registry/) to a Solana cluster and exercising the C# adapter against it.

> **Verified on devnet.** This path has been run end-to-end on devnet: program
> `FRHDcMs7MKDi87TPtcRZBovLrb6Kj2Aa1SL5iqvm1nEi` deployed, with the full
> `SolanaDevnetSmokeTests` suite passing live (5/5). See
> [`chains/solana/DEPLOYMENT.md`](../chains/solana/DEPLOYMENT.md) for the record (program id,
> deployer pubkey, sample tx links).

## Prerequisites

- **Rust toolchain**: `rustup` with stable Rust ≥ 1.79.
- **Solana CLI**: `solana --version` ≥ 1.18 ([install instructions](https://docs.solanalabs.com/cli/install)).
- **Anchor CLI**: `anchor --version` ≥ 0.30 (`avm install 0.30.1 && avm use 0.30.1`).
- **.NET 8 SDK** (only required for the smoke tests).

## Quick path — `scripts/deploy-devnet.sh`

[`chains/solana/scripts/deploy-devnet.sh`](../chains/solana/scripts/deploy-devnet.sh)
automates the deploy end to end: it builds, reads the program id from the generated
keypair (`anchor keys list`), patches `declare_id!` + `Anchor.toml` to that id, rebuilds,
and runs `anchor deploy`. It is idempotent (re-running upgrades the same program id) and
fails loudly if the Solana/Anchor toolchain is missing.

```bash
# 0. one-time: point the CLI at devnet and fund the deploy wallet
solana config set --url https://api.devnet.solana.com
solana-keygen new --outfile ~/.config/solana/id.json --no-bip39-passphrase   # if you have none
solana airdrop 2                                                              # fund it

# 1. deploy (from the repo root)
./chains/solana/scripts/deploy-devnet.sh            # or: cd chains/solana && ./scripts/deploy-devnet.sh

# 2. the script prints these three vars — export them (program id comes from its output)
export TESSERA_SOLANA_RPC="https://api.devnet.solana.com"
export TESSERA_SOLANA_PROGRAM_ID="<program id printed by the script>"
export TESSERA_SOLANA_PAYER_KEYPAIR="$HOME/.config/solana/id.json"

# 3. run the live smoke suite — Skipped → Passed with no test-code changes
dotnet test src/Tessera.Chains.Solana.Tests \
    --filter "FullyQualifiedName~Smoke.SolanaDevnetSmokeTests"
```

The deploy wallet is `Anchor.toml`'s `[provider].wallet` (default `~/.config/solana/id.json`);
the same keypair is the smoke tests' `TESSERA_SOLANA_PAYER_KEYPAIR` and becomes the `owner`
of every DID anchor it registers. Record the deployed program id and a couple of sample tx
signatures in [`chains/solana/DEPLOYMENT.md`](../chains/solana/DEPLOYMENT.md).

> **`initialize(admin)` is optional** and not exercised by the smoke tests: `register_did`,
> `update_root`, and `bump_revocation` are owner-signed and consult no `RegistryConfig`. Run
> [`scripts/initialize-devnet.sh`](../chains/solana/scripts/initialize-devnet.sh) only if you
> will use the admin-gated issuer instructions (`register_issuer` / `deactivate_issuer`).

The rest of this document is the manual, step-by-step version of what the script does (and
the issuer-registration / re-deploy / cleanup flows it does not).

## One-time setup

### 1. Point the Solana CLI at devnet and fund a keypair

```bash
solana config set --url https://api.devnet.solana.com
solana-keygen new --outfile ~/.config/solana/zkp-devnet.json --no-bip39-passphrase
solana config set --keypair ~/.config/solana/zkp-devnet.json
solana airdrop 2                                   # 2 SOL is plenty for several deploys
solana balance                                     # verify it landed
```

> Devnet faucets rate-limit; retry after a few minutes if the airdrop fails.

### 2. Generate the program keypair and sync the on-chain ID

> [`scripts/deploy-devnet.sh`](../chains/solana/scripts/deploy-devnet.sh) does this step
> (and the build + deploy below) for you — the manual commands here are the underlying
> mechanics.

The `declare_id!` macro in [`src/lib.rs`](../chains/solana/programs/identity-registry/src/lib.rs) ships with a placeholder. Replace it with the pubkey of a fresh keypair before the first deploy:

```bash
cd chains/solana
mkdir -p target/deploy
solana-keygen new -o target/deploy/identity_registry-keypair.json --no-bip39-passphrase
anchor keys sync                                   # rewrites declare_id! in src/lib.rs
```

`anchor keys sync` opens the source file and updates `declare_id!("...")` to the pubkey derived from `target/deploy/identity_registry-keypair.json`. Commit the resulting change.

### 3. Build and deploy

```bash
cd chains/solana
anchor build
anchor deploy --provider.cluster devnet
```

`anchor deploy` prints the program ID. Verify it matches `declare_id!`:

```bash
solana address -k target/deploy/identity_registry-keypair.json
```

### 4. Initialize the registry admin (once)

The program is **admin-gated**: issuer registration and deactivation are restricted to a
single `admin` key recorded in a singleton `RegistryConfig` PDA (seed `["config"]`). Before
any issuer can be registered, call `initialize(admin)` exactly once. Because the config PDA
uses a constant seed, a second `initialize` fails with `AccountAlreadyInUse`, so an attacker
cannot re-initialize the config to seize admin.

```bash
# from the chains/solana workspace, using an Anchor TS client or `anchor run` script
#   await program.methods.initialize(adminPubkey).rpc();
# the signer/payer becomes the registry deployer; `adminPubkey` becomes the key that
# may thereafter call register_issuer / deactivate_issuer.
```

`register_did`, `update_root`, and `bump_revocation` do **not** require the registry to be
initialized — they are owner-signed and bind each DID anchor to its registering signer. The
`RegistryConfig` is only consulted on the admin-gated issuer instructions.

## Issuer registration (admin only)

Once `initialize(admin)` has run, the recorded admin (and only that key) may register or
deactivate issuers:

| Instruction | Signer | Effect |
|---|---|---|
| `register_issuer(issuer_did_hash, schema_uri)` | `RegistryConfig.admin` | Create an `Issuer` PDA recording the issuer's off-chain signing key and schema URI. The `admin` signer must equal `RegistryConfig.admin` (`has_one = admin`); any other signer is rejected with `NotAdmin`. |
| `deactivate_issuer()` | `RegistryConfig.admin` | Flip an issuer record inactive. Same admin gate. |

These instructions are admin/governance operations, not part of the runtime
`IChainAnchor` path. The C# adapter exposes internal builders
(`IdentityRegistryInstructions.Initialize` / `RegisterIssuer` / `DeactivateIssuer`); the
runtime `SolanaChainAnchor` surface only drives `register_did` / `update_root` /
`bump_revocation` and reads.

## Wiring the C# adapter

Once deployed, configure the `SolanaChainAnchor`:

```csharp
var anchor = new SolanaChainAnchor(
    rpcUrl:       "https://api.devnet.solana.com",
    programId:    "<the pubkey printed by anchor deploy>",
    payerKeypair: File.ReadAllBytes("/path/to/64-byte-keypair.bin"));
```

The payer keypair is 64 bytes: 32-byte private seed concatenated with the 32-byte public key. To convert a Solana CLI JSON keypair (which stores the same 64 bytes as a JSON array) into a byte array, parse it with `System.Text.Json`:

```csharp
var bytes = JsonSerializer.Deserialize<byte[]>(File.ReadAllText(keypairPath));
```

## Running the smoke tests

The devnet smoke tests in [`src/Tessera.Chains.Solana.Tests/Smoke/`](../src/Tessera.Chains.Solana.Tests/Smoke/) are gated by three environment variables and skipped otherwise — they will not run in CI by default.

```bash
export TESSERA_SOLANA_RPC="https://api.devnet.solana.com"
export TESSERA_SOLANA_PROGRAM_ID="<deployed program pubkey>"
export TESSERA_SOLANA_PAYER_KEYPAIR="$HOME/.config/solana/zkp-devnet.json"

dotnet test src/Tessera.Chains.Solana.Tests \
    --filter "FullyQualifiedName~Smoke.SolanaDevnetSmokeTests"
```

The tests exercise the full anchor flow:

| Test | Confirms |
|---|---|
| `AnchorRoot_RegistersFreshDid` | `register_did` writes a new PDA, then `get_anchor` reads it back. |
| `AnchorRoot_TwiceOnSameDid_UpdatesRoot` | Second call routes through `update_root` instead of duplicate-creating. |
| `BumpRevocation_IncrementsEpoch` | `bump_revocation` advances `revocation_epoch` monotonically. |
| `GetAnchor_UnknownDid_ReturnsNull` | RPC returns no account for a never-anchored DID. |
| `IsRevokedSince_TracksEpoch` | Convenience comparison against the on-chain epoch. |

Each test uses a freshly randomised DID so PDAs do not collide across runs. Cost per full pass is a few thousand lamports.

## Re-deploying after code changes

After any change to `src/lib.rs`:

```bash
cd chains/solana
anchor build
anchor upgrade target/deploy/identity_registry.so --program-id <programId>
```

The program ID stays stable across upgrades; only the bytecode changes. Account data on existing PDAs is preserved.

> The admin gate and the other on-chain guards are **source-level** changes in
> `src/lib.rs`. They only take effect on a cluster after `anchor build` (which validates
> `declare_id!` against the on-disk keypair — re-run `anchor keys sync` if you rotated it)
> and an `anchor upgrade` / `anchor deploy`. A previously deployed program keeps running its
> old bytecode until you upgrade it. Note that adding the `RegistryConfig` to a registry that
> was deployed before the admin gate existed requires a fresh `initialize(admin)` after the
> upgrade.

## Cleaning up devnet artefacts

Devnet state is wiped periodically by Solana, so cleanup is rarely necessary. If you want to manually close a program (e.g. to reclaim rent):

```bash
solana program close <programId> --bypass-warning
```

> Closing is irreversible. Do it only on devnet or programs you intend to retire.
