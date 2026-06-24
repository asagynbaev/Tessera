# Deploying the Cardano anchor (preprod)

How to compile the Aiken validators and exercise the full anchor flow on the
**preprod** testnet from C#. The chain backend is chain-agnostic — only the
network and the script address change between Cardano networks. If you only need
a working backend *today*, the [Solana](../../docs/deploying-solana.md) and EVM
adapters are also complete.

> **Verified on preprod.** The full `CardanoPreprodSmokeTests` suite has been run live
> against preprod (register / update-root / bump-revocation / reads), passing 5/5. The one
> setup gotcha that bites everyone — the faucet funds a single UTxO but Plutus needs two — is
> called out in Step 3.

> Unlike Solana (where the program is deployed once to a program id), a Plutus
> validator is **not** "deployed" to a fixed address by an admin. Its script
> address is a deterministic function of the compiled code. You simply build the
> blueprint, derive the address, and start sending transactions to it. The first
> `register_did` creates the DID's UTxO there.

## Prerequisites

1. **Aiken** ≥ v1.1.21 — `npm install -g @aiken-lang/aiken@1.1.21` (or `aikup`),
   verify with `aiken --version`.
2. **.NET 8 SDK** — for the C# adapter / example.
3. **A Blockfrost preprod project id** — from <https://blockfrost.io> (free
   tier). This key does reads *and* transaction submission.
4. **A preprod wallet with test ADA** — a payment signing key whose address holds
   a few test ADA from the faucet (fees + min-UTxO + Plutus collateral). The
   adapter's `SigningKey` becomes the on-chain `controller`.

## Step 1 — Build the blueprint

```sh
cd chains/cardano/contracts/identity-registry
aiken check     # 20 on-chain unit tests must pass
aiken build     # writes plutus.json (checked into the repo)
```

## Step 2 — Derive the script address and policy id

```sh
aiken blueprint policy  -m identity_anchor -v identity_anchor   # policy id == script hash
aiken blueprint address -m identity_anchor -v identity_anchor   # preprod (testnet) script address
```

For the validators as committed:

| Validator | Policy id | Preprod address |
|---|---|---|
| `identity_anchor` | `6d6f737ce5acbc23a4bb0daf5391a6b2bfb2f22adde5671d7bbb58d3` | `addr_test1wpkk7umuukktcgayhvx675u356etlvhj9tw72eca0wa435cx7hx7c` |
| `issuer_registry` (pre-parameter) | `5fa90b33d76bde659c294dff557eae6df6c4157bba6048aa2ff8f477` | `addr_test1wp06jzen6a4auevu99xl74t74ekld3q40waxqj929lu0gacxv898p` |

The C# adapter derives the `identity_anchor` values from `plutus.json` at runtime,
so you do not need to copy them into config. **`issuer_registry` is now
governance-gated** — it is parameterized by an `admin: VerificationKeyHash`, so
the values above are the *pre-parameter* scaffold in the checked-in `plutus.json`
and will change once you `aiken build` and apply your admin VKH. If you use issuer
registration, derive the parameter-applied script/address and supply it
explicitly (Step 4) — do not rely on the embedded blueprint for issuer
onboarding. On-chain validator changes only take effect after rebuilding with the
Aiken toolchain and using the new script address.

## Step 3 — Fund the controller wallet

Send preprod test ADA to your payment address from the faucet:
<https://docs.cardano.org/cardano-testnets/tools/faucet> (select **Preprod**).
A few test ADA is plenty. Plutus transactions also need a pure-ADA UTxO for
collateral, which the adapter selects automatically from this wallet.

> **You need ≥ 2 UTxOs, not just enough ADA.** The faucet delivers the funds as a
> **single** UTxO, but every Plutus anchor tx needs one UTxO for collateral *plus* at
> least one separate UTxO for funding — so a freshly-funded wallet with one UTxO fails
> with `Insufficient funds … have 0`. Split it once with a plain self-payment that creates
> several outputs back to your own address (e.g. 4–5 outputs), then anchor as normal. The
> adapter also retries a write that hits an already-spent input (the Blockfrost address-UTxO
> index lags confirmation, so back-to-back writes can momentarily select a stale UTxO).

## Step 4 — Configure the C# adapter

```csharp
using Tessera.Chains.Cardano;

var anchor = new CardanoChainAnchor(new CardanoAnchorOptions
{
    Network             = CardanoNetwork.Preprod,
    BlockfrostProjectId = Environment.GetEnvironmentVariable("TESSERA_CARDANO_BLOCKFROST_KEY")!,
    SigningKey          = Environment.GetEnvironmentVariable("TESSERA_CARDANO_SKEY")!, // payment skey
    AnchorMode          = AnchorMode.Validator, // or AnchorMode.Metadata for the demo fallback
});
```

`ScriptRefs` is optional for DID anchoring — leave it null to derive the
`identity_anchor` script + address + policy id from the blueprint shipped with the
package.

**Issuer registration is different.** `RegisterIssuerAsync` requires
`AnchorMode.Validator`, and because `issuer_registry` is now parameterized by a
governance admin VKH, the embedded blueprint is only the unparameterized scaffold.
To register issuers securely, build the parameter-applied `issuer_registry`
(`aiken build` with your admin VKH), pass its compiled script bytes via
`CardanoScriptRefs.IssuerRegistryScript`, and have the admin co-sign the
registration transaction:

```csharp
// Each field is the validator's `compiledCode` hex from a `plutus.json`, decoded to bytes.
// IssuerRegistryScript must be the build with your admin VKH applied as the parameter.
byte[] identityAnchorBytes      = Convert.FromHexString(identityAnchorCompiledCodeHex);
byte[] issuerRegistryBytes      = Convert.FromHexString(parameterAppliedIssuerRegistryHex);

var anchor = new CardanoChainAnchor(new CardanoAnchorOptions
{
    Network             = CardanoNetwork.Preprod,
    BlockfrostProjectId = Environment.GetEnvironmentVariable("TESSERA_CARDANO_BLOCKFROST_KEY")!,
    SigningKey          = Environment.GetEnvironmentVariable("TESSERA_CARDANO_SKEY")!,
    AnchorMode          = AnchorMode.Validator,
    ScriptRefs          = new CardanoScriptRefs
    {
        IdentityAnchorScript = identityAnchorBytes,   // required when ScriptRefs is set
        IssuerRegistryScript = issuerRegistryBytes,   // admin-VKH-applied compiledCode
    },
});
```

## Step 5 — Exercise the flow

```csharp
var did = new DidId("did:tessera:alice");
await anchor.AnchorRootAsync(did, merkleRoot);          // register_did (first call) / update_root
var state = await anchor.GetAnchorAsync(did);           // read back root + epoch
await anchor.BumpRevocationAsync(did, RevocationReason.KeyRotation);
```

The runnable end-to-end sample is
[`examples/CardanoCreditLine`](../../examples/CardanoCreditLine/) — it issues an
income attestation, anchors the root on preprod in Validator mode, builds a
Bulletproof predicate, and verifies the presentation against the on-chain root.
It needs only `TESSERA_CARDANO_BLOCKFROST_KEY` and `TESSERA_CARDANO_SKEY`.

## Troubleshooting

- **`InsufficientFunds` / no collateral** — fund the controller address (Step 3);
  Plutus txs need ≥ ~5 test ADA for fees + min-UTxO + collateral.
- **`ScriptExecutionFailure`** — the datum/redeemer did not satisfy the validator.
  Re-run `aiken check`; confirm the blueprint in the package matches
  `plutus.json`.
- **`not_owner` on update/bump** — the `SigningKey` is not the controller that
  registered the DID. Owner is set at registration and is immutable (parity with
  Solana/EVM).
- **Reads return null right after submit** — preprod needs a block (~20s) to
  confirm; the adapter awaits confirmation up to `ConfirmationTimeout`.

## Cost

Preprod test ADA is free from the faucet. Each anchor transaction costs a small
fraction of a test ADA in fees plus the locked min-UTxO (~1.2 test ADA) for the
anchor UTxO, returned only if the UTxO is ever spent to nothing.

## Continuous integration

CI compiles and tests the validators on every push (`aiken check` + `aiken
build`, with a blueprint-up-to-date diff). The live preprod flow is an
env-gated `SkippableFact` integration test — skipped unless
`TESSERA_CARDANO_BLOCKFROST_KEY` / `TESSERA_CARDANO_SKEY` are set — so CI never
needs a funded wallet.

## Resources

- Aiken: <https://aiken-lang.org>
- Blockfrost API: <https://docs.blockfrost.io>
- Preprod faucet: <https://docs.cardano.org/cardano-testnets/tools/faucet>

## Support

Questions: sagynbaev6@gmail.com
