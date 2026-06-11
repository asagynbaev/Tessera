# CardanoCreditLine

A console walkthrough of the full Tessera flow with anchoring on **Cardano preprod**:

1. An issuer commits a holder's `annual_income` as a Pedersen commitment and signs an
   `accredited` attestation carrying it.
2. The holder accepts the attestation and **anchors the Merkle root on Cardano preprod**
   in Validator mode (a real Plutus V3 transaction against the `identity_anchor` validator).
3. The holder proves `income ≥ 50,000` with a Bulletproof bound to that commitment —
   without revealing the income.
4. A verifier checks the presentation, reads the **on-chain root + revocation epoch** back
   from Cardano, evaluates the predicate, and prints **`credit line approved`**.

## Run

The demo anchors on a live testnet, so it needs two environment variables:

```bash
export TESSERA_CARDANO_BLOCKFROST_KEY=preprod...      # a Blockfrost preprod project id
export TESSERA_CARDANO_SKEY="word1 word2 ... word24"  # a funded preprod payment mnemonic

dotnet run --project examples/CardanoCreditLine
```

- Get a free preprod project id at <https://blockfrost.io>.
- The `SKEY` is a standard 24-word mnemonic; its CIP-1852 payment address must hold a few
  **preprod test ADA** (fees + min-UTxO + Plutus collateral) from the
  [faucet](https://docs.cardano.org/cardano-testnets/tools/faucet). A cardano-cli `.skey`
  cborHex / 96-byte extended-key hex also works.

Without the env vars the program prints these instructions and exits.

## What to expect

```
Anchoring on chain: cardano:preprod
Issuer committed annual_income (hidden). Threshold to clear: 50,000.
Holder DID: did:tessera:<deterministic>
Anchoring the attestation root on Cardano preprod (this submits a Plutus tx and awaits a block)…
  anchored — tx <txhash>
  ProveMinimum verifies: True
  ProveBoundMinimum bound to the attested commitment: True

credit line approved
```

Anchoring submits a transaction and waits for a block (~20–60s on preprod), so the run takes
a minute or two. The on-chain record stores **only** the Merkle root + revocation epoch —
never the income, the attestation, or any PII.

To try the trust-trade-off fallback, set `AnchorMode = AnchorMode.Metadata` in the options:
the root/epoch are written as transaction metadata instead of a script-locked UTxO (cheaper,
but the verifier then trusts the controller key, not the chain). See
[`chains/cardano/README.md`](../../chains/cardano/README.md).
