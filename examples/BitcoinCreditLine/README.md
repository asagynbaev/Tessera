# BitcoinCreditLine

A console walkthrough of "private proof-of-Bitcoin": prove you hold ≥ 1 BTC without revealing the
amount, the addresses, or the UTXOs, with the proof anchored on **Cardano preprod**.

1. The holder proves **control** of a testnet Bitcoin address by signing a Tessera challenge with
   their wallet (BIP-137 `signmessage`); `Tessera.Sources.Bitcoin` verifies the signature.
2. The issuer commits the **confirmed balance** as a Pedersen commitment and signs a `btc_balance`
   attestation carrying it (no address, txid, or amount in the payload).
3. The holder accepts the attestation and **anchors the Merkle root on Cardano preprod**
   (Validator mode by default; `metadata` fallback selectable by env var).
4. The holder proves `btc_balance ≥ 1 BTC` with a Bulletproof bound to that commitment — without
   revealing the balance.
5. A verifier checks the presentation, reads the **on-chain root + revocation epoch** back from
   Cardano, evaluates the predicate, and prints **`proof of bitcoin verified`**.

## What is real vs simulated

Everything cryptographic is real: the BIP-137 control signature and its verification, the Pedersen
commitment, the Bulletproof, and the Cardano preprod anchoring. The **on-chain BTC balance is a
fixed simulated holding** (1.5 BTC) — funding ≥ 1 BTC on a Bitcoin testnet from a faucet isn't
practical, so the demo doesn't read it live. The live `EsploraBitcoinProvider` (mempool.space) read
is exercised by the env-gated integration test (`TESSERA_BITCOIN_E2E=1` in
`Tessera.Sources.Bitcoin.Tests`).

## Run

Anchoring is on a live testnet, so it needs two environment variables:

```bash
export TESSERA_CARDANO_BLOCKFROST_KEY=preprod...      # a Blockfrost preprod project id
export TESSERA_CARDANO_SKEY="word1 word2 ... word24"  # a funded preprod payment mnemonic

# optional — the cheaper trust-trade-off anchor mode (default: validator):
export TESSERA_CARDANO_ANCHOR_MODE=metadata

dotnet run --project examples/BitcoinCreditLine
```

- Get a free preprod project id at <https://blockfrost.io>.
- The `SKEY` is a standard 24-word mnemonic; its CIP-1852 payment address must hold a few
  **preprod test ADA** (fees + min-UTxO + Plutus collateral) from the
  [faucet](https://docs.cardano.org/cardano-testnets/tools/faucet). A cardano-cli `.skey`
  cborHex / 96-byte extended-key hex also works.
- `TESSERA_CARDANO_ANCHOR_MODE=metadata` writes the root/epoch as transaction metadata instead of a
  script-locked UTxO (cheaper, but the verifier then trusts the controller key, not the chain) —
  the same trade-off as [`CardanoCreditLine`](../CardanoCreditLine/README.md).

Without the env vars the program prints these instructions and exits.

## What to expect

```
Anchoring on chain: cardano:preprod (mode: Validator)
Holder DID: did:tessera:<deterministic>
Holder Bitcoin address (testnet, P2WPKH): tb1q...
  control proven for a P2wpkh address (BIP-137 signature verified)
  issuer committed btc_balance (hidden). hodl age ≈ 400 days, 1 address proven.
Anchoring the attestation root on Cardano preprod (submits a tx and awaits a block)…
  anchored — tx <txhash>
  ProveBoundMinimum bound to the committed balance: True

proof of bitcoin verified — balance ≥ 1 BTC, never revealed
```

Anchoring submits a transaction and waits for a block (~20–60s on preprod), so the run takes a
minute or two. The on-chain record stores **only** the Merkle root + revocation epoch — never the
balance, the addresses, the attestation, or any PII.
