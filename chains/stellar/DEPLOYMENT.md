# Soroban attestation-verifier deployment

How to build and deploy the `attestation-verifier` Soroban contract on Stellar.
Tessera is chain-agnostic — any network is an equal anchor target. For the Solana
adapter flow see [`docs/deploying-solana.md`](../../docs/deploying-solana.md).

This contract verifies issuer **Ed25519 signatures** over attestation messages and
runs structural validation of Bulletproof envelopes on-chain. Full Bulletproofs EC
verification stays off-chain in `Tessera.Attestations.CredentialProof.Verify`.

> **Security note.** Earlier revisions of this contract accepted the HMAC secret key
> as a public `verify_proof` argument. On Soroban every invocation argument is recorded
> on-ledger, so that "secret" leaked on first use and let any caller forge a valid HMAC
> for arbitrary data — it authenticated nothing. The contract now uses a public-key
> scheme: the trusted issuer's **Ed25519 public key** is stored in instance storage by
> an authenticated admin, and `verify_proof` checks the issuer's signature against it.
> No secret of any kind is ever passed in by the caller.

## Prerequisites

Before you begin, ensure you have the following installed:

1. **Rust and Cargo** (latest stable version)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Stellar CLI** (`stellar`; replaces the legacy `soroban-cli` crate)
   ```bash
   cargo install --locked stellar-cli --features opt
   ```
   See [install & setup](https://developers.stellar.org/docs/build/smart-contracts/getting-started/setup#install) and [CLI guides](https://developers.stellar.org/docs/smart-contracts/guides/cli).

3. **wasm32 target**
   ```bash
   rustup target add wasm32v1-none
   ```

4. **Stellar account with XLM** for testnet or mainnet

## Step 1: Build the Contract

Navigate to the contract directory and build the WASM file:

```bash
cd chains/stellar
cargo build --target wasm32v1-none --release --package attestation-verifier
```

The compiled WASM file will be located at:
```
target/wasm32v1-none/release/attestation_verifier.wasm
```

## Step 2: Optimize the WASM (Optional but Recommended)

Optimize the WASM file to reduce size and gas costs:

```bash
stellar contract optimize \
  --wasm target/wasm32v1-none/release/attestation_verifier.wasm
```

This creates an optimized version:
```
target/wasm32v1-none/release/attestation_verifier_optimized.wasm
```

## Step 3: Configure Stellar Network

### For Testnet

```bash
# Configure Soroban CLI for testnet
stellar network add \
  --global testnet \
  --rpc-url https://soroban-testnet.stellar.org \
  --network-passphrase "Test SDF Network ; September 2015"

# Generate or import your account
stellar keys generate --global alice --network testnet

# Fund your account from the friendbot
stellar keys fund alice --network testnet
```

### For Mainnet (Production)

```bash
# Configure Soroban CLI for mainnet
stellar network add \
  --global mainnet \
  --rpc-url https://soroban-rpc.mainnet.stellar.org \
  --network-passphrase "Public Global Stellar Network ; September 2015"

# Import your funded account
stellar keys add --global production-key --secret-key

# Verify your account has sufficient XLM
stellar keys address production-key
```

WARNING: Never commit or share your mainnet secret keys.

## Step 4: Deploy the Contract

### Deploy to Testnet

```bash
stellar contract deploy \
  --wasm target/wasm32v1-none/release/attestation_verifier.wasm \
  --source alice \
  --network testnet
```

The command will output your contract ID:
```
CXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

**Save this contract ID!** You'll need it to interact with the contract.

### Deploy to Mainnet

```bash
stellar contract deploy \
  --wasm target/wasm32v1-none/release/attestation_verifier_optimized.wasm \
  --source production-key \
  --network mainnet
```

## Step 5: Initialize the Contract and Register the Issuer Key

The contract must be initialized **once** with an admin address, after which the admin
registers the trusted issuer's **Ed25519 public key** (32 bytes). No secret is ever sent
on-chain — only the issuer's public key is stored.

```bash
export CONTRACT_ID="CXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

# 1) Initialize with the admin address (signed by that same key — require_auth).
stellar contract invoke \
  --id $CONTRACT_ID \
  --source alice \
  --network testnet \
  -- \
  initialize \
  --admin alice

# 2) Register the trusted issuer Ed25519 public key (32-byte hex or base64 XDR).
#    This is the PUBLIC key of the off-chain key Tessera uses to sign attestations.
stellar contract invoke \
  --id $CONTRACT_ID \
  --source alice \
  --network testnet \
  -- \
  set_issuer \
  --issuer_pubkey <ISSUER_ED25519_PUBLIC_KEY_32_BYTES>
```

To rotate the issuer key later, the admin simply calls `set_issuer` again.

## Step 6: Verify Deployment

Test that your contract is deployed and working. Note that **no key argument** is passed
to `verify_proof` — the signature is checked against the stored issuer public key. The
`signature` is the issuer's 64-byte Ed25519 signature over the canonical message
`data || salt`.

```bash
stellar contract invoke \
  --id $CONTRACT_ID \
  --source alice \
  --network testnet \
  -- \
  verify_proof \
  --signature <ISSUER_ED25519_SIGNATURE_64_BYTES> \
  --data "dGVzdC1kYXRh" \
  --salt "cmFuZG9tc2FsdDEyMzQ1Ng=="
```

`verify_proof` returns `true` on success and **traps (reverts)** if the signature does
not verify, so an invalid proof fails the transaction rather than returning a value.

## Step 7: Configure Your C# Application

After deployment, configure your Tessera application. The verifier holds only the issuer's
**public** key, so the only key material near the client is the issuer's *signing* secret,
which lives wherever attestations are issued — it is **never** sent to the contract.

### Environment Variables

```bash
# Set the contract ID
export ZKP_CONTRACT_ID="CXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

# The issuer's Ed25519 PUBLIC key registered on-chain via set_issuer (non-secret).
# Used to cross-check which issuer the contract trusts; NOT a secret.
export ZKP_ISSUER_PUBLIC_KEY="<ISSUER_ED25519_PUBLIC_KEY_32_BYTES>"

# Funded G... account on this network (required for Soroban simulateTransaction envelope)
export ZKP_SOURCE_ACCOUNT="GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
```

> The attestation **signing key** (the issuer's Ed25519 *secret* key) must be kept in a
> secure signer/KMS on the issuing side and must never be placed in environment variables
> shared with verifiers or committed to source control.

### appsettings.json (Alternative)

```json
{
  "Stellar": {
    "ContractId": "CXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "HorizonUrl": "https://horizon-testnet.stellar.org",
    "SorobanRpcUrl": "https://soroban-testnet.stellar.org"
  },
  "Tessera": {
    "IssuerPublicKey": "<ISSUER_ED25519_PUBLIC_KEY_32_BYTES>"
  }
}
```

## Step 8: Deploy the DID anchor and run the C# smoke suite

Everything above deploys the **`attestation-verifier`** (issuer-signature checks). DID
anchoring through `IChainAnchor` uses a second contract, **`attestation-anchor`**, which the
`Tessera.Chains.Stellar` adapter drives. This is the parity path with Solana devnet / EVM
testnet / Cardano preprod.

### 8a. Build & deploy the anchor contract

```bash
cd chains/stellar
cargo build --target wasm32v1-none --release        # builds both contracts (workspace)

stellar contract deploy \
  --wasm target/wasm32v1-none/release/attestation_anchor.wasm \
  --source alice \
  --network testnet
# → prints the anchor contract id: CXXXX...
```

No `initialize` step is needed: anchors are owner-authorized per DID (the first `anchor_root`
binds the DID to its owner), so there is no admin to set up.

> **Verified on testnet.** The full `StellarTestnetSmokeTests` suite ran live against a deployed
> anchor (5/5). If you can't build the WASM locally (e.g. no Rust host linker on Windows), build it
> in Docker — `docker run --rm -v "<repo>/chains/stellar:/work" -w /work -e CARGO_TARGET_DIR=/tmp/target
> rust:1 bash -c "rustup target add wasm32v1-none && cargo build --release --target wasm32v1-none -p
> attestation-anchor"` — and deploy with the prebuilt `stellar` CLI binary (GitHub releases), no
> local Rust toolchain required.

### 8b. Run the live smoke suite

The `StellarTestnetSmokeTests` in `src/Tessera.Chains.Stellar.Tests` are `[SkippableFact]`-gated
on the env vars below, so they skip unless pointed at a live network. The signing account must
be **funded** (friendbot, Step 3) — it signs writes and becomes each DID's `owner`.

```bash
export TESSERA_STELLAR_RPC=https://soroban-testnet.stellar.org   # optional; this is the default
export TESSERA_STELLAR_CONTRACT=CXXXX...                         # the anchor id from 8a
export TESSERA_STELLAR_SKEY=SXXXX...                             # funded testnet secret seed (S...)
# export TESSERA_STELLAR_PASSPHRASE="Public Global Stellar Network ; September 2015"  # for mainnet

dotnet test src/Tessera.Chains.Stellar.Tests -c Release          # Skipped → Passed, live on testnet
```

`stellar keys show alice --secret` prints the `S...` seed for the account you funded above.
The suite registers fresh random DIDs, updates roots, bumps revocation, and reads state back —
each write awaits on-chain confirmation, so a full run takes about a minute on testnet.

> Stellar is at full parity with the Solana, EVM, and Cardano adapters — all four are validated
> live on their public testnets, so pick whichever network fits your deployment.

## Troubleshooting

### Problem: "account not found" error

**Solution**: Make sure your account is funded. For testnet, use:
```bash
stellar keys fund alice --network testnet
```

### Problem: "insufficient balance" error

**Solution**: Your account needs more XLM. The minimum amount for operations is typically 1 XLM plus transaction fees.

### Problem: Contract deployment fails

**Solution**: 
1. Check that the WASM file exists and is valid
2. Verify your network configuration
3. Ensure you have sufficient XLM for deployment fees
4. Try optimizing the WASM file first

### Problem: Contract invocation fails

**Solution**:
1. Verify the contract ID is correct
2. Check that function arguments are properly encoded
3. Ensure the contract is deployed to the correct network
4. Review Soroban RPC logs for detailed error messages

## Contract Upgrade

To upgrade an existing contract:

```bash
# Build new version
cargo build --target wasm32v1-none --release --package attestation-verifier

# Install the new WASM
stellar contract install \
  --wasm target/wasm32v1-none/release/attestation_verifier.wasm \
  --source alice \
  --network testnet
```

**Note**: Contract upgrades require proper authorization. Refer to Soroban documentation for upgrade patterns.

## Cost Estimation

### Testnet
- **Deployment**: Free (using friendbot-funded account)
- **Invocations**: Free (testnet has no fees)

### Mainnet
- **Deployment**: ~0.1-1 XLM (varies by contract size)
- **Invocations**: ~0.0001-0.001 XLM per call (varies by complexity)
- **Storage**: Ongoing fee based on contract state size

Always test thoroughly on testnet before deploying to mainnet.

## Security Best Practices

1. **Code Audit**: Have your contract audited before mainnet deployment
2. **Key Management**: Use hardware wallets or secure key management systems for mainnet keys
3. **Testing**: Run comprehensive tests on testnet
4. **Monitoring**: Set up monitoring for contract invocations and errors
5. **Upgrades**: Plan for contract upgrades and migrations
6. **Documentation**: Document all contract functions and their parameters

## Continuous Integration

### GitHub Actions Example

```yaml
name: Build and Test Soroban Contract

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          target: wasm32v1-none
      
      - name: Install Soroban CLI
        run: cargo install --locked stellar-cli --features opt
      
      - name: Build Contract
        run: |
          cd chains/stellar
          cargo build --target wasm32v1-none --release
      
      - name: Run Tests
        run: |
          cd chains/stellar
          cargo test
      
      - name: Optimize WASM
        run: |
          stellar contract optimize \
            --wasm chains/stellar/target/wasm32v1-none/release/attestation_verifier.wasm
```

## Resources

- [Smart contracts (Soroban)](https://developers.stellar.org/docs/smart-contracts)
- [Stellar RPC (Soroban)](https://developers.stellar.org/network/soroban-rpc)
- [Stellar CLI guides](https://developers.stellar.org/docs/smart-contracts/guides/cli)
- [Stellar Documentation](https://developers.stellar.org/)
- [Stellar CLI repository](https://github.com/stellar/stellar-cli)
- [Stellar Discord](https://discord.gg/stellar)

## Support

If you encounter issues:

1. Check the [Soroban Discord](https://discord.gg/stellar) for community support
2. Review [Soroban examples](https://github.com/stellar/soroban-examples)
3. Open an issue in this repository
4. Contact the maintainers at sagynbaev6@gmail.com

## Next Steps

After successful deployment:

1. Test all contract functions thoroughly
2. Integrate with your C# application
3. Set up monitoring and logging
4. Document your integration for your team
5. Plan for contract upgrades and maintenance
6. Consider security audits for production use

For additional support, refer to the official Stellar documentation or community channels.

