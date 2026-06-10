# EVM — IdentityRegistry

Generic EVM backend for the Tessera identity layer — the EVM counterpart of
`chains/solana/`. The on-chain contract is deliberately minimal: it anchors Merkle
attestation roots and revocation epochs keyed by DID hash. No proof verification,
no balances, no reputation logic.

The contract is **network-agnostic**: chainId and RPC are pure configuration. The
same bytecode runs on any EVM chain (the reference scenario targets BNB Chain).

## Contracts

`contracts/IdentityRegistry.sol` — the anchor. State:

- `DidAnchor` (keyed by `didHash`) — owner address, current attestation Merkle root,
  revocation epoch, timestamps.
- `IssuerRecord` (keyed by `issuerDidHash`) — signing key (32-byte Ed25519, off-chain
  verification), schema URI, active flag.

Operations (parity with the Solana program):

| Function | Caller | Effect |
|---|---|---|
| `registerDid(didHash, attestationRoot)` | DID owner (becomes `owner`) | Create the DID anchor. |
| `updateRoot(didHash, newRoot)` | DID owner | Replace the attestation Merkle root. |
| `bumpRevocation(didHash, reason)` | DID owner | Increment the revocation epoch — prior presentations are stale. |
| `registerIssuer(issuerDidHash, signingKey, schemaUri)` | Registry authority | Add/refresh an issuer record. |
| `deactivateIssuer(issuerDidHash)` | Registry authority | Mark an issuer inactive. |

`didHash = SHA-256(utf8(did))` — identical across the C# adapter, the Solana program,
and this contract, so a DID hashes to the same value on every backend.

## What is NOT here

This contract **does not**: verify zero-knowledge proofs (Bulletproofs verification
stays off-chain in C#), store DID documents / attestation payloads / names / handles /
any PII, compute reputation, or implement a token / governance / DAO surface.

## Build & test

```bash
cd chains/evm
npm install
npm run build      # hardhat compile (solc 0.8.24)
npm test           # contract unit tests
npm run export-abi # refresh abi/*.abi.json (checked into the repo)
```

The checked-in `abi/IdentityRegistry.abi.json` is the stable interface the C# adapter
(`src/Tessera.Chains.Evm/`) and its integration tests target.

## Deploy

```bash
export TESSERA_EVM_RPC=https://...        # any EVM RPC
export TESSERA_EVM_KEY=<deployer-privkey> # funded account
npm run deploy:bnbtestnet
```

The deployer becomes the initial issuer-registry authority unless
`TESSERA_EVM_AUTHORITY` overrides it.

## C# client

`src/Tessera.Chains.Evm/EvmChainAnchor` implements `IChainAnchor` against this
contract via Nethereum. See that package for the adapter and tests.
