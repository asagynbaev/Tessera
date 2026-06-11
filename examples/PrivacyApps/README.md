# PrivacyApps

Three self-contained demos of the from-scratch `Tessera.Cryptography` primitives
(Pedersen commitments + Bulletproofs on secp256k1). They use no chain and no DID layer —
just the proof system.

- **ConfidentialTransfer** — hides a transfer amount while proving it is non-negative and does
  not exceed the sender's balance (Pedersen commitments + two Bulletproof range proofs).
- **SealedBidAuction** — bidders commit to a hidden bid with a range proof that it lies within
  `[minBid, maxBid]`; after the auction closes, bids are revealed and verified against their
  commitments. No bid is visible before reveal, and none can change after committing.
- **PrivateVoting** — each voter commits to a binary `0/1` vote with a validity (range) proof;
  individual votes stay hidden and the tally is computed from the revealed ballot openings.

## Run

```bash
dotnet test examples/PrivacyApps.Tests
```
