# PrivacyApps

Three self-contained demos of the from-scratch `Tessera.Cryptography` primitives
(Pedersen commitments + Bulletproofs on secp256k1). They use no chain and no DID layer —
just the proof system.

- **ConfidentialTransfer** — hides a transfer amount while proving it is non-negative and does
  not exceed the sender's balance (Pedersen commitments + two Bulletproof range proofs). Soundness
  rests on three checks, all required: `amount ≥ 0`, `change ≥ 0`, and **balance conservation**
  (`AmountCommitment + ChangeCommitment == SenderBalanceCommitment` as secp256k1 points). The two
  range proofs alone only show two independent non-negative numbers; the conservation check is what
  stops a sender from inflating value, so the verifier checks it against an independently trusted
  balance commitment.
- **SealedBidAuction** — bidders commit to a hidden bid with **two** range proofs that together
  prove it lies within `[minBid, maxBid]`: a lower proof (`amount − minBid ≥ 0`) and an upper proof
  (`maxBid − amount ≥ 0`), both bound to the same commitment via the Pedersen homomorphism so
  neither bound can be bypassed. After the auction closes, bids are revealed and verified against
  their commitments, and reveals outside `[minBid, maxBid]` are rejected outright. No bid is visible
  before reveal, and none can change after committing.
- **PrivateVoting** — each voter commits to a binary vote with a **1-bit** Bulletproofs range proof,
  attesting the committed value lies in `[0, 2¹) = {0, 1}`. A 1-bit (not 64-bit) bound is what stops
  a malicious voter from committing to a larger value to inflate the tally. Individual votes stay
  hidden and the tally is computed from the revealed ballot openings.

## Run

```bash
dotnet test examples/PrivacyApps.Tests
```

> **Note** — These demos exercise the from-scratch `Tessera.Cryptography` primitives, which are
> **not** constant-time (`Point.ScalarMul` is a data-dependent double-and-add loop). A formal
> external cryptography audit is still pending, so do not use these as-is in production where
> side-channel resistance matters.
