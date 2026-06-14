using Tessera.Crypto;
using Tessera.Crypto.Bulletproofs;
using Tessera.Crypto.Secp256k1;

namespace Tessera.Examples.PrivacyApps
{
    /// <summary>
    /// Sealed-bid auction with cryptographic guarantees.
    /// Bidders commit to a hidden bid with TWO range proofs that together prove the bid
    /// falls within [minBid, maxBid]: a lower proof that <c>amount − minBid ≥ 0</c> and an
    /// upper proof that <c>maxBid − amount ≥ 0</c>. Both bounds are bound to the same Pedersen
    /// commitment <c>C</c> via the homomorphism (the lower proof's commitment is <c>C − minBid·G</c>
    /// and the upper proof's is <c>maxBid·G − C</c>), so neither bound can be bypassed. After the
    /// auction closes, bids are revealed and verified against their commitments. No one can see
    /// bids before reveal, and no one can change their bid after committing.
    /// </summary>
    public class SealedBidAuction
    {
        private const int BitSize = 64;
        private readonly long _minBid;
        private readonly long _maxBid;

        /// <summary>
        /// Creates a new sealed-bid auction.
        /// </summary>
        /// <param name="minBid">Minimum allowed bid (inclusive).</param>
        /// <param name="maxBid">Maximum allowed bid (inclusive).</param>
        public SealedBidAuction(long minBid, long maxBid)
        {
            if (minBid > maxBid) throw new ArgumentException("minBid must be <= maxBid.");
            _minBid = minBid;
            _maxBid = maxBid;
        }

        /// <summary>
        /// Places a sealed bid. Returns a public SealedBid (commitment + range proof)
        /// and a secret BidOpening that must be kept private until the reveal phase.
        /// </summary>
        /// <param name="amount">The bid amount (kept secret until reveal).</param>
        public (SealedBid bid, BidOpening secret) PlaceBid(long amount)
        {
            if (amount < _minBid || amount > _maxBid)
                throw new ArgumentOutOfRangeException(nameof(amount), $"Bid must be in [{_minBid}, {_maxBid}].");

            var blinding = Scalar.Random();

            // The published commitment is C = amount·G + blinding·H. We prove BOTH bounds against C
            // using the Pedersen homomorphism:
            //   lower: amount − minBid ∈ [0, 2^n)  with commitment V_low  = C − minBid·G
            //   upper: maxBid − amount ∈ [0, 2^n)  with commitment V_high = maxBid·G − C
            //                                       = (maxBid − amount)·G + (−blinding)·H
            var (lowerProof, vLow) = RangeProof.Prove(Scalar.From(amount - _minBid), blinding, BitSize);
            var (upperProof, _) = RangeProof.Prove(Scalar.From(_maxBid - amount), -blinding, BitSize);

            var bid = new SealedBid
            {
                // Commitment is V_low = C − minBid·G; the verifier reconstructs C from it.
                Commitment = vLow.Encode(),
                RangeProof = lowerProof.ToBytes(),
                UpperRangeProof = upperProof.ToBytes(),
                MinBid = _minBid,
                MaxBid = _maxBid
            };

            var opening = new BidOpening
            {
                Amount = amount,
                BlindingFactor = blinding.ToBytes()
            };

            return (bid, opening);
        }

        /// <summary>
        /// Verifies that a sealed bid is valid -- the committed amount lies within the auction's
        /// [minBid, maxBid] range -- without learning the bid amount. BOTH bounds are checked
        /// cryptographically: the lower proof against <c>V_low = C − minBid·G</c> and the upper
        /// proof against <c>V_high = maxBid·G − C</c>. Because both are derived from the SAME
        /// commitment, a bid above maxBid (or below minBid) cannot pass.
        /// </summary>
        public bool VerifyBid(SealedBid bid)
        {
            if (bid?.RangeProof == null || bid.UpperRangeProof == null || bid.Commitment == null)
                return false;
            // The bid's advertised bounds must match this auction's bounds.
            if (bid.MinBid != _minBid || bid.MaxBid != _maxBid || _minBid > _maxBid)
                return false;
            try
            {
                // Stored commitment is V_low = C − minBid·G. Verify the lower proof against it.
                var vLow = Point.Decode(bid.Commitment);
                var lowerProof = RangeProof.FromBytes(bid.RangeProof);
                if (!RangeProof.Verify(vLow, lowerProof, BitSize))
                    return false;

                // Reconstruct C = V_low + minBid·G, then the upper commitment V_high = maxBid·G − C
                //   = (maxBid − minBid)·G − V_low.
                var c = vLow + Scalar.From(_minBid) * Generators.G;
                var vHigh = Scalar.From(_maxBid) * Generators.G - c;
                var upperProof = RangeProof.FromBytes(bid.UpperRangeProof);
                return RangeProof.Verify(vHigh, upperProof, BitSize);
            }
            catch { return false; }
        }

        /// <summary>
        /// Reveals and verifies a bid after the auction closes. Checks that the opening matches the
        /// commitment AND that the revealed amount lies within [MinBid, MaxBid]. Returns the bid
        /// amount if valid, null if the opening is forged or the amount is out of range.
        /// </summary>
        public long? RevealBid(SealedBid bid, BidOpening opening)
        {
            if (bid?.Commitment == null || opening == null)
                return null;

            // Reject out-of-range reveals outright (defense in depth alongside the range proofs).
            // Scalar.From rejects negatives, so an amount below MinBid would otherwise throw below;
            // we check both bounds explicitly to make the policy obvious.
            if (opening.Amount < bid.MinBid || opening.Amount > bid.MaxBid)
                return null;

            try
            {
                // Stored commitment is V_low = (Amount − MinBid)·G + blinding·H.
                long shifted = opening.Amount - bid.MinBid;
                var blinding = Scalar.FromBytes(opening.BlindingFactor);
                var expected = PedersenCommitment.Commit(Scalar.From(shifted), blinding);

                if (!expected.Encode().SequenceEqual(bid.Commitment))
                    return null;

                return opening.Amount;
            }
            catch { return null; }
        }

        /// <summary>
        /// Determines the winner from a set of revealed bids.
        /// Returns the index of the highest valid bid, or -1 if no valid bids.
        /// </summary>
        public int DetermineWinner(SealedBid[] bids, BidOpening[] openings)
        {
            if (bids.Length != openings.Length) return -1;

            long highestBid = -1;
            int winnerIndex = -1;

            for (int i = 0; i < bids.Length; i++)
            {
                var amount = RevealBid(bids[i], openings[i]);
                if (amount.HasValue && amount.Value > highestBid)
                {
                    highestBid = amount.Value;
                    winnerIndex = i;
                }
            }

            return winnerIndex;
        }
    }

    /// <summary>Public sealed bid: commitment + two range proofs. Safe to publish.</summary>
    public class SealedBid
    {
        /// <summary>
        /// SEC1-encoded lower commitment <c>V_low = C − MinBid·G</c>, where <c>C</c> is the Pedersen
        /// commitment to the bid amount. The original commitment is recovered as <c>V_low + MinBid·G</c>.
        /// </summary>
        public byte[] Commitment { get; init; } = Array.Empty<byte>();
        /// <summary>Lower-bound range proof: <c>amount − MinBid ≥ 0</c> (verified against <c>V_low</c>).</summary>
        public byte[] RangeProof { get; init; } = Array.Empty<byte>();
        /// <summary>Upper-bound range proof: <c>MaxBid − amount ≥ 0</c> (verified against <c>MaxBid·G − C</c>).</summary>
        public byte[] UpperRangeProof { get; init; } = Array.Empty<byte>();
        /// <summary>Public minimum bid for this auction.</summary>
        public long MinBid { get; init; }
        /// <summary>Public maximum bid for this auction.</summary>
        public long MaxBid { get; init; }
    }

    /// <summary>Secret bid opening. Must be kept private until the reveal phase.</summary>
    public class BidOpening
    {
        /// <summary>The actual bid amount.</summary>
        public long Amount { get; init; }
        /// <summary>The blinding factor used in the Pedersen commitment.</summary>
        public byte[] BlindingFactor { get; init; } = Array.Empty<byte>();
    }
}
