using Xunit;
using Tessera.Examples.PrivacyApps;
using Tessera.Crypto;
using Tessera.Crypto.Bulletproofs;
using Tessera.Crypto.Secp256k1;

namespace Tessera.Examples.PrivacyApps.Tests
{
    public class ConfidentialTransferTests
    {
        private readonly ConfidentialTransfer _ct = new();

        [Fact]
        public void CreateAndVerify_ValidTransfer()
        {
            var bundle = _ct.CreateTransfer(senderBalance: 10000, transferAmount: 2500);

            Assert.NotEmpty(bundle.AmountCommitment);
            Assert.NotEmpty(bundle.AmountProof);
            Assert.NotEmpty(bundle.ChangeCommitment);
            Assert.NotEmpty(bundle.ChangeProof);
            Assert.True(_ct.VerifyTransfer(bundle));
        }

        [Fact]
        public void Verify_TamperedProof_Fails()
        {
            var bundle = _ct.CreateTransfer(10000, 3000);
            bundle.AmountProof[10] ^= 0xFF;
            Assert.False(_ct.VerifyTransfer(bundle));
        }

        [Fact]
        public void CreateTransfer_ExceedsBalance_Throws()
        {
            Assert.Throws<ArgumentException>(() => _ct.CreateTransfer(1000, 2000));
        }

        [Fact]
        public void CreateTransfer_NegativeAmount_Throws()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => _ct.CreateTransfer(1000, -1));
        }

        [Fact]
        public void CreateTransfer_ZeroAmount_Valid()
        {
            var bundle = _ct.CreateTransfer(5000, 0);
            Assert.True(_ct.VerifyTransfer(bundle));
        }

        [Fact]
        public void CreateTransfer_FullBalance_Valid()
        {
            var bundle = _ct.CreateTransfer(5000, 5000);
            Assert.True(_ct.VerifyTransfer(bundle));
        }

        [Fact]
        public void Serialize_Deserialize_RoundTrip()
        {
            var bundle = _ct.CreateTransfer(10000, 4000);
            string serialized = _ct.Serialize(bundle);
            var restored = _ct.Deserialize(serialized);
            Assert.True(_ct.VerifyTransfer(restored));
        }

        // --- H15 malicious-case tests: balance conservation must be enforced ---

        [Fact]
        public void Verify_AgainstTrustedBalanceCommitment_Succeeds()
        {
            var bundle = _ct.CreateTransfer(senderBalance: 8000, transferAmount: 3000);
            // A verifier supplying the matching trusted balance commitment accepts it.
            Assert.True(_ct.VerifyTransfer(bundle, bundle.SenderBalanceCommitment));
        }

        [Fact]
        public void Verify_NonConservingCommitments_Fails()
        {
            // Forge a bundle where amount + change do NOT equal the claimed balance:
            // both amount (5000) and change (5000) carry valid non-negative range proofs,
            // but they sum to 10000 while the sender's real balance is only 6000.
            // Without the conservation check this would let the sender inflate value.
            var (amountProof, amountV) = RangeProof.Prove(Scalar.From(5000), Scalar.Random(), 64);
            var (changeProof, changeV) = RangeProof.Prove(Scalar.From(5000), Scalar.Random(), 64);

            var realBalanceCommitment = PedersenCommitment.Commit(Scalar.From(6000), Scalar.Random());

            var forged = new TransferBundle
            {
                AmountCommitment = amountV.Encode(),
                AmountProof = amountProof.ToBytes(),
                ChangeCommitment = changeV.Encode(),
                ChangeProof = changeProof.ToBytes(),
                SenderBalanceCommitment = realBalanceCommitment.Encode()
            };

            // The two range proofs are individually valid, but conservation fails.
            Assert.False(_ct.VerifyTransfer(forged, realBalanceCommitment.Encode()));
        }

        [Fact]
        public void Verify_ChangeExceedingBalance_Fails()
        {
            // Sender's true balance is 1000, but they craft a transfer whose hidden change
            // commitment (1,000,000) exceeds the balance. The change is non-negative (range
            // proof passes) yet amount + change != balance, so verification must reject it.
            var (amountProof, amountV) = RangeProof.Prove(Scalar.From(0), Scalar.Random(), 64);
            var (changeProof, changeV) = RangeProof.Prove(Scalar.From(1_000_000), Scalar.Random(), 64);

            var trustedBalance = PedersenCommitment.Commit(Scalar.From(1000), Scalar.Random());

            var forged = new TransferBundle
            {
                AmountCommitment = amountV.Encode(),
                AmountProof = amountProof.ToBytes(),
                ChangeCommitment = changeV.Encode(),
                ChangeProof = changeProof.ToBytes(),
                SenderBalanceCommitment = trustedBalance.Encode()
            };

            Assert.False(_ct.VerifyTransfer(forged, trustedBalance.Encode()));
        }

        [Fact]
        public void Verify_WrongTrustedBalanceCommitment_Fails()
        {
            // A legitimate bundle, but checked against a balance commitment for a DIFFERENT balance.
            var bundle = _ct.CreateTransfer(senderBalance: 8000, transferAmount: 3000);
            var wrongBalance = PedersenCommitment.Commit(Scalar.From(8000), Scalar.Random());
            Assert.False(_ct.VerifyTransfer(bundle, wrongBalance.Encode()));
        }
    }

    public class SealedBidAuctionTests
    {
        [Fact]
        public void PlaceAndVerify_ValidBid()
        {
            var auction = new SealedBidAuction(minBid: 100, maxBid: 50000);
            var (bid, secret) = auction.PlaceBid(7500);

            Assert.True(auction.VerifyBid(bid));
            Assert.Equal(7500, secret.Amount);
        }

        [Fact]
        public void RevealBid_MatchesOriginal()
        {
            var auction = new SealedBidAuction(100, 50000);
            var (bid, secret) = auction.PlaceBid(12000);

            long? revealed = auction.RevealBid(bid, secret);
            Assert.Equal(12000, revealed);
        }

        [Fact]
        public void RevealBid_ForgedOpening_ReturnsNull()
        {
            var auction = new SealedBidAuction(100, 50000);
            var (bid, _) = auction.PlaceBid(5000);

            var fakeBid2 = auction.PlaceBid(9999);
            long? revealed = auction.RevealBid(bid, fakeBid2.secret);
            Assert.Null(revealed);
        }

        [Fact]
        public void PlaceBid_OutOfRange_Throws()
        {
            var auction = new SealedBidAuction(100, 50000);
            Assert.Throws<ArgumentOutOfRangeException>(() => auction.PlaceBid(50));
            Assert.Throws<ArgumentOutOfRangeException>(() => auction.PlaceBid(60000));
        }

        [Fact]
        public void DetermineWinner_PicksHighest()
        {
            var auction = new SealedBidAuction(100, 50000);

            var (bid1, open1) = auction.PlaceBid(5000);
            var (bid2, open2) = auction.PlaceBid(15000);
            var (bid3, open3) = auction.PlaceBid(8000);

            int winner = auction.DetermineWinner(
                new[] { bid1, bid2, bid3 },
                new[] { open1, open2, open3 });

            Assert.Equal(1, winner);
        }

        [Fact]
        public void PlaceBid_MinimumBid_Valid()
        {
            var auction = new SealedBidAuction(100, 50000);
            var (bid, secret) = auction.PlaceBid(100);
            Assert.True(auction.VerifyBid(bid));
            Assert.Equal(100, auction.RevealBid(bid, secret));
        }

        [Fact]
        public void PlaceBid_MaximumBid_Valid()
        {
            var auction = new SealedBidAuction(100, 50000);
            var (bid, secret) = auction.PlaceBid(50000);
            Assert.True(auction.VerifyBid(bid));
            Assert.Equal(50000, auction.RevealBid(bid, secret));
        }

        // --- H14 malicious-case tests: the maxBid upper bound must be enforced ---

        [Fact]
        public void VerifyBid_AboveMaxBid_Fails()
        {
            const long minBid = 100, maxBid = 50000;
            const long cheating = 1_000_000; // far above maxBid
            var auction = new SealedBidAuction(minBid, maxBid);

            // Attacker builds the commitment C = cheating·G + r·H and a VALID lower proof
            // (cheating − minBid ≥ 0). The upper bound (maxBid − cheating) is negative and cannot
            // be honestly proven, so the attacker can only attach a bogus upper proof.
            var r = Scalar.Random();
            var (lowerProof, vLow) = RangeProof.Prove(Scalar.From(cheating - minBid), r, 64);
            // Bogus upper proof for an unrelated non-negative value.
            var (bogusUpper, _) = RangeProof.Prove(Scalar.From(42), Scalar.Random(), 64);

            var forged = new SealedBid
            {
                Commitment = vLow.Encode(),
                RangeProof = lowerProof.ToBytes(),
                UpperRangeProof = bogusUpper.ToBytes(),
                MinBid = minBid,
                MaxBid = maxBid
            };

            Assert.False(auction.VerifyBid(forged));
        }

        [Fact]
        public void RevealBid_AboveMaxBid_ReturnsNull()
        {
            const long minBid = 100, maxBid = 50000;
            const long cheating = 1_000_000;
            var auction = new SealedBidAuction(minBid, maxBid);

            var r = Scalar.Random();
            var (lowerProof, vLow) = RangeProof.Prove(Scalar.From(cheating - minBid), r, 64);

            var forged = new SealedBid
            {
                Commitment = vLow.Encode(),
                RangeProof = lowerProof.ToBytes(),
                UpperRangeProof = Array.Empty<byte>(),
                MinBid = minBid,
                MaxBid = maxBid
            };
            var opening = new BidOpening { Amount = cheating, BlindingFactor = r.ToBytes() };

            // Even though the opening matches the commitment, the amount is out of range.
            Assert.Null(auction.RevealBid(forged, opening));
        }
    }

    public class PrivateVotingTests
    {
        private readonly PrivateVoting _voting = new();

        [Fact]
        public void CastAndVerify_YesVote()
        {
            var (ballot, _) = _voting.CastVote(true);
            Assert.True(_voting.VerifyBallot(ballot));
        }

        [Fact]
        public void CastAndVerify_NoVote()
        {
            var (ballot, _) = _voting.CastVote(false);
            Assert.True(_voting.VerifyBallot(ballot));
        }

        [Fact]
        public void OpenBallot_RevealsCorrectVote()
        {
            var (ballot, secret) = _voting.CastVote(true);
            bool? vote = _voting.OpenBallot(ballot, secret);
            Assert.True(vote);
        }

        [Fact]
        public void OpenBallot_ForgedSecret_ReturnsNull()
        {
            var (ballot1, _) = _voting.CastVote(true);
            var (_, secret2) = _voting.CastVote(false);
            Assert.Null(_voting.OpenBallot(ballot1, secret2));
        }

        [Fact]
        public void Tally_CorrectCounts()
        {
            var (b1, s1) = _voting.CastVote(true);
            var (b2, s2) = _voting.CastVote(false);
            var (b3, s3) = _voting.CastVote(true);
            var (b4, s4) = _voting.CastVote(true);

            var result = _voting.Tally(
                new[] { b1, b2, b3, b4 },
                new[] { s1, s2, s3, s4 });

            Assert.NotNull(result);
            Assert.Equal(3, result!.YesCount);
            Assert.Equal(1, result.NoCount);
            Assert.Equal(4, result.TotalCount);
        }

        [Fact]
        public void Tally_WithInvalidBallot_ReturnsNull()
        {
            var (b1, s1) = _voting.CastVote(true);
            var (b2, _) = _voting.CastVote(false);
            var (_, s3) = _voting.CastVote(true);

            var result = _voting.Tally(
                new[] { b1, b2 },
                new[] { s1, s3 });

            Assert.Null(result);
        }

        // --- H13 malicious-case tests: a non-binary vote must be rejected ---

        [Theory]
        [InlineData(2L)]
        [InlineData(1000L)]
        public void VerifyBallot_NonBinaryVote_Fails(long maliciousValue)
        {
            // A malicious voter commits to a value outside {0, 1} to inflate the tally.
            // Such a value cannot be proven with a 1-bit range proof, so the attacker can only
            // attach a wider (64-bit) proof -- exactly what the vulnerable code accepted. The
            // hardened VerifyBallot verifies at 1 bit and must reject it.
            var blinding = Scalar.Random();
            var (wideProof, v) = RangeProof.Prove(Scalar.From(maliciousValue), blinding, 64);

            var maliciousBallot = new Ballot
            {
                Commitment = v.Encode(),
                ValidityProof = wideProof.ToBytes()
            };

            Assert.False(_voting.VerifyBallot(maliciousBallot));
        }
    }
}
