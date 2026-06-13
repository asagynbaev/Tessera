using Tessera.Crypto;
using Tessera.Crypto.Bulletproofs;
using Tessera.Crypto.Secp256k1;

namespace Tessera.Examples.PrivacyApps
{
    /// <summary>
    /// Confidential transfers: hide the amount being transferred while proving
    /// it is non-negative and does not exceed the sender's balance.
    /// Uses Pedersen commitments (computationally hiding) and Bulletproofs range proofs.
    ///
    /// Soundness rests on THREE checks, all required:
    ///   (1) amount ≥ 0          (range proof on the amount commitment),
    ///   (2) change ≥ 0          (range proof on the change commitment), and
    ///   (3) balance conservation: <c>AmountCommitment + ChangeCommitment == SenderBalanceCommitment</c>
    ///       as secp256k1 points, via the additive homomorphism of Pedersen commitments.
    /// Check (3) is what stops a sender from inflating value: without it, the two range proofs
    /// only show two independent non-negative numbers, never that they sum to the prior balance.
    /// </summary>
    public class ConfidentialTransfer
    {
        private const int BitSize = 64;

        /// <summary>
        /// Creates a confidential transfer. The amount is cryptographically hidden
        /// in a Pedersen commitment. Two range proofs ensure (1) amount >= 0 and
        /// (2) change (balance - amount) >= 0; the returned <see cref="TransferBundle.SenderBalanceCommitment"/>
        /// lets a verifier additionally check balance conservation. The blinding factors are chosen so
        /// that <c>Commit(amount) + Commit(change) == Commit(balance)</c> holds exactly.
        /// Neither the amount nor the balance is revealed to the verifier.
        /// </summary>
        /// <param name="senderBalance">Sender's current balance.</param>
        /// <param name="transferAmount">Amount to transfer (hidden from verifier).</param>
        /// <returns>A transfer proof that can be published without revealing the amount.</returns>
        public TransferBundle CreateTransfer(long senderBalance, long transferAmount)
        {
            if (transferAmount < 0)
                throw new ArgumentOutOfRangeException(nameof(transferAmount));
            if (transferAmount > senderBalance)
                throw new ArgumentException("Insufficient balance.");

            long change = senderBalance - transferAmount;

            var amountBlinding = Scalar.Random();
            var (amountProof, amountV) = RangeProof.Prove(Scalar.From(transferAmount), amountBlinding, BitSize);

            var changeBlinding = Scalar.Random();
            var (changeProof, changeV) = RangeProof.Prove(Scalar.From(change), changeBlinding, BitSize);

            // The sender's pre-transfer balance commitment. By the homomorphism,
            // Commit(amount, rA) + Commit(change, rC) == Commit(amount + change, rA + rC)
            //                                          == Commit(balance, rA + rC),
            // so we publish exactly that point and the verifier re-checks the equality.
            var balanceV = PedersenCommitment.Commit(Scalar.From(senderBalance), amountBlinding + changeBlinding);

            return new TransferBundle
            {
                AmountCommitment = amountV.Encode(),
                AmountProof = amountProof.ToBytes(),
                ChangeCommitment = changeV.Encode(),
                ChangeProof = changeProof.ToBytes(),
                SenderBalanceCommitment = balanceV.Encode()
            };
        }

        /// <summary>
        /// Verifies that a confidential transfer is valid against a trusted pre-transfer balance
        /// commitment. Checks both range proofs AND balance conservation
        /// (<c>AmountCommitment + ChangeCommitment == senderBalanceCommitment</c>) without learning
        /// the transfer amount. The verifier MUST supply the balance commitment it independently
        /// trusts (e.g. the sender's prior on-ledger commitment) -- passing the bundle's own value
        /// blindly would defeat the conservation check.
        /// </summary>
        /// <param name="bundle">The transfer bundle (commitments + range proofs).</param>
        /// <param name="senderBalanceCommitment">SEC1-encoded commitment to the sender's pre-transfer balance.</param>
        public bool VerifyTransfer(TransferBundle bundle, byte[] senderBalanceCommitment)
        {
            if (bundle?.AmountProof == null || bundle.ChangeProof == null
                || bundle.AmountCommitment == null || bundle.ChangeCommitment == null
                || senderBalanceCommitment == null)
                return false;
            try
            {
                var amountV = Point.Decode(bundle.AmountCommitment);
                var changeV = Point.Decode(bundle.ChangeCommitment);
                var balanceV = Point.Decode(senderBalanceCommitment);

                // (3) Balance conservation: the hidden amount and change must sum to the prior balance.
                if (amountV + changeV != balanceV)
                    return false;

                // (1) amount ≥ 0
                var amountRp = RangeProof.FromBytes(bundle.AmountProof);
                if (!RangeProof.Verify(amountV, amountRp, BitSize))
                    return false;

                // (2) change ≥ 0
                var changeRp = RangeProof.FromBytes(bundle.ChangeProof);
                return RangeProof.Verify(changeV, changeRp, BitSize);
            }
            catch { return false; }
        }

        /// <summary>
        /// Convenience overload that verifies against the balance commitment embedded in the bundle.
        /// Only as trustworthy as the bundle itself -- prefer
        /// <see cref="VerifyTransfer(TransferBundle, byte[])"/> with an independently trusted
        /// balance commitment in real deployments.
        /// </summary>
        public bool VerifyTransfer(TransferBundle bundle)
            => bundle != null && VerifyTransfer(bundle, bundle.SenderBalanceCommitment);

        /// <summary>Serializes a transfer bundle to a Base64 string for storage or transmission.</summary>
        public string Serialize(TransferBundle bundle)
        {
            using var ms = new MemoryStream();
            using var w = new BinaryWriter(ms);
            WriteField(w, bundle.AmountCommitment);
            WriteField(w, bundle.AmountProof);
            WriteField(w, bundle.ChangeCommitment);
            WriteField(w, bundle.ChangeProof);
            WriteField(w, bundle.SenderBalanceCommitment);
            return Convert.ToBase64String(ms.ToArray());
        }

        /// <summary>Deserializes a transfer bundle from a Base64 string.</summary>
        public TransferBundle Deserialize(string data)
        {
            var bytes = Convert.FromBase64String(data);
            using var ms = new MemoryStream(bytes);
            using var r = new BinaryReader(ms);
            return new TransferBundle
            {
                AmountCommitment = ReadField(r),
                AmountProof = ReadField(r),
                ChangeCommitment = ReadField(r),
                ChangeProof = ReadField(r),
                SenderBalanceCommitment = ReadField(r)
            };
        }

        private static void WriteField(BinaryWriter w, byte[] data)
        {
            w.Write(data.Length);
            w.Write(data);
        }

        private static byte[] ReadField(BinaryReader r)
        {
            int len = r.ReadInt32();
            return r.ReadBytes(len);
        }
    }

    /// <summary>
    /// A confidential transfer bundle containing commitments and range proofs
    /// for both the transfer amount and the change. No secret values are included.
    /// </summary>
    public class TransferBundle
    {
        /// <summary>Pedersen commitment to the transfer amount (33 bytes, compressed secp256k1 point).</summary>
        public byte[] AmountCommitment { get; init; } = Array.Empty<byte>();
        /// <summary>Bulletproofs range proof that the amount is non-negative.</summary>
        public byte[] AmountProof { get; init; } = Array.Empty<byte>();
        /// <summary>Pedersen commitment to the change (balance - amount).</summary>
        public byte[] ChangeCommitment { get; init; } = Array.Empty<byte>();
        /// <summary>Bulletproofs range proof that the change is non-negative.</summary>
        public byte[] ChangeProof { get; init; } = Array.Empty<byte>();
        /// <summary>
        /// Pedersen commitment to the sender's pre-transfer balance. Used to verify balance
        /// conservation: <c>AmountCommitment + ChangeCommitment == SenderBalanceCommitment</c>.
        /// In a real deployment the verifier supplies its own trusted value to
        /// <see cref="ConfidentialTransfer.VerifyTransfer(TransferBundle, byte[])"/> rather than
        /// relying on this field.
        /// </summary>
        public byte[] SenderBalanceCommitment { get; init; } = Array.Empty<byte>();
    }
}
