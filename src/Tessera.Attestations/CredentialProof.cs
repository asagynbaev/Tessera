using Tessera.Cryptography;
using Tessera.Cryptography.Bulletproofs;
using Tessera.Cryptography.Secp256k1;

namespace Tessera.Attestations
{
    /// <summary>
    /// Predicate proof over a committed attestation value.
    /// Proves a numeric attribute (income, score, age, balance) meets a threshold or lies
    /// within a range without revealing the actual value. Built on Bulletproofs over secp256k1.
    /// </summary>
    public class CredentialProof
    {
        private const int BitSize = 64;

        /// <summary>
        /// Prove that <paramref name="actualValue"/> ≥ <paramref name="minimumRequired"/>.
        /// </summary>
        public CredentialBundle ProveMinimum(long actualValue, long minimumRequired, string label)
        {
            if (actualValue < minimumRequired)
                throw new ArgumentException($"Value {actualValue} does not meet minimum {minimumRequired}.");

            long shifted = actualValue - minimumRequired;
            var blinding = Scalar.Random();
            var (proof, V) = RangeProof.Prove(Scalar.From(shifted), blinding, BitSize);

            return new CredentialBundle
            {
                Label = label,
                Commitment = V.Encode(),
                RangeProof = proof.ToBytes(),
                Threshold = minimumRequired,
                ProofType = CredentialProofType.Minimum,
            };
        }

        /// <summary>
        /// Prove that <paramref name="actualValue"/> ∈ [<paramref name="min"/>, <paramref name="max"/>].
        /// </summary>
        public CredentialBundle ProveRange(long actualValue, long min, long max, string label)
        {
            if (actualValue < min || actualValue > max)
                throw new ArgumentOutOfRangeException(nameof(actualValue), $"Value not in [{min}, {max}].");

            long shifted = actualValue - min;
            var blinding = Scalar.Random();
            var (proof, V) = RangeProof.Prove(Scalar.From(shifted), blinding, BitSize);

            return new CredentialBundle
            {
                Label = label,
                Commitment = V.Encode(),
                RangeProof = proof.ToBytes(),
                Threshold = min,
                UpperBound = max,
                ProofType = CredentialProofType.Range,
            };
        }

        /// <summary>
        /// Verify a credential bundle without learning the underlying value.
        /// </summary>
        /// <remarks>
        /// This is the <b>unbound</b> check: it confirms the range proof is valid for the bundle's
        /// own commitment, but NOT that the commitment is the one inside any particular attestation.
        /// For attestation-bound verification (the sound path used by the verification policy) use
        /// <see cref="VerifyBound"/>.
        /// </remarks>
        public bool Verify(CredentialBundle credential)
        {
            if (credential?.RangeProof == null || credential.Commitment == null)
                return false;
            try
            {
                var V = Point.Decode(credential.Commitment);
                var proof = RangeProof.FromBytes(credential.RangeProof);
                return RangeProof.Verify(V, proof, BitSize);
            }
            catch { return false; }
        }

        // ── Attestation-bound predicate proofs ───────────────────────────────
        //
        // The issuer commits to a value as C = value·G + r·H in the attestation payload and hands
        // the holder the opening (r). To prove value ≥ threshold BOUND to that attestation, the
        // holder proves the committed value of C' = C − threshold·G is non-negative, reusing r as
        // the blinding so the proof's commitment V == C'. A verifier that knows C recomputes
        // C − threshold·G and checks it equals V, binding the proof to THIS attested value — a
        // holder cannot substitute a proof about a different value.

        /// <summary>
        /// Commit to <paramref name="value"/> with a fresh blinding. Returns the SEC1-encoded
        /// commitment (put this in the attestation's <c>Payload.Commitment</c>) and the opaque
        /// opening the holder keeps secret to later build bound predicate proofs.
        /// </summary>
        public (byte[] Commitment, byte[] Opening) CommitValue(long value)
        {
            var blinding = Scalar.Random();
            var commitment = PedersenCommitment.Commit(Scalar.From(value), blinding);
            return (commitment.Encode(), blinding.ToBytes());
        }

        /// <summary>
        /// Prove <paramref name="actualValue"/> ≥ <paramref name="minimumRequired"/>, bound to the
        /// commitment produced by <see cref="CommitValue"/> with <paramref name="opening"/>.
        /// </summary>
        public CredentialBundle ProveBoundMinimum(long actualValue, long minimumRequired, byte[] opening, string label)
        {
            if (actualValue < minimumRequired)
                throw new ArgumentException($"Value {actualValue} does not meet minimum {minimumRequired}.");
            ArgumentNullException.ThrowIfNull(opening);

            var blinding = Scalar.FromBytes(opening);
            long shifted = actualValue - minimumRequired;
            var (proof, V) = RangeProof.Prove(Scalar.From(shifted), blinding, BitSize);

            return new CredentialBundle
            {
                Label = label,
                Commitment = V.Encode(),
                RangeProof = proof.ToBytes(),
                Threshold = minimumRequired,
                ProofType = CredentialProofType.Minimum,
            };
        }

        /// <summary>
        /// Prove <paramref name="actualValue"/> ∈ [<paramref name="min"/>, <paramref name="max"/>],
        /// bound to the commitment from <see cref="CommitValue"/>. BOTH bounds are cryptographically
        /// proven: a lower proof that <c>value − min ≥ 0</c> (commitment <c>C − min·G</c>) and an upper
        /// proof that <c>max − value ≥ 0</c> (commitment <c>max·G − C</c>, blinding negated).
        /// </summary>
        public CredentialBundle ProveBoundRange(long actualValue, long min, long max, byte[] opening, string label)
        {
            if (min > max)
                throw new ArgumentException($"min ({min}) must not exceed max ({max}).", nameof(min));
            if (actualValue < min || actualValue > max)
                throw new ArgumentOutOfRangeException(nameof(actualValue), $"Value not in [{min}, {max}].");
            ArgumentNullException.ThrowIfNull(opening);

            var blinding = Scalar.FromBytes(opening);

            // Lower side: value − min ∈ [0, 2^n), commitment V_low = C − min·G.
            var (lowProof, vLow) = RangeProof.Prove(Scalar.From(actualValue - min), blinding, BitSize);

            // Upper side: max − value ∈ [0, 2^n), commitment V_high = max·G − C = (max−value)·G + (−r)·H.
            var (highProof, _) = RangeProof.Prove(Scalar.From(max - actualValue), -blinding, BitSize);

            return new CredentialBundle
            {
                Label = label,
                Commitment = vLow.Encode(),
                RangeProof = lowProof.ToBytes(),
                UpperRangeProof = highProof.ToBytes(),
                Threshold = min,
                UpperBound = max,
                ProofType = CredentialProofType.Range,
            };
        }

        /// <summary>
        /// Verify a predicate bundle BOUND to an attestation commitment. For a Minimum proof: the
        /// bundle commitment must equal <c>C − threshold·G</c> and the range proof must verify. For a
        /// two-sided Range proof: the lower proof must verify against <c>C − min·G</c> AND the upper
        /// proof against <c>max·G − C</c>, so both bounds are enforced. Never throws — returns false
        /// on malformed input.
        /// </summary>
        public bool VerifyBound(byte[] attestationCommitment, CredentialBundle credential)
        {
            if (attestationCommitment is null || credential?.Commitment is null || credential.RangeProof is null)
                return false;
            if (credential.Threshold < 0)
                return false;
            try
            {
                var c = Point.Decode(attestationCommitment);
                var vLow = Point.Decode(credential.Commitment);

                // Binding (lower): the proof's commitment is C − threshold·G for THIS attestation.
                var expectedLow = c - Scalar.From(credential.Threshold) * Generators.G;
                if (vLow != expectedLow)
                    return false;
                if (!RangeProof.Verify(vLow, RangeProof.FromBytes(credential.RangeProof), BitSize))
                    return false;

                if (credential.ProofType != CredentialProofType.Range)
                    return true; // Minimum: lower bound only

                // Two-sided Range: also verify the upper proof against max·G − C.
                if (credential.UpperBound is not { } max || credential.UpperRangeProof is null)
                    return false; // a Range bundle without an upper proof is not a valid two-sided proof
                if (max < credential.Threshold)
                    return false;

                var vHigh = Scalar.From(max) * Generators.G - c;
                return RangeProof.Verify(vHigh, RangeProof.FromBytes(credential.UpperRangeProof), BitSize);
            }
            catch { return false; }
        }

        public string Serialize(CredentialBundle bundle)
        {
            using var ms = new MemoryStream();
            using var w = new BinaryWriter(ms);
            w.Write(bundle.Label ?? "");
            w.Write((int)bundle.ProofType);
            w.Write(bundle.Threshold);
            w.Write(bundle.UpperBound ?? 0L);
            w.Write(bundle.Commitment.Length);
            w.Write(bundle.Commitment);
            w.Write(bundle.RangeProof.Length);
            w.Write(bundle.RangeProof);
            // Upper-bound proof (two-sided Range). Length-prefixed; 0 = absent. Appended last so
            // older single-proof blobs (which simply end here) still deserialize.
            var upperProof = bundle.UpperRangeProof ?? Array.Empty<byte>();
            w.Write(upperProof.Length);
            w.Write(upperProof);
            return Convert.ToBase64String(ms.ToArray());
        }

        public CredentialBundle Deserialize(string data)
        {
            var bytes = Convert.FromBase64String(data);
            using var ms = new MemoryStream(bytes);
            using var r = new BinaryReader(ms);
            var label = r.ReadString();
            var proofType = (CredentialProofType)r.ReadInt32();
            var threshold = r.ReadInt64();
            var upper = r.ReadInt64();
            int cLen = r.ReadInt32();
            var commitment = r.ReadBytes(cLen);
            int pLen = r.ReadInt32();
            var proof = r.ReadBytes(pLen);

            byte[]? upperProof = null;
            if (ms.Position < ms.Length)
            {
                int uLen = r.ReadInt32();
                if (uLen > 0) upperProof = r.ReadBytes(uLen);
            }

            return new CredentialBundle
            {
                Label = label,
                ProofType = proofType,
                Threshold = threshold,
                UpperBound = proofType == CredentialProofType.Range ? upper : null,
                Commitment = commitment,
                RangeProof = proof,
                UpperRangeProof = upperProof,
            };
        }
    }

    /// <summary>A verifiable credential bundle. Contains no secret values — safe to share.</summary>
    public class CredentialBundle
    {
        public string Label { get; init; } = "";
        public byte[] Commitment { get; init; } = Array.Empty<byte>();

        /// <summary>The lower-bound range proof (value − Threshold ≥ 0).</summary>
        public byte[] RangeProof { get; init; } = Array.Empty<byte>();

        /// <summary>
        /// The upper-bound range proof (UpperBound − value ≥ 0), present for two-sided bound Range
        /// proofs. Null for Minimum (and legacy one-sided) bundles.
        /// </summary>
        public byte[]? UpperRangeProof { get; init; }

        public long Threshold { get; init; }
        public long? UpperBound { get; init; }
        public CredentialProofType ProofType { get; init; }
    }

    public enum CredentialProofType
    {
        Minimum,
        Range,
    }
}
