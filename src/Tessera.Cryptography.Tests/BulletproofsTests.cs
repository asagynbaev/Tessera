using Xunit;
using Tessera.Cryptography;
using Tessera.Cryptography.Bulletproofs;
using Tessera.Cryptography.Secp256k1;

namespace Tessera.Cryptography.Tests
{
    public class BulletproofsTests
    {
        // Use small n for faster tests where possible
        private const int SmallN = 8;

        #region Inner Product Argument Tests

        [Fact]
        public void InnerProductProof_SmallVectors_ProveAndVerify()
        {
            int n = 4;
            var g = Generators.Gi[..n];
            var h = Generators.Hi[..n];
            var u = Scalar.Random() * Generators.G;

            var a = new Scalar[] { new(1), new(2), new(3), new(4) };
            var b = new Scalar[] { new(5), new(6), new(7), new(8) };
            var c = Scalar.InnerProduct(a, b);

            var P = Point.Infinity;
            for (int i = 0; i < n; i++)
                P = P + a[i] * g[i] + b[i] * h[i];
            P = P + c * u;

            var transcript1 = new Transcript("test_ipa");
            var proof = InnerProductProof.Create(g, h, u, a, b, transcript1);

            var transcript2 = new Transcript("test_ipa");
            bool valid = InnerProductProof.Verify(n, g, h, u, P, proof, transcript2);
            Assert.True(valid);
        }

        [Fact]
        public void InnerProductProof_TamperedProof_Fails()
        {
            int n = 4;
            var g = Generators.Gi[..n];
            var h = Generators.Hi[..n];
            var u = Scalar.Random() * Generators.G;

            var a = new Scalar[] { new(1), new(2), new(3), new(4) };
            var b = new Scalar[] { new(5), new(6), new(7), new(8) };
            var c = Scalar.InnerProduct(a, b);

            var P = Point.Infinity;
            for (int i = 0; i < n; i++)
                P = P + a[i] * g[i] + b[i] * h[i];
            P = P + c * u;

            var transcript1 = new Transcript("test_ipa");
            var proof = InnerProductProof.Create(g, h, u, a, b, transcript1);

            var tampered = new InnerProductProof(proof.Ls, proof.Rs, proof.A + Scalar.One, proof.B);

            var transcript2 = new Transcript("test_ipa");
            bool valid = InnerProductProof.Verify(n, g, h, u, P, tampered, transcript2);
            Assert.False(valid);
        }

        [Fact]
        public void InnerProductProof_SerializationRoundTrip()
        {
            int n = 4;
            var g = Generators.Gi[..n];
            var h = Generators.Hi[..n];
            var u = Scalar.Random() * Generators.G;

            var a = new Scalar[] { new(10), new(20), new(30), new(40) };
            var b = new Scalar[] { new(1), new(2), new(3), new(4) };

            var transcript = new Transcript("test_ipa_ser");
            var proof = InnerProductProof.Create(g, h, u, a, b, transcript);

            var bytes = proof.ToBytes();
            var deserialized = InnerProductProof.FromBytes(bytes);

            Assert.Equal(proof.A, deserialized.A);
            Assert.Equal(proof.B, deserialized.B);
            Assert.Equal(proof.Ls.Length, deserialized.Ls.Length);
        }

        #endregion

        #region Range Proof Tests

        [Fact]
        public void RangeProof_ValidValue_ProvesAndVerifies()
        {
            var v = Scalar.From(42);
            var gamma = Scalar.Random();
            var (proof, V) = RangeProof.Prove(v, gamma, SmallN);
            bool valid = RangeProof.Verify(V, proof, SmallN);
            Assert.True(valid);
        }

        [Fact]
        public void RangeProof_ZeroValue_Succeeds()
        {
            var v = Scalar.Zero;
            var gamma = Scalar.Random();
            var (proof, V) = RangeProof.Prove(v, gamma, SmallN);
            Assert.True(RangeProof.Verify(V, proof, SmallN));
        }

        [Fact]
        public void RangeProof_MaxValue_Succeeds()
        {
            var maxVal = Scalar.From((1L << SmallN) - 1); // 2^n - 1
            var gamma = Scalar.Random();
            var (proof, V) = RangeProof.Prove(maxVal, gamma, SmallN);
            Assert.True(RangeProof.Verify(V, proof, SmallN));
        }

        [Fact]
        public void RangeProof_OutOfRange_ThrowsOnProve()
        {
            var tooLarge = Scalar.From(1L << SmallN); // 2^n, out of range
            var gamma = Scalar.Random();
            Assert.Throws<ArgumentOutOfRangeException>(() => RangeProof.Prove(tooLarge, gamma, SmallN));
        }

        [Fact]
        public void RangeProof_TamperedCommitment_Fails()
        {
            var v = Scalar.From(50);
            var gamma = Scalar.Random();
            var (proof, V) = RangeProof.Prove(v, gamma, SmallN);

            var wrongV = PedersenCommitment.Commit(Scalar.From(51), gamma);
            Assert.False(RangeProof.Verify(wrongV, proof, SmallN));
        }

        [Fact]
        public void RangeProof_SerializationRoundTrip()
        {
            var v = Scalar.From(100);
            var gamma = Scalar.Random();
            var (proof, V) = RangeProof.Prove(v, gamma, SmallN);

            var bytes = proof.ToBytes();
            var deserialized = RangeProof.FromBytes(bytes);

            Assert.True(RangeProof.Verify(V, deserialized, SmallN));
        }

        // Constant-time hardening (Medium finding): the bit split now reads the scalar's fixed 4-limb
        // little-endian form (no BigInteger, no data-dependent shift) and the range check is folded
        // into one overflow mask tested AFTER the fixed-length loop. These tests pin that the split
        // still produces the correct bits (proofs verify) and that out-of-range values are rejected.

        [Fact]
        public void DecomposeBits_AllValuesInRange_ProveAndVerify()
        {
            // Exhaustively confirm the constant-time decomposition yields the correct bits for every
            // value in [0, 2^n): a wrong bit value or order would break tHat and fail verification.
            const int n = 4;
            for (long v = 0; v < (1L << n); v++)
            {
                var gamma = Scalar.Random();
                var (proof, V) = RangeProof.Prove(Scalar.From(v), gamma, n);
                Assert.True(RangeProof.Verify(V, proof, n), $"value {v} failed to verify");
            }
        }

        [Theory]
        [InlineData(1L << 4)]         // 2^n exactly — the first out-of-range value
        [InlineData((1L << 4) + 1)]   // 2^n + 1
        [InlineData(1L << 10)]        // well above range, high bits set
        [InlineData(long.MaxValue)]   // ~2^63, exercises the high limb of the far-past-n overflow scan
        public void DecomposeBits_OutOfRange_RejectedAfterLoop(long v)
        {
            // The overflow check now runs after the fixed-length scan (no per-bit throw), but an
            // out-of-range value must still be rejected before a proof is produced.
            const int n = 4;
            var gamma = Scalar.Random();
            Assert.Throws<ArgumentOutOfRangeException>(() => RangeProof.Prove(Scalar.From(v), gamma, n));
        }

        #endregion

        #region Bitcoin balance range width (satoshis)

        // The default range proof is 64-bit (Generators.DefaultN), so it holds any satoshi amount:
        // 100 BTC ≈ 2^33, the whole 21M-BTC supply ≈ 2^51, and the long ceiling ≈ 2^63 all fit with
        // room to spare. No clamp or scaling is needed for Bitcoin balances (see Sources.Bitcoin README).

        [Theory]
        [InlineData(10_000_000_000L)]        // 100 BTC in sats (~2^33)
        [InlineData(9_900_000_000L)]         // 100 BTC − 1 BTC: the shifted value ProveBoundMinimum proves
        [InlineData(2_100_000_000_000_000L)] // 21,000,000 BTC — the entire money supply (~2^51)
        [InlineData(long.MaxValue)]          // the long ceiling (~2^63), far above any real balance
        public void RangeProof_SatoshiAmount_FitsFullWidth(long sats)
        {
            var gamma = Scalar.Random();
            var (proof, V) = RangeProof.Prove(Scalar.From(sats), gamma, Generators.DefaultN);
            Assert.True(RangeProof.Verify(V, proof, Generators.DefaultN));
        }

        #endregion

        // High-level wrappers (BulletproofsProvider, CredentialProof) live in
        // Tessera.Attestations / legacy Tessera; this package tests primitives only.
    }
}
