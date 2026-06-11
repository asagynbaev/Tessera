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
