using System.Numerics;
using Tessera.Crypto.Secp256k1;

namespace Tessera.Crypto.Bulletproofs
{
    /// <summary>
    /// Bulletproofs range proof: proves v ∈ [0, 2^n) for a Pedersen commitment V = v*G + gamma*H.
    /// Implements Protocol 2 from the Bulletproofs paper (Bunz et al., 2018).
    /// Proof size is O(log n) group elements.
    /// </summary>
    public sealed class RangeProof
    {
        public Point A { get; }
        public Point S { get; }
        public Point T1 { get; }
        public Point T2 { get; }
        public Scalar TauX { get; }
        public Scalar Mu { get; }
        public Scalar THat { get; }
        public InnerProductProof IpaProof { get; }

        private RangeProof(Point a, Point s, Point t1, Point t2,
            Scalar tauX, Scalar mu, Scalar tHat, InnerProductProof ipaProof)
        {
            A = a; S = s; T1 = t1; T2 = t2;
            TauX = tauX; Mu = mu; THat = tHat; IpaProof = ipaProof;
        }

        /// <summary>
        /// Generate a range proof that value v ∈ [0, 2^n).
        /// </summary>
        /// <param name="v">The secret value to prove is in range.</param>
        /// <param name="gamma">The blinding factor for the Pedersen commitment V = v*G + gamma*H.</param>
        /// <param name="n">Number of bits (determines range [0, 2^n)). Must be power of 2.</param>
        /// <returns>The range proof and the commitment V.</returns>
        public static (RangeProof proof, Point V) Prove(Scalar v, Scalar gamma, int n = Generators.DefaultN)
        {
            ValidateN(n);

            var gVec = Generators.Gi[..n];
            var hVec = Generators.Hi[..n];
            var hPoint = Generators.H;

            var V = PedersenCommitment.Commit(v, gamma);

            // Step 1: Compute aL (bit decomposition of v) and aR = aL - 1^n
            var aL = DecomposeBits(v, n);
            var aR = new Scalar[n];
            for (int i = 0; i < n; i++)
                aR[i] = aL[i] - Scalar.One;

            // Step 2: Commit to aL, aR with blinding alpha
            var alpha = Scalar.Random();
            var pointA = alpha * hPoint;
            for (int i = 0; i < n; i++)
                pointA = pointA + aL[i] * gVec[i] + aR[i] * hVec[i];

            // Step 3: Commit to blinding vectors sL, sR with blinding rho
            var sL = RandomScalarVector(n);
            var sR = RandomScalarVector(n);
            var rho = Scalar.Random();
            var pointS = rho * hPoint;
            for (int i = 0; i < n; i++)
                pointS = pointS + sL[i] * gVec[i] + sR[i] * hVec[i];

            // Step 4: Fiat-Shamir challenges y, z
            var transcript = NewTranscript(V, n);
            transcript.AppendPoint("A", pointA);
            transcript.AppendPoint("S", pointS);
            var y = transcript.ChallengeScalar("y");
            var z = transcript.ChallengeScalar("z");

            // Step 5: Compute polynomial t(x) = <l(x), r(x)>
            // l(x) = (aL - z*1^n) + sL*x
            // r(x) = y^n ∘ (aR + z*1^n + sR*x) + z^2 * 2^n
            var yn = PowerVector(y, n);
            var twoN = PowersOfTwo(n);
            var zSq = z.Square();

            // Compute t1, t2 (coefficients of x and x^2 in t(x))
            // t0 = <aL - z, y^n ∘ (aR + z) + z^2 * 2^n>
            // t1 = <sL, y^n ∘ (aR + z) + z^2 * 2^n> + <aL - z, y^n ∘ sR>
            // t2 = <sL, y^n ∘ sR>
            var t1 = Scalar.Zero;
            var t2 = Scalar.Zero;
            for (int i = 0; i < n; i++)
            {
                var lConst = aL[i] - z;
                var rConst = yn[i] * (aR[i] + z) + zSq * twoN[i];
                var rLin = yn[i] * sR[i];

                t1 = t1 + sL[i] * rConst + lConst * rLin;
                t2 = t2 + sL[i] * rLin;
            }

            // Step 6: Commit to t1, t2
            var tau1 = Scalar.Random();
            var tau2 = Scalar.Random();
            var pointT1 = PedersenCommitment.Commit(t1, tau1);
            var pointT2 = PedersenCommitment.Commit(t2, tau2);

            // Step 7: Challenge x
            transcript.AppendPoint("T1", pointT1);
            transcript.AppendPoint("T2", pointT2);
            var x = transcript.ChallengeScalar("x");

            // Step 8: Compute response scalars
            var tauX = tau2 * x.Square() + tau1 * x + zSq * gamma;
            var mu = alpha + rho * x;

            // Evaluate l(x) and r(x) at challenge x
            var lVec = new Scalar[n];
            var rVec = new Scalar[n];
            var tHat = Scalar.Zero;
            for (int i = 0; i < n; i++)
            {
                lVec[i] = (aL[i] - z) + sL[i] * x;
                rVec[i] = yn[i] * (aR[i] + z + sR[i] * x) + zSq * twoN[i];
                tHat = tHat + lVec[i] * rVec[i];
            }

            // Step 9: Run inner product argument
            // Need modified generators h'_i = y^{-i} * h_i
            var hPrime = new Point[n];
            var yInv = y.Inv();
            var yInvPow = Scalar.One;
            for (int i = 0; i < n; i++)
            {
                hPrime[i] = yInvPow * hVec[i];
                yInvPow = yInvPow * yInv;
            }

            // Derive IPA blinding point from transcript
            var uIpa = transcript.ChallengeScalar("ipa_u");
            var uPoint = uIpa * Generators.G;

            var ipaProof = InnerProductProof.Create(gVec, hPrime, uPoint, lVec, rVec, transcript);

            return (new RangeProof(pointA, pointS, pointT1, pointT2, tauX, mu, tHat, ipaProof), V);
        }

        /// <summary>
        /// Verify a range proof against commitment V.
        /// Returns true if the prover knows v ∈ [0, 2^n) such that V = v*G + gamma*H.
        /// </summary>
        public static bool Verify(Point V, RangeProof proof, int n = Generators.DefaultN)
        {
            ValidateN(n);

            var gVec = Generators.Gi[..n];
            var hVec = Generators.Hi[..n];
            var hPoint = Generators.H;

            // Recompute challenges from transcript
            var transcript = NewTranscript(V, n);
            transcript.AppendPoint("A", proof.A);
            transcript.AppendPoint("S", proof.S);
            var y = transcript.ChallengeScalar("y");
            var z = transcript.ChallengeScalar("z");

            transcript.AppendPoint("T1", proof.T1);
            transcript.AppendPoint("T2", proof.T2);
            var x = transcript.ChallengeScalar("x");

            // Check 1: Polynomial evaluation
            // t_hat * G + tau_x * H == delta(y,z) * G + z^2 * V + x * T1 + x^2 * T2
            var zSq = z.Square();
            var delta = ComputeDelta(y, z, n);

            var lhs1 = PedersenCommitment.Commit(proof.THat, proof.TauX);
            var rhs1 = delta * Generators.G + zSq * V + x * proof.T1 + x.Square() * proof.T2;
            if (lhs1 != rhs1)
                return false;

            // Check 2: Inner product argument
            // Compute modified generators h'_i = y^{-i} * h_i
            var hPrime = new Point[n];
            var yInv = y.Inv();
            var yInvPow = Scalar.One;
            for (int i = 0; i < n; i++)
            {
                hPrime[i] = yInvPow * hVec[i];
                yInvPow = yInvPow * yInv;
            }

            // Compute the commitment P for the IPA:
            // P = A + x*S + sum(-z * g_i) + sum((z*y^i + z^2*2^i) * h'_i) - mu * H
            var yn = PowerVector(y, n);
            var twoN = PowersOfTwo(n);

            var P = proof.A + x * proof.S - proof.Mu * hPoint;
            for (int i = 0; i < n; i++)
            {
                P = P + (-z) * gVec[i];
                P = P + (z * yn[i] + zSq * twoN[i]) * hPrime[i];
            }

            // Derive IPA blinding point (must match prover's transcript)
            var uIpa = transcript.ChallengeScalar("ipa_u");
            var uPoint = uIpa * Generators.G;

            // P should equal <l, g> + <r, h'> + t_hat * u
            // The IPA proof proves exactly this
            var pWithIP = P + proof.THat * uPoint;

            return InnerProductProof.Verify(n, gVec, hPrime, uPoint, pWithIP, proof.IpaProof, transcript);
        }

        /// <summary>
        /// Serialize the proof to a compact byte array.
        /// </summary>
        public byte[] ToBytes()
        {
            var ipa = IpaProof.ToBytes();
            var result = new byte[4 * 33 + 3 * 32 + 4 + ipa.Length];
            int offset = 0;

            A.Encode().CopyTo(result, offset); offset += 33;
            S.Encode().CopyTo(result, offset); offset += 33;
            T1.Encode().CopyTo(result, offset); offset += 33;
            T2.Encode().CopyTo(result, offset); offset += 33;
            TauX.ToBytes().CopyTo(result, offset); offset += 32;
            Mu.ToBytes().CopyTo(result, offset); offset += 32;
            THat.ToBytes().CopyTo(result, offset); offset += 32;
            BitConverter.GetBytes(ipa.Length).CopyTo(result, offset); offset += 4;
            ipa.CopyTo(result, offset);

            return result;
        }

        public static RangeProof FromBytes(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);
            const int headerLen = 4 * 33 + 3 * 32 + 4; // 4 points + 3 scalars + ipa-length prefix
            if (data.Length < headerLen)
                throw new FormatException($"RangeProof: data too short ({data.Length} bytes).");
            int offset = 0;
            var a = Point.Decode(data[offset..(offset + 33)]); offset += 33;
            var s = Point.Decode(data[offset..(offset + 33)]); offset += 33;
            var t1 = Point.Decode(data[offset..(offset + 33)]); offset += 33;
            var t2 = Point.Decode(data[offset..(offset + 33)]); offset += 33;
            var tauX = Scalar.FromBytes(data[offset..(offset + 32)]); offset += 32;
            var mu = Scalar.FromBytes(data[offset..(offset + 32)]); offset += 32;
            var tHat = Scalar.FromBytes(data[offset..(offset + 32)]); offset += 32;
            var ipaLen = BitConverter.ToInt32(data, offset); offset += 4;
            // The inner-product blob must consume exactly the remainder; reject otherwise before slicing.
            if (ipaLen < 0 || (long)offset + ipaLen != data.Length)
                throw new FormatException(
                    $"RangeProof: declared inner-product length {ipaLen} is inconsistent with data length {data.Length}.");
            var ipa = InnerProductProof.FromBytes(data[offset..(offset + ipaLen)]);

            return new RangeProof(a, s, t1, t2, tauX, mu, tHat, ipa);
        }

        private static Transcript NewTranscript(Point V, int n)
        {
            var t = new Transcript("Tessera_Bulletproofs_RangeProof");
            t.AppendPoint("V", V);
            t.AppendU64("n", (ulong)n);
            return t;
        }

        /// <summary>
        /// Compute delta(y, z) = (z - z^2) * &lt;1^n, y^n&gt; - z^3 * &lt;1^n, 2^n&gt;
        /// </summary>
        private static Scalar ComputeDelta(Scalar y, Scalar z, int n)
        {
            var zSq = z.Square();
            var zCub = zSq * z;

            // <1^n, y^n> = sum_{i=0}^{n-1} y^i = (y^n - 1) / (y - 1)
            // But to avoid division, just compute directly
            var sumYn = Scalar.Zero;
            var yPow = Scalar.One;
            for (int i = 0; i < n; i++)
            {
                sumYn = sumYn + yPow;
                yPow = yPow * y;
            }

            // <1^n, 2^n> = 2^n - 1
            var sumTwoN = Scalar.Zero;
            var twoPow = Scalar.One;
            for (int i = 0; i < n; i++)
            {
                sumTwoN = sumTwoN + twoPow;
                twoPow = twoPow * Scalar.Two;
            }

            return (z - zSq) * sumYn - zCub * sumTwoN;
        }

        /// <summary>
        /// Decompose a scalar into its binary representation as a vector of 0/1 scalars.
        /// Least significant bit first.
        /// </summary>
        private static Scalar[] DecomposeBits(Scalar v, int n)
        {
            var bits = new Scalar[n];
            var val = v.Value;
            for (int i = 0; i < n; i++)
            {
                bits[i] = (val & BigInteger.One) == BigInteger.One ? Scalar.One : Scalar.Zero;
                val >>= 1;
            }
            if (val > BigInteger.Zero)
                throw new ArgumentOutOfRangeException(nameof(v), "Value does not fit in n bits.");
            return bits;
        }

        private static Scalar[] PowerVector(Scalar base_, int n)
        {
            var result = new Scalar[n];
            result[0] = Scalar.One;
            for (int i = 1; i < n; i++)
                result[i] = result[i - 1] * base_;
            return result;
        }

        private static Scalar[] PowersOfTwo(int n)
        {
            var result = new Scalar[n];
            result[0] = Scalar.One;
            for (int i = 1; i < n; i++)
                result[i] = result[i - 1] * Scalar.Two;
            return result;
        }

        private static Scalar[] RandomScalarVector(int n)
        {
            var result = new Scalar[n];
            for (int i = 0; i < n; i++)
                result[i] = Scalar.Random();
            return result;
        }

        private static void ValidateN(int n)
        {
            if (n <= 0 || (n & (n - 1)) != 0)
                throw new ArgumentException("n must be a positive power of 2.", nameof(n));
            if (n > Generators.DefaultN)
                throw new ArgumentException($"n must be <= {Generators.DefaultN}.", nameof(n));
        }
    }
}
