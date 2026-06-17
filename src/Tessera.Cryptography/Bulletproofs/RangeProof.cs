using System.Numerics;
using Tessera.Cryptography.Secp256k1;

namespace Tessera.Cryptography.Bulletproofs
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

        public static (RangeProof proof, Point V) Prove(Scalar v, Scalar gamma, int n = Generators.DefaultN)
        {
            ValidateN(n);
            var gVec = Generators.Gi[..n];
            var hVec = Generators.Hi[..n];
            var hPoint = Generators.H;
            var V = PedersenCommitment.Commit(v, gamma);

            var aL = DecomposeBits(v, n);
            var aR = new Scalar[n];
            for (int i = 0; i < n; i++) aR[i] = aL[i] - Scalar.One;

            var alpha = Scalar.Random();
            var pointA = alpha * hPoint;
            for (int i = 0; i < n; i++) pointA = pointA + aL[i] * gVec[i] + aR[i] * hVec[i];

            var sL = RandomScalarVector(n);
            var sR = RandomScalarVector(n);
            var rho = Scalar.Random();
            var pointS = rho * hPoint;
            for (int i = 0; i < n; i++) pointS = pointS + sL[i] * gVec[i] + sR[i] * hVec[i];

            var transcript = NewTranscript(V, n);
            transcript.AppendPoint("A", pointA);
            transcript.AppendPoint("S", pointS);
            var y = transcript.ChallengeScalar("y");
            var z = transcript.ChallengeScalar("z");

            var yn = PowerVector(y, n);
            var twoN = PowersOfTwo(n);
            var zSq = z.Square();

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

            var tau1 = Scalar.Random();
            var tau2 = Scalar.Random();
            var pointT1 = PedersenCommitment.Commit(t1, tau1);
            var pointT2 = PedersenCommitment.Commit(t2, tau2);

            transcript.AppendPoint("T1", pointT1);
            transcript.AppendPoint("T2", pointT2);
            var x = transcript.ChallengeScalar("x");

            var tauX = tau2 * x.Square() + tau1 * x + zSq * gamma;
            var mu = alpha + rho * x;

            var lVec = new Scalar[n];
            var rVec = new Scalar[n];
            var tHat = Scalar.Zero;
            for (int i = 0; i < n; i++)
            {
                lVec[i] = (aL[i] - z) + sL[i] * x;
                rVec[i] = yn[i] * (aR[i] + z + sR[i] * x) + zSq * twoN[i];
                tHat = tHat + lVec[i] * rVec[i];
            }

            var hPrime = new Point[n];
            var yInv = y.Inv();
            var yInvPow = Scalar.One;
            for (int i = 0; i < n; i++)
            {
                hPrime[i] = yInvPow * hVec[i];
                yInvPow = yInvPow * yInv;
            }

            var uIpa = transcript.ChallengeScalar("ipa_u");
            var uPoint = uIpa * Generators.G;
            var ipaProof = InnerProductProof.Create(gVec, hPrime, uPoint, lVec, rVec, transcript);

            return (new RangeProof(pointA, pointS, pointT1, pointT2, tauX, mu, tHat, ipaProof), V);
        }

        public static bool Verify(Point V, RangeProof proof, int n = Generators.DefaultN)
        {
            ValidateN(n);
            var gVec = Generators.Gi[..n];
            var hVec = Generators.Hi[..n];
            var hPoint = Generators.H;

            var transcript = NewTranscript(V, n);
            transcript.AppendPoint("A", proof.A);
            transcript.AppendPoint("S", proof.S);
            var y = transcript.ChallengeScalar("y");
            var z = transcript.ChallengeScalar("z");

            transcript.AppendPoint("T1", proof.T1);
            transcript.AppendPoint("T2", proof.T2);
            var x = transcript.ChallengeScalar("x");

            var zSq = z.Square();
            var delta = ComputeDelta(y, z, n);

            var lhs1 = PedersenCommitment.Commit(proof.THat, proof.TauX);
            var rhs1 = delta * Generators.G + zSq * V + x * proof.T1 + x.Square() * proof.T2;
            if (lhs1 != rhs1) return false;

            var hPrime = new Point[n];
            var yInv = y.Inv();
            var yInvPow = Scalar.One;
            for (int i = 0; i < n; i++)
            {
                hPrime[i] = yInvPow * hVec[i];
                yInvPow = yInvPow * yInv;
            }

            var yn = PowerVector(y, n);
            var twoN = PowersOfTwo(n);

            var P = proof.A + x * proof.S - proof.Mu * hPoint;
            for (int i = 0; i < n; i++)
            {
                P = P + (-z) * gVec[i];
                P = P + (z * yn[i] + zSq * twoN[i]) * hPrime[i];
            }

            var uIpa = transcript.ChallengeScalar("ipa_u");
            var uPoint = uIpa * Generators.G;
            var pWithIP = P + proof.THat * uPoint;

            return InnerProductProof.Verify(n, gVec, hPrime, uPoint, pWithIP, proof.IpaProof, transcript);
        }

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
            // Fixed header: 4 points (33 each) + 3 scalars (32 each) + a 4-byte inner-product length.
            const int headerLen = 4 * 33 + 3 * 32 + 4;
            if (data.Length < headerLen)
                throw new FormatException($"RangeProof: data too short ({data.Length} bytes).");
            int offset = 0;
            var a = Point.Decode(data[offset..(offset + 33)]); offset += 33;
            var s = Point.Decode(data[offset..(offset + 33)]); offset += 33;
            var t1 = Point.Decode(data[offset..(offset + 33)]); offset += 33;
            var t2 = Point.Decode(data[offset..(offset + 33)]); offset += 33;
            var tauX = Scalar.FromCanonicalBytes(data[offset..(offset + 32)]); offset += 32;
            var mu = Scalar.FromCanonicalBytes(data[offset..(offset + 32)]); offset += 32;
            var tHat = Scalar.FromCanonicalBytes(data[offset..(offset + 32)]); offset += 32;
            var ipaLen = BitConverter.ToInt32(data, offset); offset += 4;
            // The inner-product blob must consume exactly the rest of the buffer; reject any other
            // length before slicing/allocating (closes the same allocation-DoS at this layer).
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

        private static Scalar ComputeDelta(Scalar y, Scalar z, int n)
        {
            var zSq = z.Square();
            var zCub = zSq * z;
            var sumYn = Scalar.Zero;
            var yPow = Scalar.One;
            for (int i = 0; i < n; i++) { sumYn = sumYn + yPow; yPow = yPow * y; }
            var sumTwoN = Scalar.Zero;
            var twoPow = Scalar.One;
            for (int i = 0; i < n; i++) { sumTwoN = sumTwoN + twoPow; twoPow = twoPow * Scalar.Two; }
            return (z - zSq) * sumYn - zCub * sumTwoN;
        }

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
            for (int i = 1; i < n; i++) result[i] = result[i - 1] * base_;
            return result;
        }

        private static Scalar[] PowersOfTwo(int n)
        {
            var result = new Scalar[n];
            result[0] = Scalar.One;
            for (int i = 1; i < n; i++) result[i] = result[i - 1] * Scalar.Two;
            return result;
        }

        private static Scalar[] RandomScalarVector(int n)
        {
            var result = new Scalar[n];
            for (int i = 0; i < n; i++) result[i] = Scalar.Random();
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
