using Tessera.Cryptography.Secp256k1;

namespace Tessera.Cryptography.Bulletproofs
{
    /// <summary>
    /// Inner product argument proof from Section 3 of the Bulletproofs paper.
    /// Proves knowledge of vectors a, b such that P = &lt;a,G&gt; + &lt;b,H&gt; + &lt;a,b&gt;*U
    /// with proof size O(log n) instead of O(n).
    /// </summary>
    public sealed class InnerProductProof
    {
        public Point[] Ls { get; }
        public Point[] Rs { get; }
        public Scalar A { get; }
        public Scalar B { get; }

        public InnerProductProof(Point[] ls, Point[] rs, Scalar a, Scalar b)
        {
            Ls = ls; Rs = rs; A = a; B = b;
        }

        public static InnerProductProof Create(
            Point[] gVec, Point[] hVec, Point u,
            Scalar[] aVec, Scalar[] bVec,
            Transcript transcript)
        {
            int n = aVec.Length;
            if (n != bVec.Length || n != gVec.Length || n != hVec.Length)
                throw new ArgumentException("All vectors must have equal length.");
            if ((n & (n - 1)) != 0 || n == 0)
                throw new ArgumentException("Vector length must be a positive power of 2.");

            var a = (Scalar[])aVec.Clone();
            var b = (Scalar[])bVec.Clone();
            var g = (Point[])gVec.Clone();
            var h = (Point[])hVec.Clone();

            var lList = new List<Point>();
            var rList = new List<Point>();
            int currentN = n;

            while (currentN > 1)
            {
                int half = currentN / 2;
                var cL = ComputeInnerProduct(a, 0, b, half, half);
                var cR = ComputeInnerProduct(a, half, b, 0, half);
                var L = ComputeLR(a, 0, g, half, b, half, h, 0, half, cL, u);
                var R = ComputeLR(a, half, g, 0, b, 0, h, half, half, cR, u);
                lList.Add(L); rList.Add(R);

                transcript.AppendPoint("L", L);
                transcript.AppendPoint("R", R);
                var x = transcript.ChallengeScalar("ipa_x");
                var xInv = x.Inv();

                var aNew = new Scalar[half];
                var bNew = new Scalar[half];
                var gNew = new Point[half];
                var hNew = new Point[half];

                for (int i = 0; i < half; i++)
                {
                    aNew[i] = x * a[i] + xInv * a[half + i];
                    bNew[i] = xInv * b[i] + x * b[half + i];
                    gNew[i] = Point.Add(xInv * g[i], x * g[half + i]);
                    hNew[i] = Point.Add(x * h[i], xInv * h[half + i]);
                }

                a = aNew; b = bNew; g = gNew; h = hNew;
                currentN = half;
            }

            return new InnerProductProof(lList.ToArray(), rList.ToArray(), a[0], b[0]);
        }

        public static bool Verify(
            int n,
            Point[] gVec, Point[] hVec, Point u,
            Point P,
            InnerProductProof proof,
            Transcript transcript)
        {
            int k = proof.Ls.Length;
            if (n != (1 << k))
                throw new ArgumentException($"n={n} must equal 2^k where k={k} is the number of rounds.");

            var challenges = new Scalar[k];
            var challengeInvs = new Scalar[k];
            for (int j = 0; j < k; j++)
            {
                transcript.AppendPoint("L", proof.Ls[j]);
                transcript.AppendPoint("R", proof.Rs[j]);
                challenges[j] = transcript.ChallengeScalar("ipa_x");
                challengeInvs[j] = challenges[j].Inv();
            }

            var rhs = P;
            for (int j = 0; j < k; j++)
            {
                var xSq = challenges[j].Square();
                var xInvSq = challengeInvs[j].Square();
                rhs = rhs + xSq * proof.Ls[j] + xInvSq * proof.Rs[j];
            }

            var sG = new Scalar[n];
            var sH = new Scalar[n];
            for (int i = 0; i < n; i++)
            {
                sG[i] = Scalar.One;
                sH[i] = Scalar.One;
                for (int j = 0; j < k; j++)
                {
                    bool bit = ((i >> (k - 1 - j)) & 1) == 1;
                    sG[i] = sG[i] * (bit ? challenges[j] : challengeInvs[j]);
                    sH[i] = sH[i] * (bit ? challengeInvs[j] : challenges[j]);
                }
            }

            var ab = proof.A * proof.B;
            var lhs = ab * u;
            for (int i = 0; i < n; i++)
                lhs = lhs + (proof.A * sG[i]) * gVec[i] + (proof.B * sH[i]) * hVec[i];

            return lhs == rhs;
        }

        public byte[] ToBytes()
        {
            int k = Ls.Length;
            var result = new byte[4 + k * 33 * 2 + 64];
            BitConverter.GetBytes(k).CopyTo(result, 0);
            int offset = 4;
            for (int i = 0; i < k; i++) { Ls[i].Encode().CopyTo(result, offset); offset += 33; }
            for (int i = 0; i < k; i++) { Rs[i].Encode().CopyTo(result, offset); offset += 33; }
            A.ToBytes().CopyTo(result, offset); offset += 32;
            B.ToBytes().CopyTo(result, offset);
            return result;
        }

        public static InnerProductProof FromBytes(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);
            // A well-formed proof is exactly 4 + k*33*2 + 64 bytes, so the round count k is fully
            // determined by the buffer length. Validate that BEFORE allocating Point[k] — otherwise a
            // crafted k (read straight from attacker bytes) drives an unbounded allocation (DoS).
            if (data.Length < 4 + 64)
                throw new FormatException($"InnerProductProof: data too short ({data.Length} bytes).");
            int k = BitConverter.ToInt32(data, 0);
            if (k < 0 || (long)data.Length != 4L + (long)k * 66 + 64)
                throw new FormatException(
                    $"InnerProductProof: declared round count {k} is inconsistent with data length {data.Length}.");
            int offset = 4;
            var ls = new Point[k];
            for (int i = 0; i < k; i++) { ls[i] = Point.Decode(data[offset..(offset + 33)]); offset += 33; }
            var rs = new Point[k];
            for (int i = 0; i < k; i++) { rs[i] = Point.Decode(data[offset..(offset + 33)]); offset += 33; }
            var a = Scalar.FromBytes(data[offset..(offset + 32)]); offset += 32;
            var b = Scalar.FromBytes(data[offset..(offset + 32)]);
            return new InnerProductProof(ls, rs, a, b);
        }

        private static Scalar ComputeInnerProduct(Scalar[] a, int aOffset, Scalar[] b, int bOffset, int len)
        {
            var sum = Scalar.Zero;
            for (int i = 0; i < len; i++) sum = sum + a[aOffset + i] * b[bOffset + i];
            return sum;
        }

        private static Point ComputeLR(
            Scalar[] a, int aOff, Point[] g, int gOff,
            Scalar[] b, int bOff, Point[] h, int hOff,
            int len, Scalar c, Point u)
        {
            var result = c * u;
            for (int i = 0; i < len; i++)
            {
                result = result + a[aOff + i] * g[gOff + i];
                result = result + b[bOff + i] * h[hOff + i];
            }
            return result;
        }
    }
}
