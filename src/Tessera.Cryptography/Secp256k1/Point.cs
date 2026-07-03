using System.Numerics;

namespace Tessera.Cryptography.Secp256k1
{
    /// <summary>
    /// Point on the secp256k1 elliptic curve (y^2 = x^3 + 7) in Jacobian coordinates.
    /// Represents affine point (X/Z^2, Y/Z^3). Point at infinity has Z = 0.
    /// </summary>
    public readonly struct Point : IEquatable<Point>
    {
        private static readonly FieldElement CurveB = new(new BigInteger(7));

        public readonly FieldElement X;
        public readonly FieldElement Y;
        public readonly FieldElement Z;

        public Point(FieldElement x, FieldElement y, FieldElement z)
        {
            X = x; Y = y; Z = z;
        }

        public static Point Infinity => new(FieldElement.Zero, FieldElement.One, FieldElement.Zero);

        public bool IsInfinity => Z.IsZero;

        public static readonly Point G = new(
            FieldElement.FromBytes(Convert.FromHexString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")),
            FieldElement.FromBytes(Convert.FromHexString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")),
            FieldElement.One
        );

        public (FieldElement x, FieldElement y) ToAffine()
        {
            if (IsInfinity)
                throw new InvalidOperationException("Point at infinity has no affine representation.");
            var zInv = Z.Inv();
            var zInv2 = zInv.Square();
            var zInv3 = zInv2 * zInv;
            return (X * zInv2, Y * zInv3);
        }

        public static Point Add(Point p, Point q)
        {
            if (p.IsInfinity) return q;
            if (q.IsInfinity) return p;

            var z1sq = p.Z.Square();
            var z2sq = q.Z.Square();
            var u1 = p.X * z2sq;
            var u2 = q.X * z1sq;
            var s1 = p.Y * q.Z * z2sq;
            var s2 = q.Y * p.Z * z1sq;

            if (u1 == u2)
                return s1 == s2 ? Double(p) : Infinity;

            var h = u2 - u1;
            var r = s2 - s1;
            var hSq = h.Square();
            var hCub = hSq * h;
            var u1hSq = u1 * hSq;

            var x3 = r.Square() - hCub - u1hSq - u1hSq;
            var y3 = r * (u1hSq - x3) - s1 * hCub;
            var z3 = h * p.Z * q.Z;

            return new Point(x3, y3, z3);
        }

        public static Point Double(Point p)
        {
            if (p.IsInfinity || p.Y.IsZero)
                return Infinity;

            var ySq = p.Y.Square();
            var s = new FieldElement(4) * p.X * ySq;
            var m = new FieldElement(3) * p.X.Square();

            var x3 = m.Square() - s - s;
            var y3 = m * (s - x3) - new FieldElement(8) * ySq.Square();
            var z3 = new FieldElement(2) * p.Y * p.Z;

            return new Point(x3, y3, z3);
        }

        public static Point Negate(Point p)
            => p.IsInfinity ? Infinity : new Point(p.X, -p.Y, p.Z);

        /// <summary>
        /// Constant-time scalar multiplication (H-1): fixed 256-bit, MSB-first double-and-add-ALWAYS
        /// with a branchless point select, over complete (branch-free) add/double formulas. The loop
        /// length, the per-bit work, and all memory accesses are independent of the secret scalar, so
        /// timing does not leak it. <c>k = 0</c> and an infinite <paramref name="p"/> both yield the
        /// point at infinity, as before — no early return is needed (the ladder handles them).
        /// </summary>
        public static Point ScalarMul(Point p, Scalar s)
        {
            var k = s.ToBytes(); // 32-byte big-endian
            var result = Infinity;
            for (int i = 0; i < 256; i++)
            {
                result = DoubleCt(result);
                var added = AddCt(result, p);
                ulong bit = (ulong)((k[i >> 3] >> (7 - (i & 7))) & 1);
                result = Select(0UL - bit, added, result);
            }
            return result;
        }

        /// <summary>Branch-free doubling: the Jacobian formula already yields Z=0 for the point at infinity.</summary>
        private static Point DoubleCt(Point p)
        {
            var ySq = p.Y.Square();
            var s = new FieldElement(4) * p.X * ySq;
            var m = new FieldElement(3) * p.X.Square();
            var x3 = m.Square() - s - s;
            var y3 = m * (s - x3) - new FieldElement(8) * ySq.Square();
            var z3 = new FieldElement(2) * p.Y * p.Z;
            return new Point(x3, y3, z3);
        }

        /// <summary>
        /// Branch-free addition covering every case (∞ operands, P==Q doubling, P==-Q → ∞): it computes
        /// the generic sum and the doubling unconditionally and selects the correct one with
        /// constant-time masks, so the running time does not depend on which case occurred. It returns
        /// the same group element as <see cref="Add"/> for every input, so it is a drop-in replacement
        /// on paths that accumulate secret-dependent points (where <see cref="Add"/>'s ∞ short-circuit
        /// would otherwise leak which addends were the identity).
        /// </summary>
        public static Point AddCt(Point p, Point q)
        {
            var z1sq = p.Z.Square();
            var z2sq = q.Z.Square();
            var u1 = p.X * z2sq;
            var u2 = q.X * z1sq;
            var s1 = p.Y * q.Z * z2sq;
            var s2 = q.Y * p.Z * z1sq;

            var h = u2 - u1;
            var r = s2 - s1;
            var hSq = h.Square();
            var hCub = hSq * h;
            var u1hSq = u1 * hSq;
            var x3 = r.Square() - hCub - u1hSq - u1hSq;
            var y3 = r * (u1hSq - x3) - s1 * hCub;
            var z3 = h * p.Z * q.Z;
            var generic = new Point(x3, y3, z3);

            var dbl = DoubleCt(p);

            ulong pInf = p.Z.CtIsZeroMask();
            ulong qInf = q.Z.CtIsZeroMask();
            ulong xEq = u1.CtEqMask(u2);
            ulong yEq = s1.CtEqMask(s2);
            ulong bothEq = xEq & yEq;  // P == Q  -> doubling
            ulong negEq = xEq & ~yEq;  // P == -Q -> infinity

            var res = generic;
            res = Select(bothEq, dbl, res);
            res = Select(negEq, Infinity, res);
            res = Select(qInf, p, res);  // Q == ∞ -> P
            res = Select(pInf, q, res);  // P == ∞ -> Q (last, so it wins when both are ∞)
            return res;
        }

        /// <summary>Constant-time point select: <paramref name="ifMask"/> when mask is all-ones, else <paramref name="ifNot"/>.</summary>
        private static Point Select(ulong mask, Point ifMask, Point ifNot)
            => new(
                FieldElement.CondSelect(mask, ifMask.X, ifNot.X),
                FieldElement.CondSelect(mask, ifMask.Y, ifNot.Y),
                FieldElement.CondSelect(mask, ifMask.Z, ifNot.Z));

        public static Point MultiScalarMul(Scalar[] scalars, Point[] points)
        {
            if (scalars.Length != points.Length)
                throw new ArgumentException("Scalar and point arrays must have equal length.");
            var result = Infinity;
            for (int i = 0; i < scalars.Length; i++)
                if (!scalars[i].IsZero)
                    result = Add(result, ScalarMul(points[i], scalars[i]));
            return result;
        }

        /// <summary>SEC1 compressed encoding: 0x02/0x03 prefix + 32-byte X coordinate.</summary>
        public byte[] Encode()
        {
            if (IsInfinity)
                throw new InvalidOperationException("Cannot encode point at infinity.");
            var (x, y) = ToAffine();
            var result = new byte[33];
            result[0] = y.IsEven ? (byte)0x02 : (byte)0x03;
            x.ToBytes().CopyTo(result, 1);
            return result;
        }

        public static Point Decode(byte[] bytes)
        {
            if (bytes.Length != 33)
                throw new ArgumentException("Compressed point must be exactly 33 bytes.", nameof(bytes));
            byte prefix = bytes[0];
            if (prefix != 0x02 && prefix != 0x03)
                throw new ArgumentException("Invalid compressed point prefix.", nameof(bytes));
            // Reject non-canonical x (x >= p): a point must have exactly one valid SEC1 encoding.
            var x = FieldElement.FromCanonicalBytes(bytes.AsSpan(1, 32));
            var rhs = x * x * x + CurveB;
            var y = rhs.Sqrt();
            bool wantOdd = prefix == 0x03;
            if (wantOdd != !y.IsEven) y = -y;
            return new Point(x, y, FieldElement.One);
        }

        public bool IsOnCurve()
        {
            if (IsInfinity) return true;
            var (x, y) = ToAffine();
            return y.Square() == x * x * x + CurveB;
        }

        public static Point operator +(Point a, Point b) => Add(a, b);
        public static Point operator -(Point a) => Negate(a);
        public static Point operator -(Point a, Point b) => Add(a, Negate(b));
        public static Point operator *(Scalar s, Point p) => ScalarMul(p, s);
        public static Point operator *(Point p, Scalar s) => ScalarMul(p, s);

        public bool Equals(Point other)
        {
            if (IsInfinity && other.IsInfinity) return true;
            if (IsInfinity || other.IsInfinity) return false;
            var z1sq = Z * Z;
            var z2sq = other.Z * other.Z;
            if (X * z2sq != other.X * z1sq) return false;
            return Y * other.Z * z2sq == other.Y * Z * z1sq;
        }

        public override bool Equals(object? obj) => obj is Point p && Equals(p);

        public override int GetHashCode()
        {
            if (IsInfinity) return 0;
            var (x, y) = ToAffine();
            return HashCode.Combine(x.Value, y.Value);
        }

        public static bool operator ==(Point a, Point b) => a.Equals(b);
        public static bool operator !=(Point a, Point b) => !a.Equals(b);
    }
}
