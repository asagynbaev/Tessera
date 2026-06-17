using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;

namespace Tessera.Cryptography.Secp256k1
{
    /// <summary>
    /// Element of the finite field F_p where p is the secp256k1 prime (p = 2^256 - 2^32 - 977).
    /// All arithmetic is performed modulo p.
    /// </summary>
    /// <remarks>
    /// Constant-time implementation (H-1). Values are held as four little-endian 64-bit limbs in
    /// canonical form [0, p). Add/Sub/Mul/Square/inverse/sqrt run with data-independent control flow
    /// and no <see cref="BigInteger"/> in the hot path, so timing does not leak the operands — this
    /// matters because these ops are invoked under <see cref="Point.ScalarMul"/> with secret scalars
    /// (blinding factors, Bulletproofs witnesses). Inversion and square root exponentiate by the
    /// FIXED public exponents (p-2) and (p+1)/4; the square-and-multiply branch pattern depends only
    /// on those public constants, not on the (secret) base, so it is constant-time w.r.t. inputs.
    /// Behaviour is byte-for-byte identical to the previous BigInteger version (pinned by the
    /// BouncyCastle cross-check oracle in the test suite).
    /// </remarks>
    public readonly struct FieldElement : IEquatable<FieldElement>
    {
        public static readonly BigInteger P = BigInteger.Parse(
            "0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            NumberStyles.HexNumber);

        // Little-endian 64-bit limbs of p.
        private const ulong P0 = 0xFFFFFFFEFFFFFC2FUL;
        private const ulong P1 = 0xFFFFFFFFFFFFFFFFUL;
        private const ulong P2 = 0xFFFFFFFFFFFFFFFFUL;
        private const ulong P3 = 0xFFFFFFFFFFFFFFFFUL;
        // 2^256 ≡ C (mod p), with C = 2^32 + 977.
        private const ulong C = 0x1000003D1UL;

        // Fixed public exponents for Fermat inverse (p-2) and sqrt ((p+1)/4), big-endian.
        private static readonly byte[] InvExp = ToBE32(P - 2);
        private static readonly byte[] SqrtExp = ToBE32((P + 1) / 4);

        private readonly ulong _l0, _l1, _l2, _l3; // canonical: value in [0, p)

        private FieldElement(ulong l0, ulong l1, ulong l2, ulong l3)
        {
            _l0 = l0; _l1 = l1; _l2 = l2; _l3 = l3;
        }

        public FieldElement(BigInteger value)
        {
            var r = value % P;
            if (r.Sign < 0) r += P;
            Span<byte> b = stackalloc byte[32];
            var be = ToBE32(r);
            be.CopyTo(b);
            _l3 = BinaryPrimitives.ReadUInt64BigEndian(b[..8]);
            _l2 = BinaryPrimitives.ReadUInt64BigEndian(b[8..16]);
            _l1 = BinaryPrimitives.ReadUInt64BigEndian(b[16..24]);
            _l0 = BinaryPrimitives.ReadUInt64BigEndian(b[24..32]);
        }

        public static FieldElement Zero => new(0, 0, 0, 0);
        public static FieldElement One => new(1, 0, 0, 0);

        public BigInteger Value => new(ToBytes(), isUnsigned: true, isBigEndian: true);
        public bool IsZero => (_l0 | _l1 | _l2 | _l3) == 0;
        public bool IsEven => (_l0 & 1) == 0;

        public static FieldElement operator +(FieldElement a, FieldElement b)
        {
            // a + b < 2p < 2^257; capture the 257th bit as t4 and reduce.
            UInt128 s;
            s = (UInt128)a._l0 + b._l0; ulong r0 = (ulong)s; ulong cc = (ulong)(s >> 64);
            s = (UInt128)a._l1 + b._l1 + cc; ulong r1 = (ulong)s; cc = (ulong)(s >> 64);
            s = (UInt128)a._l2 + b._l2 + cc; ulong r2 = (ulong)s; cc = (ulong)(s >> 64);
            s = (UInt128)a._l3 + b._l3 + cc; ulong r3 = (ulong)s; cc = (ulong)(s >> 64);
            return ReduceWide(r0, r1, r2, r3, cc, 0, 0, 0);
        }

        public static FieldElement operator -(FieldElement a, FieldElement b)
        {
            // a - b in (-p, p); add p back on borrow.
            UInt128 d;
            d = (UInt128)a._l0 - b._l0; ulong r0 = (ulong)d; ulong brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)a._l1 - b._l1 - brw; ulong r1 = (ulong)d; brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)a._l2 - b._l2 - brw; ulong r2 = (ulong)d; brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)a._l3 - b._l3 - brw; ulong r3 = (ulong)d; brw = (ulong)(d >> 64) & 1UL;
            // brw == 1 means a < b: add p back (constant-time, masked).
            ulong mask = 0UL - brw;
            UInt128 s;
            s = (UInt128)r0 + (P0 & mask); r0 = (ulong)s; ulong cc = (ulong)(s >> 64);
            s = (UInt128)r1 + (P1 & mask) + cc; r1 = (ulong)s; cc = (ulong)(s >> 64);
            s = (UInt128)r2 + (P2 & mask) + cc; r2 = (ulong)s; cc = (ulong)(s >> 64);
            s = (UInt128)r3 + (P3 & mask) + cc; r3 = (ulong)s;
            return new FieldElement(r0, r1, r2, r3);
        }

        public static FieldElement operator -(FieldElement a) => Zero - a;

        public static FieldElement operator *(FieldElement a, FieldElement b)
        {
            // Operand-scanning 4x4 -> 8-limb product. Each MAC term
            // a_i*b_j + acc + carry <= (2^64-1)^2 + 2(2^64-1) = 2^128-1, so it fits one UInt128.
            Span<ulong> t = stackalloc ulong[8];
            ReadOnlySpan<ulong> av = stackalloc ulong[4] { a._l0, a._l1, a._l2, a._l3 };
            ReadOnlySpan<ulong> bv = stackalloc ulong[4] { b._l0, b._l1, b._l2, b._l3 };
            for (int i = 0; i < 4; i++)
            {
                ulong carry = 0;
                for (int j = 0; j < 4; j++)
                {
                    UInt128 m = (UInt128)av[i] * bv[j] + t[i + j] + carry;
                    t[i + j] = (ulong)m;
                    carry = (ulong)(m >> 64);
                }
                t[i + 4] = carry;
            }
            return ReduceWide(t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]);
        }

        public FieldElement Square() => this * this;

        /// <summary>
        /// Modular inverse via Fermat's little theorem: a^(p-2) mod p.
        /// </summary>
        public FieldElement Inv()
        {
            if (IsZero)
                throw new DivideByZeroException("Cannot invert zero in the field.");
            return Pow(InvExp);
        }

        /// <summary>
        /// Square root using the identity sqrt(a) = a^((p+1)/4) mod p.
        /// Valid because p ≡ 3 (mod 4) for secp256k1.
        /// </summary>
        public FieldElement Sqrt()
        {
            var candidate = Pow(SqrtExp);
            if (candidate.Square() != this)
                throw new ArithmeticException("Element has no square root in the field.");
            return candidate;
        }

        public bool HasSqrt()
        {
            if (IsZero) return true;
            var candidate = Pow(SqrtExp);
            return candidate.Square() == this;
        }

        public byte[] ToBytes()
        {
            var b = new byte[32];
            BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(0, 8), _l3);
            BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(8, 8), _l2);
            BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(16, 8), _l1);
            BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(24, 8), _l0);
            return b;
        }

        public static FieldElement FromBytes(byte[] bytes)
        {
            ArgumentNullException.ThrowIfNull(bytes);
            return FromBytes(bytes.AsSpan());
        }

        public static FieldElement FromBytes(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length != 32)
                throw new ArgumentException("Field element encoding must be exactly 32 bytes.", nameof(bytes));
            ulong l3 = BinaryPrimitives.ReadUInt64BigEndian(bytes[..8]);
            ulong l2 = BinaryPrimitives.ReadUInt64BigEndian(bytes[8..16]);
            ulong l1 = BinaryPrimitives.ReadUInt64BigEndian(bytes[16..24]);
            ulong l0 = BinaryPrimitives.ReadUInt64BigEndian(bytes[24..32]);
            // Input may be >= p (matches the prior BigInteger reduce-on-construct behaviour).
            (l0, l1, l2, l3) = CondSubP(l0, l1, l2, l3);
            (l0, l1, l2, l3) = CondSubP(l0, l1, l2, l3);
            return new FieldElement(l0, l1, l2, l3);
        }

        /// <summary>
        /// Parse a 32-byte big-endian field element, REJECTING a non-canonical encoding (x ≥ p) rather
        /// than reducing it. Use on deserialization where the byte form is security-relevant (SEC1 point
        /// x-coordinates) so a value has exactly ONE valid encoding — otherwise the same point has
        /// multiple byte representations (encoding malleability).
        /// </summary>
        public static FieldElement FromCanonicalBytes(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length != 32)
                throw new ArgumentException("Field element encoding must be exactly 32 bytes.", nameof(bytes));
            ulong l3 = BinaryPrimitives.ReadUInt64BigEndian(bytes[..8]);
            ulong l2 = BinaryPrimitives.ReadUInt64BigEndian(bytes[8..16]);
            ulong l1 = BinaryPrimitives.ReadUInt64BigEndian(bytes[16..24]);
            ulong l0 = BinaryPrimitives.ReadUInt64BigEndian(bytes[24..32]);
            // Reject x >= p: compute x - p; the absence of a final borrow means x >= p.
            UInt128 d;
            d = (UInt128)l0 - P0; ulong brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)l1 - P1 - brw; brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)l2 - P2 - brw; brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)l3 - P3 - brw; brw = (ulong)(d >> 64) & 1UL;
            if (brw == 0)
                throw new FormatException("Field element encoding is not canonical (value >= p).");
            return new FieldElement(l0, l1, l2, l3);
        }

        // ── internals ────────────────────────────────────────────────────────────

        /// <summary>
        /// Reduce a 512-bit value (8 little-endian limbs) modulo p into canonical form, by folding
        /// the high half through 2^256 ≡ C, then normalising with conditional subtractions.
        /// </summary>
        private static FieldElement ReduceWide(
            ulong t0, ulong t1, ulong t2, ulong t3, ulong t4, ulong t5, ulong t6, ulong t7)
        {
            // m = C * (t4..t7), 5 limbs (C is 33-bit, so the product is < 2^289).
            UInt128 p;
            p = (UInt128)C * t4; ulong m0 = (ulong)p; ulong cc = (ulong)(p >> 64);
            p = (UInt128)C * t5 + cc; ulong m1 = (ulong)p; cc = (ulong)(p >> 64);
            p = (UInt128)C * t6 + cc; ulong m2 = (ulong)p; cc = (ulong)(p >> 64);
            p = (UInt128)C * t7 + cc; ulong m3 = (ulong)p; ulong m4 = (ulong)(p >> 64);

            // d = (t0..t3) + (m0..m3); carry accumulates into d4 (< 2^34).
            UInt128 s;
            s = (UInt128)t0 + m0; ulong d0 = (ulong)s; cc = (ulong)(s >> 64);
            s = (UInt128)t1 + m1 + cc; ulong d1 = (ulong)s; cc = (ulong)(s >> 64);
            s = (UInt128)t2 + m2 + cc; ulong d2 = (ulong)s; cc = (ulong)(s >> 64);
            s = (UInt128)t3 + m3 + cc; ulong d3 = (ulong)s; cc = (ulong)(s >> 64);
            ulong d4 = m4 + cc;

            // value ≡ (d0..d3) + d4 * C, with d4*C < 2^67 (two limbs).
            UInt128 e = (UInt128)d4 * C;
            s = (UInt128)d0 + (ulong)e; d0 = (ulong)s; cc = (ulong)(s >> 64);
            s = (UInt128)d1 + (ulong)(e >> 64) + cc; d1 = (ulong)s; cc = (ulong)(s >> 64);
            s = (UInt128)d2 + cc; d2 = (ulong)s; cc = (ulong)(s >> 64);
            s = (UInt128)d3 + cc; d3 = (ulong)s; cc = (ulong)(s >> 64);

            // Fold any remaining 2^256 carry (cc <= 1 here); two passes converge fully.
            for (int rep = 0; rep < 2; rep++)
            {
                ulong add = cc * C;
                s = (UInt128)d0 + add; d0 = (ulong)s; cc = (ulong)(s >> 64);
                s = (UInt128)d1 + cc; d1 = (ulong)s; cc = (ulong)(s >> 64);
                s = (UInt128)d2 + cc; d2 = (ulong)s; cc = (ulong)(s >> 64);
                s = (UInt128)d3 + cc; d3 = (ulong)s; cc = (ulong)(s >> 64);
            }

            // value now < 2^256; bring into [0, p) (at most two subtractions needed).
            (d0, d1, d2, d3) = CondSubP(d0, d1, d2, d3);
            (d0, d1, d2, d3) = CondSubP(d0, d1, d2, d3);
            return new FieldElement(d0, d1, d2, d3);
        }

        /// <summary>Constant-time conditional subtraction of p: returns (l - p) if l >= p, else l.</summary>
        private static (ulong, ulong, ulong, ulong) CondSubP(ulong l0, ulong l1, ulong l2, ulong l3)
        {
            UInt128 d;
            d = (UInt128)l0 - P0; ulong s0 = (ulong)d; ulong brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)l1 - P1 - brw; ulong s1 = (ulong)d; brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)l2 - P2 - brw; ulong s2 = (ulong)d; brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)l3 - P3 - brw; ulong s3 = (ulong)d; brw = (ulong)(d >> 64) & 1UL;
            // brw == 0 -> l >= p -> use the subtracted result; brw == 1 -> keep l.
            ulong useSub = 0UL - (1UL - brw); // 0xFFFF.. when brw==0, else 0
            return (
                (s0 & useSub) | (l0 & ~useSub),
                (s1 & useSub) | (l1 & ~useSub),
                (s2 & useSub) | (l2 & ~useSub),
                (s3 & useSub) | (l3 & ~useSub));
        }

        /// <summary>Square-and-multiply by a FIXED big-endian exponent (public), MSB first.</summary>
        private FieldElement Pow(byte[] expBE)
        {
            var result = One;
            var basePow = this;
            foreach (var by in expBE)
            {
                for (int bit = 7; bit >= 0; bit--)
                {
                    result = result.Square();
                    if (((by >> bit) & 1) == 1)
                        result = result * basePow;
                }
            }
            return result;
        }

        private static byte[] ToBE32(BigInteger v)
        {
            var raw = v.ToByteArray(isUnsigned: true, isBigEndian: true);
            if (raw.Length == 32) return raw;
            var outp = new byte[32];
            raw.CopyTo(outp, 32 - raw.Length);
            return outp;
        }

        /// <summary>Constant-time equality mask: all-ones if equal, zero otherwise.</summary>
        internal ulong CtEqMask(FieldElement o)
        {
            ulong d = (_l0 ^ o._l0) | (_l1 ^ o._l1) | (_l2 ^ o._l2) | (_l3 ^ o._l3);
            ulong nonZero = (d | (0UL - d)) >> 63; // 1 if d != 0, else 0
            return 0UL - (nonZero ^ 1UL);          // all-ones when equal
        }

        /// <summary>Constant-time "is this zero" mask.</summary>
        internal ulong CtIsZeroMask() => CtEqMask(Zero);

        /// <summary>Constant-time select: returns <paramref name="ifMask"/> if mask is all-ones, else <paramref name="ifNot"/>.</summary>
        internal static FieldElement CondSelect(ulong mask, FieldElement ifMask, FieldElement ifNot)
            => new(
                (ifMask._l0 & mask) | (ifNot._l0 & ~mask),
                (ifMask._l1 & mask) | (ifNot._l1 & ~mask),
                (ifMask._l2 & mask) | (ifNot._l2 & ~mask),
                (ifMask._l3 & mask) | (ifNot._l3 & ~mask));

        public bool Equals(FieldElement other)
            => ((_l0 ^ other._l0) | (_l1 ^ other._l1) | (_l2 ^ other._l2) | (_l3 ^ other._l3)) == 0;

        public override bool Equals(object? obj) => obj is FieldElement fe && Equals(fe);
        public override int GetHashCode() => HashCode.Combine(_l0, _l1, _l2, _l3);
        public static bool operator ==(FieldElement a, FieldElement b) => a.Equals(b);
        public static bool operator !=(FieldElement a, FieldElement b) => !a.Equals(b);
        public override string ToString() => Value.ToString("X64");
    }
}
