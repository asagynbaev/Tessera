using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace Tessera.Cryptography.Secp256k1
{
    /// <summary>
    /// Element of the scalar field F_n where n is the secp256k1 group order.
    /// Used for discrete logarithms, blinding factors, and challenges.
    /// </summary>
    /// <remarks>
    /// Constant-time implementation (H-1). Values are four little-endian 64-bit limbs in canonical
    /// form [0, n). Add/Sub/Mul run with data-independent control flow and no <see cref="BigInteger"/>
    /// in the hot path; n is not a pseudo-Mersenne prime, so multiplication reduces via Barrett
    /// reduction (precomputed μ = ⌊2^512 / n⌋, fixed conditional subtractions — no data-dependent
    /// loop). Inversion exponentiates by the FIXED public exponent (n-2), whose square-and-multiply
    /// pattern is independent of the secret base. Behaviour is byte-for-byte identical to the prior
    /// BigInteger version (pinned by the BouncyCastle cross-check oracle).
    /// </remarks>
    public readonly struct Scalar : IEquatable<Scalar>
    {
        public static readonly BigInteger N = BigInteger.Parse(
            "0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            NumberStyles.HexNumber);

        // Little-endian limbs of n, Barrett μ (⌊2^512/n⌋, 5 limbs), and the fixed inverse exponent
        // (n-2). All derived from N at static init so there is no hand-transcribed constant.
        private static readonly ulong N0, N1, N2, N3;
        private static readonly ulong Mu0, Mu1, Mu2, Mu3, Mu4;
        private static readonly byte[] InvExp;

        static Scalar()
        {
            var nl = LimbsLE(N, 4);
            N0 = nl[0]; N1 = nl[1]; N2 = nl[2]; N3 = nl[3];
            var mu = LimbsLE((BigInteger.One << 512) / N, 5);
            Mu0 = mu[0]; Mu1 = mu[1]; Mu2 = mu[2]; Mu3 = mu[3]; Mu4 = mu[4];
            InvExp = ToBE32(N - 2);
        }

        private readonly ulong _l0, _l1, _l2, _l3; // canonical: value in [0, n)

        private Scalar(ulong l0, ulong l1, ulong l2, ulong l3)
        {
            _l0 = l0; _l1 = l1; _l2 = l2; _l3 = l3;
        }

        public Scalar(BigInteger value)
        {
            var r = value % N;
            if (r.Sign < 0) r += N;
            var l = LimbsLE(r, 4);
            _l0 = l[0]; _l1 = l[1]; _l2 = l[2]; _l3 = l[3];
        }

        public static Scalar Zero => new(0, 0, 0, 0);
        public static Scalar One => new(1, 0, 0, 0);
        public static Scalar Two => new(2, 0, 0, 0);

        public BigInteger Value => new(ToBytes(), isUnsigned: true, isBigEndian: true);
        public bool IsZero => (_l0 | _l1 | _l2 | _l3) == 0;

        public static Scalar operator +(Scalar a, Scalar b)
        {
            // a + b < 2n; capture the carry as a 5th limb, then subtract n if the value >= n.
            UInt128 s;
            s = (UInt128)a._l0 + b._l0; ulong r0 = (ulong)s; ulong cc = (ulong)(s >> 64);
            s = (UInt128)a._l1 + b._l1 + cc; ulong r1 = (ulong)s; cc = (ulong)(s >> 64);
            s = (UInt128)a._l2 + b._l2 + cc; ulong r2 = (ulong)s; cc = (ulong)(s >> 64);
            s = (UInt128)a._l3 + b._l3 + cc; ulong r3 = (ulong)s; ulong r4 = (ulong)(s >> 64);
            Span<ulong> r = stackalloc ulong[5] { r0, r1, r2, r3, r4 };
            CondSubN(r);
            return new Scalar(r[0], r[1], r[2], r[3]);
        }

        public static Scalar operator -(Scalar a, Scalar b)
        {
            // a - b in (-n, n); add n back on borrow.
            UInt128 d;
            d = (UInt128)a._l0 - b._l0; ulong r0 = (ulong)d; ulong brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)a._l1 - b._l1 - brw; ulong r1 = (ulong)d; brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)a._l2 - b._l2 - brw; ulong r2 = (ulong)d; brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)a._l3 - b._l3 - brw; ulong r3 = (ulong)d; brw = (ulong)(d >> 64) & 1UL;
            ulong mask = 0UL - brw;
            UInt128 s;
            s = (UInt128)r0 + (N0 & mask); r0 = (ulong)s; ulong cc = (ulong)(s >> 64);
            s = (UInt128)r1 + (N1 & mask) + cc; r1 = (ulong)s; cc = (ulong)(s >> 64);
            s = (UInt128)r2 + (N2 & mask) + cc; r2 = (ulong)s; cc = (ulong)(s >> 64);
            s = (UInt128)r3 + (N3 & mask) + cc; r3 = (ulong)s;
            return new Scalar(r0, r1, r2, r3);
        }

        public static Scalar operator -(Scalar a) => Zero - a;

        public static Scalar operator *(Scalar a, Scalar b)
        {
            Span<ulong> prod = stackalloc ulong[8];
            ReadOnlySpan<ulong> av = stackalloc ulong[4] { a._l0, a._l1, a._l2, a._l3 };
            ReadOnlySpan<ulong> bv = stackalloc ulong[4] { b._l0, b._l1, b._l2, b._l3 };
            MulFull(av, bv, prod);
            return ReduceBarrett(prod);
        }

        public Scalar Square() => this * this;

        /// <summary>
        /// Modular inverse via Fermat's little theorem: a^(n-2) mod n.
        /// </summary>
        public Scalar Inv()
        {
            if (IsZero)
                throw new DivideByZeroException("Cannot invert zero scalar.");
            return Pow(InvExp);
        }

        /// <summary>
        /// Raise to a power. Square-and-multiply over the big-endian exponent; constant-time only
        /// when the exponent is public (it is, for the internal Fermat inverse).
        /// </summary>
        public Scalar Pow(BigInteger exponent)
        {
            if (exponent.Sign < 0)
                throw new ArgumentOutOfRangeException(nameof(exponent), "Exponent must be non-negative.");
            return Pow(exponent.ToByteArray(isUnsigned: true, isBigEndian: true));
        }

        private Scalar Pow(byte[] expBE)
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

        /// <summary>
        /// Generate a cryptographically random non-zero scalar.
        /// </summary>
        public static Scalar Random()
        {
            Span<byte> bytes = stackalloc byte[32];
            while (true)
            {
                RandomNumberGenerator.Fill(bytes);
                var s = FromBytes(bytes);
                if (!s.IsZero) return s;
            }
        }

        /// <summary>
        /// Create scalar from a long value (non-negative).
        /// </summary>
        public static Scalar From(long value)
        {
            if (value < 0)
                throw new ArgumentOutOfRangeException(nameof(value), "Value must be non-negative.");
            return new Scalar(new BigInteger(value));
        }

        /// <summary>
        /// The canonical value as four little-endian 64-bit limbs (limb 0 is least significant).
        /// Exposes the fixed-width internal representation so callers can read individual bits without a
        /// data-dependent <see cref="BigInteger"/> (used by the constant-time range-proof bit split).
        /// </summary>
        internal ulong[] ToLimbsLE() => new[] { _l0, _l1, _l2, _l3 };

        /// <summary>
        /// Branchless construction of <see cref="Zero"/> (bit 0) or <see cref="One"/> (bit 1) from a
        /// single bit — the same limb layout is built regardless of the bit's value, so it does not
        /// leak the secret bit through a <c>?:</c> branch. <paramref name="bit"/> MUST be 0 or 1.
        /// Used by the constant-time range-proof bit split.
        /// </summary>
        internal static Scalar FromBit(ulong bit) => new(bit, 0, 0, 0);

        public byte[] ToBytes()
        {
            var b = new byte[32];
            BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(0, 8), _l3);
            BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(8, 8), _l2);
            BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(16, 8), _l1);
            BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(24, 8), _l0);
            return b;
        }

        public static Scalar FromBytes(byte[] bytes)
        {
            ArgumentNullException.ThrowIfNull(bytes);
            return FromBytes(bytes.AsSpan());
        }

        public static Scalar FromBytes(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length != 32)
                throw new ArgumentException("Scalar encoding must be exactly 32 bytes.", nameof(bytes));
            ulong l3 = BinaryPrimitives.ReadUInt64BigEndian(bytes[..8]);
            ulong l2 = BinaryPrimitives.ReadUInt64BigEndian(bytes[8..16]);
            ulong l1 = BinaryPrimitives.ReadUInt64BigEndian(bytes[16..24]);
            ulong l0 = BinaryPrimitives.ReadUInt64BigEndian(bytes[24..32]);
            // Input may be >= n (e.g. a hash squeezed into a challenge): reduce mod n. A 256-bit
            // value is < 2n, so one subtraction suffices; a second is a harmless safety margin.
            Span<ulong> r = stackalloc ulong[5] { l0, l1, l2, l3, 0 };
            CondSubN(r);
            CondSubN(r);
            return new Scalar(r[0], r[1], r[2], r[3]);
        }

        /// <summary>
        /// Parse a 32-byte big-endian scalar, REJECTING a non-canonical encoding (s ≥ n) rather than
        /// reducing it. Use on proof/opening deserialization so each scalar has exactly ONE valid byte
        /// form (closes scalar-encoding malleability of serialized proofs).
        /// </summary>
        public static Scalar FromCanonicalBytes(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length != 32)
                throw new ArgumentException("Scalar encoding must be exactly 32 bytes.", nameof(bytes));
            ulong l3 = BinaryPrimitives.ReadUInt64BigEndian(bytes[..8]);
            ulong l2 = BinaryPrimitives.ReadUInt64BigEndian(bytes[8..16]);
            ulong l1 = BinaryPrimitives.ReadUInt64BigEndian(bytes[16..24]);
            ulong l0 = BinaryPrimitives.ReadUInt64BigEndian(bytes[24..32]);
            // Reject s >= n: compute s - n; the absence of a final borrow means s >= n.
            UInt128 d;
            d = (UInt128)l0 - N0; ulong brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)l1 - N1 - brw; brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)l2 - N2 - brw; brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)l3 - N3 - brw; brw = (ulong)(d >> 64) & 1UL;
            if (brw == 0)
                throw new FormatException("Scalar encoding is not canonical (value >= n).");
            return new Scalar(l0, l1, l2, l3);
        }

        /// <summary>
        /// Inner product of two scalar vectors: sum(a[i] * b[i]).
        /// </summary>
        public static Scalar InnerProduct(Scalar[] a, Scalar[] b)
        {
            if (a.Length != b.Length)
                throw new ArgumentException("Vectors must have the same length.");
            var sum = Zero;
            for (int i = 0; i < a.Length; i++)
                sum = sum + a[i] * b[i];
            return sum;
        }

        // ── internals ────────────────────────────────────────────────────────────

        /// <summary>Schoolbook (operand-scanning) multiply: outp = a * b, len(outp) = len(a)+len(b).</summary>
        private static void MulFull(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> outp)
        {
            outp.Clear();
            for (int i = 0; i < a.Length; i++)
            {
                ulong carry = 0;
                for (int j = 0; j < b.Length; j++)
                {
                    UInt128 m = (UInt128)a[i] * b[j] + outp[i + j] + carry;
                    outp[i + j] = (ulong)m;
                    carry = (ulong)(m >> 64);
                }
                outp[i + b.Length] += carry;
            }
        }

        /// <summary>
        /// Barrett reduction of an 8-limb (≤ 512-bit) value modulo n. With μ = ⌊2^512/n⌋ the
        /// quotient estimate is short by at most 2, so a fixed number of conditional subtractions
        /// (no data-dependent branch) yields the canonical residue.
        /// </summary>
        private static Scalar ReduceBarrett(ReadOnlySpan<ulong> x)
        {
            // q1 = x >> 192 (limbs 3..7, 5 limbs); q2 = q1 * μ; q3 = q2 >> 320 (limbs 5..9, 5 limbs).
            Span<ulong> q2 = stackalloc ulong[10];
            MulFull(x.Slice(3, 5), Mu(), q2);
            ReadOnlySpan<ulong> q3 = q2.Slice(5, 5);

            // r2 = (q3 * n) mod 2^320 (low 5 limbs); r1 = x mod 2^320 (low 5 limbs).
            Span<ulong> q3n = stackalloc ulong[9];
            MulFull(q3, NLimbs(), q3n);

            // r = r1 - r2 (mod 2^320, kept in 5 limbs).
            Span<ulong> r = stackalloc ulong[5];
            ulong borrow = 0;
            for (int i = 0; i < 5; i++)
            {
                UInt128 d = (UInt128)x[i] - q3n[i] - borrow;
                r[i] = (ulong)d;
                borrow = (ulong)(d >> 64) & 1UL;
            }

            // r < 3n here; at most two subtractions reduce it, a third is safety margin.
            CondSubN(r);
            CondSubN(r);
            CondSubN(r);
            return new Scalar(r[0], r[1], r[2], r[3]);
        }

        /// <summary>Constant-time conditional subtraction of n from a 5-limb value (in place).</summary>
        private static void CondSubN(Span<ulong> r)
        {
            // s = r - n (n is 4 limbs; top limb of n is 0).
            UInt128 d;
            d = (UInt128)r[0] - N0; ulong s0 = (ulong)d; ulong brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)r[1] - N1 - brw; ulong s1 = (ulong)d; brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)r[2] - N2 - brw; ulong s2 = (ulong)d; brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)r[3] - N3 - brw; ulong s3 = (ulong)d; brw = (ulong)(d >> 64) & 1UL;
            d = (UInt128)r[4] - 0UL - brw; ulong s4 = (ulong)d; brw = (ulong)(d >> 64) & 1UL;
            // brw == 0 -> r >= n -> take the subtracted value; brw == 1 -> keep r.
            ulong mask = 0UL - (1UL - brw);
            r[0] = (s0 & mask) | (r[0] & ~mask);
            r[1] = (s1 & mask) | (r[1] & ~mask);
            r[2] = (s2 & mask) | (r[2] & ~mask);
            r[3] = (s3 & mask) | (r[3] & ~mask);
            r[4] = (s4 & mask) | (r[4] & ~mask);
        }

        private static ReadOnlySpan<ulong> Mu() => new[] { Mu0, Mu1, Mu2, Mu3, Mu4 };
        private static ReadOnlySpan<ulong> NLimbs() => new[] { N0, N1, N2, N3 };

        private static ulong[] LimbsLE(BigInteger v, int count)
        {
            var limbs = new ulong[count];
            var mask = (BigInteger.One << 64) - 1;
            for (int i = 0; i < count; i++)
            {
                limbs[i] = (ulong)(v & mask);
                v >>= 64;
            }
            return limbs;
        }

        private static byte[] ToBE32(BigInteger v)
        {
            var raw = v.ToByteArray(isUnsigned: true, isBigEndian: true);
            if (raw.Length == 32) return raw;
            var outp = new byte[32];
            raw.CopyTo(outp, 32 - raw.Length);
            return outp;
        }

        public bool Equals(Scalar other)
            => ((_l0 ^ other._l0) | (_l1 ^ other._l1) | (_l2 ^ other._l2) | (_l3 ^ other._l3)) == 0;

        public override bool Equals(object? obj) => obj is Scalar s && Equals(s);
        public override int GetHashCode() => HashCode.Combine(_l0, _l1, _l2, _l3);
        public static bool operator ==(Scalar a, Scalar b) => a.Equals(b);
        public static bool operator !=(Scalar a, Scalar b) => !a.Equals(b);
        public override string ToString() => Value.ToString("X64");
    }
}
