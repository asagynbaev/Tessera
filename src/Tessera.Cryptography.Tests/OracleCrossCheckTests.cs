using System.Security.Cryptography;
using SnBig = System.Numerics.BigInteger;
using BcBig = Org.BouncyCastle.Math.BigInteger;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using ECCurve = Org.BouncyCastle.Math.EC.ECCurve;
using Tessera.Cryptography;
using Tessera.Cryptography.Secp256k1;

namespace Tessera.Cryptography.Tests;

/// <summary>
/// Independent-oracle cross-checks for the secp256k1 field/scalar/group arithmetic.
///
/// The rest of the suite is self-consistent (round-trips, homomorphism, prove→verify) and so
/// CANNOT catch a self-consistent reduction bug — prover and verifier would share the same fault.
/// These tests pin Tessera's results against BouncyCastle's secp256k1 (a separate, audited
/// implementation), so any divergence in modular reduction, inversion, sqrt, or scalar
/// multiplication fails loudly. They must stay green across the constant-time rewrite (H-1):
/// behaviour is frozen, only the timing characteristics change.
/// </summary>
public class OracleCrossCheckTests
{
    private static readonly X9ECParameters Bc = SecNamedCurves.GetByName("secp256k1");
    private static readonly ECCurve Curve = Bc.Curve;
    private static readonly BcBig P = Curve.Field.Characteristic;
    private static readonly BcBig N = Bc.N;

    // Deterministic input set: structural edge cases + reproducible pseudo-random 32-byte values.
    private static IEnumerable<SnBig> Inputs()
    {
        foreach (var small in new SnBig[] { 1, 2, 3, 7, 8, 12345, 0xDEADBEEF })
            yield return small;
        // Near the field/scalar boundaries.
        yield return ToSn(P.Subtract(BcBig.One));
        yield return ToSn(N.Subtract(BcBig.One));
        yield return ToSn(P.Subtract(BcBig.Two));
        // Reproducible pseudo-random values (SHA-256 of a counter), 16 of them.
        for (int i = 0; i < 16; i++)
        {
            var h = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes($"tessera-oracle-{i}"));
            yield return new SnBig(h, isUnsigned: true, isBigEndian: true);
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static SnBig ToSn(BcBig b) => new(b.ToByteArrayUnsigned(), isUnsigned: true, isBigEndian: true);
    private static BcBig ToBc(SnBig v) => new(1, To32(v));

    private static byte[] To32(SnBig v)
    {
        var raw = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (raw.Length == 32) return raw;
        var outp = new byte[32];
        Array.Copy(raw, 0, outp, 32 - raw.Length, raw.Length);
        return outp;
    }

    private static byte[] To32(BcBig b)
    {
        var raw = b.ToByteArrayUnsigned();
        if (raw.Length == 32) return raw;
        var outp = new byte[32];
        Array.Copy(raw, 0, outp, 32 - raw.Length, raw.Length);
        return outp;
    }

    // ── constants ──────────────────────────────────────────────────────────────

    [Fact]
    public void Constants_FieldPrime_ScalarOrder_Generator_MatchBouncyCastle()
    {
        // Field prime p and group order n must match exactly.
        Assert.Equal(To32(P), To32(FieldElement.P));
        Assert.Equal(To32(N), To32(Scalar.N));
        // Generator G must encode identically (SEC1 compressed).
        Assert.Equal(Bc.G.Normalize().GetEncoded(true), Point.G.Encode());
    }

    // ── field F_p ──────────────────────────────────────────────────────────────

    [Fact]
    public void Field_MulAddSubInv_MatchBouncyCastle()
    {
        var vals = Inputs().ToArray();
        for (int i = 0; i < vals.Length; i++)
        {
            var a = vals[i];
            var b = vals[(i + 1) % vals.Length];
            var fa = new FieldElement(a);
            var fb = new FieldElement(b);
            var ba = Curve.FromBigInteger(ToBc(a).Mod(P));
            var bb = Curve.FromBigInteger(ToBc(b).Mod(P));

            Assert.Equal(To32(ba.Multiply(bb).ToBigInteger()), (fa * fb).ToBytes());
            Assert.Equal(To32(ba.Add(bb).ToBigInteger()), (fa + fb).ToBytes());
            Assert.Equal(To32(ba.Subtract(bb).ToBigInteger()), (fa - fb).ToBytes());
            Assert.Equal(To32(ba.Negate().ToBigInteger()), (-fa).ToBytes());

            if (!fa.IsZero)
                Assert.Equal(To32(ba.Invert().ToBigInteger()), fa.Inv().ToBytes());
        }
    }

    [Fact]
    public void Field_Sqrt_MatchesBouncyCastle_UpToSign()
    {
        foreach (var a in Inputs())
        {
            // Square the input so a root is guaranteed to exist, then check Tessera's root
            // squares back to it and equals BouncyCastle's root up to negation.
            var fa = new FieldElement(a);
            var sq = fa.Square();
            var root = sq.Sqrt();
            Assert.Equal(sq, root.Square());

            var bcRoot = Curve.FromBigInteger(ToBc(a).ModPow(BcBig.Two, P)).Sqrt();
            Assert.NotNull(bcRoot);
            var bc = To32(bcRoot!.ToBigInteger());
            var bcNeg = To32(P.Subtract(bcRoot.ToBigInteger()).Mod(P));
            var got = root.ToBytes();
            Assert.True(got.SequenceEqual(bc) || got.SequenceEqual(bcNeg),
                $"sqrt mismatch for input {a}");
        }
    }

    // ── scalar F_n ──────────────────────────────────────────────────────────────

    [Fact]
    public void Scalar_MulAddSubInv_MatchBouncyCastle()
    {
        var vals = Inputs().ToArray();
        for (int i = 0; i < vals.Length; i++)
        {
            var a = vals[i];
            var b = vals[(i + 1) % vals.Length];
            var sa = new Scalar(a);
            var sb = new Scalar(b);
            var ba = ToBc(a).Mod(N);
            var bb = ToBc(b).Mod(N);

            Assert.Equal(To32(ba.Multiply(bb).Mod(N)), (sa * sb).ToBytes());
            Assert.Equal(To32(ba.Add(bb).Mod(N)), (sa + sb).ToBytes());
            Assert.Equal(To32(ba.Subtract(bb).Mod(N)), (sa - sb).ToBytes());

            if (!sa.IsZero)
                Assert.Equal(To32(ba.ModInverse(N)), sa.Inv().ToBytes());
        }
    }

    // ── group ────────────────────────────────────────────────────────────────────

    [Fact]
    public void ScalarMul_OnGenerator_MatchesBouncyCastle()
    {
        foreach (var k in Inputs())
        {
            var sk = new Scalar(k);
            if (sk.IsZero) continue;
            var got = (sk * Point.G).Encode();
            var want = Bc.G.Multiply(ToBc(k).Mod(N)).Normalize().GetEncoded(true);
            Assert.Equal(want, got);
        }
    }

    [Fact]
    public void ScalarMul_OnArbitraryPoint_H_MatchesBouncyCastle()
    {
        // Exercise scalar multiplication on a non-generator point (Bulletproofs multiplies the
        // NUMS vector generators Gi/Hi by secret scalars — that path must be correct too).
        var hBytes = Generators.H.Encode();
        var hBc = Curve.DecodePoint(hBytes);
        foreach (var k in Inputs())
        {
            var sk = new Scalar(k);
            if (sk.IsZero) continue;
            var got = (sk * Generators.H).Encode();
            var want = hBc.Multiply(ToBc(k).Mod(N)).Normalize().GetEncoded(true);
            Assert.Equal(want, got);
        }
    }

    [Fact]
    public void PointAddition_MatchesBouncyCastle()
    {
        var gBc = Bc.G;
        var hBc = Curve.DecodePoint(Generators.H.Encode());
        Assert.Equal(
            gBc.Add(hBc).Normalize().GetEncoded(true),
            (Point.G + Generators.H).Encode());
        // P + P path (doubling).
        Assert.Equal(
            gBc.Twice().Normalize().GetEncoded(true),
            (Point.G + Point.G).Encode());
    }

    [Fact]
    public void CanonicalDecode_RejectsNonCanonicalFieldAndScalar()
    {
        // x == p and s == n are the smallest non-canonical encodings; both must be rejected (F1/F2 —
        // closes proof/commitment byte-malleability where two encodings map to one point/scalar).
        Assert.Throws<FormatException>(() => FieldElement.FromCanonicalBytes(To32(P)));
        Assert.Throws<FormatException>(() => Scalar.FromCanonicalBytes(To32(N)));

        // p-1 and n-1 are canonical and must be accepted (no throw).
        FieldElement.FromCanonicalBytes(To32(P.Subtract(BcBig.One)));
        Scalar.FromCanonicalBytes(To32(N.Subtract(BcBig.One)));

        // A compressed point whose x-coordinate equals p must fail to decode (no silent reduction).
        var nonCanonical = new byte[33];
        nonCanonical[0] = 0x02;
        To32(P).CopyTo(nonCanonical, 1);
        Assert.Throws<FormatException>(() => Point.Decode(nonCanonical));
    }
}
