using Tessera.Cryptography.Secp256k1;

namespace Tessera.Cryptography
{
    /// <summary>
    /// Pedersen commitment scheme on secp256k1: C = v*G + r*H.
    /// Perfectly hiding (r is random), computationally binding (discrete log assumption).
    /// Additively homomorphic: Commit(v1,r1) + Commit(v2,r2) = Commit(v1+v2, r1+r2).
    /// </summary>
    public static class PedersenCommitment
    {
        // Constant-time: AddCt (not the branchy operator+) so a secret value of 0 — which makes
        // value*G the point at infinity — does not take a different, timing-observable branch than
        // a non-zero value. The scalar multiplications are already constant-time (ScalarMul).
        public static Point Commit(Scalar value, Scalar blinding)
            => Point.AddCt(value * Generators.G, blinding * Generators.H);

        public static bool Open(Point commitment, Scalar value, Scalar blinding)
            => commitment == Commit(value, blinding);
    }
}
