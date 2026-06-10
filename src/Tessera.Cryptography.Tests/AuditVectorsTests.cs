using Tessera.Cryptography;
using Tessera.Cryptography.Bulletproofs;
using Tessera.Cryptography.Secp256k1;

namespace Tessera.Cryptography.Tests;

/// <summary>
/// Deterministic audit anchors (A6): fixed-input behavior an external auditor can reproduce.
/// Proof bytes are intentionally non-deterministic (fresh blinding), but commitments are
/// deterministic, verification is deterministic, and tampering must fail.
/// </summary>
public class AuditVectorsTests
{
    [Fact]
    public void Pedersen_Commit_IsDeterministic_AndRoundTrips()
    {
        var c1 = PedersenCommitment.Commit(Scalar.From(100), Scalar.From(7));
        var c2 = PedersenCommitment.Commit(Scalar.From(100), Scalar.From(7));
        Assert.True(c1 == c2);

        var roundTripped = Point.Decode(c1.Encode());
        Assert.True(roundTripped == c1);
    }

    [Fact]
    public void Pedersen_IsAdditivelyHomomorphic()
    {
        var left = PedersenCommitment.Commit(Scalar.From(100), Scalar.From(7))
                 + PedersenCommitment.Commit(Scalar.From(20), Scalar.From(3));
        var right = PedersenCommitment.Commit(Scalar.From(120), Scalar.From(10));
        Assert.True(left == right);
    }

    [Fact]
    public void Pedersen_Open_AcceptsCorrect_RejectsWrong()
    {
        var c = PedersenCommitment.Commit(Scalar.From(100), Scalar.From(7));
        Assert.True(PedersenCommitment.Open(c, Scalar.From(100), Scalar.From(7)));
        Assert.False(PedersenCommitment.Open(c, Scalar.From(101), Scalar.From(7)));
        Assert.False(PedersenCommitment.Open(c, Scalar.From(100), Scalar.From(8)));
    }

    [Fact]
    public void Generators_GandH_AreDistinct_AndStable()
    {
        Assert.False(Generators.G == Generators.H);
        Assert.Equal(Generators.G.Encode(), Generators.G.Encode()); // stable encoding
    }

    [Fact]
    public void RangeProof_Verifies_ValidProof_AndRoundTripsThroughBytes()
    {
        var (proof, v) = RangeProof.Prove(Scalar.From(42), Scalar.Random(), 64);
        Assert.True(RangeProof.Verify(v, proof, 64));

        var rebuilt = RangeProof.FromBytes(proof.ToBytes());
        Assert.True(RangeProof.Verify(v, rebuilt, 64));
    }

    [Fact]
    public void RangeProof_FailsVerification_AgainstWrongCommitment()
    {
        var (proof, _) = RangeProof.Prove(Scalar.From(42), Scalar.Random(), 64);
        var wrongCommitment = PedersenCommitment.Commit(Scalar.From(43), Scalar.Random());
        Assert.False(RangeProof.Verify(wrongCommitment, proof, 64));
    }
}
