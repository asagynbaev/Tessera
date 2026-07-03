using Tessera.Attestations;

namespace Tessera.Attestations.Tests;

/// <summary>
/// The soundness property of A4 predicates: a bound proof verifies only against the exact
/// attestation commitment it was built for. This is what stops a holder from attaching a valid
/// range proof about an arbitrary value.
/// </summary>
public class CredentialProofBindingTests
{
    [Fact]
    public void VerifyBound_Accepts_ProofBoundToItsCommitment()
    {
        var cp = new CredentialProof();
        var (commitment, opening) = cp.CommitValue(120_000);
        var bundle = cp.ProveBoundMinimum(120_000, 100_000, opening, "income");

        Assert.True(cp.VerifyBound(commitment, bundle));
    }

    [Fact]
    public void VerifyAgainstOwnCommitment_IsUnbound_AndProvesNothingAboutAnAttestation()
    {
        // The renamed unbound self-check verifies a bundle against ITS OWN commitment only.
        var cp = new CredentialProof();
        var standalone = cp.ProveMinimum(120_000, 100_000, "income");
        Assert.True(cp.VerifyAgainstOwnCommitment(standalone));

        // It is explicitly NOT attestation-bound: an independent attestation commitment does not
        // verify the same proof (that guarantee comes from VerifyBound, not this method).
        var (attestationCommitment, _) = cp.CommitValue(120_000);
        Assert.False(cp.VerifyBound(attestationCommitment, standalone));
    }

    [Fact]
    public void VerifyBound_Rejects_ProofBoundToDifferentCommitment()
    {
        var cp = new CredentialProof();
        var (_, openingA) = cp.CommitValue(120_000);
        var bundle = cp.ProveBoundMinimum(120_000, 100_000, openingA, "income");

        var (commitmentB, _) = cp.CommitValue(120_000); // same value, independent blinding
        Assert.False(cp.VerifyBound(commitmentB, bundle));
    }

    [Fact]
    public void VerifyBound_Rejects_UnboundProof()
    {
        var cp = new CredentialProof();
        var (commitment, _) = cp.CommitValue(120_000);
        var unbound = cp.ProveMinimum(120_000, 100_000, "income"); // fresh blinding, not bound

        Assert.False(cp.VerifyBound(commitment, unbound));
    }

    [Fact]
    public void VerifyBound_Rejects_MalformedInput()
    {
        var cp = new CredentialProof();
        var (commitment, opening) = cp.CommitValue(120_000);
        var bundle = cp.ProveBoundMinimum(120_000, 100_000, opening, "income");

        Assert.False(cp.VerifyBound(new byte[33], bundle));        // not a valid point
        Assert.False(cp.VerifyBound(commitment, new CredentialBundle())); // empty bundle
    }

    [Fact]
    public void ProveBoundMinimum_Rejects_ValueBelowThreshold()
    {
        var cp = new CredentialProof();
        var (_, opening) = cp.CommitValue(50_000);
        Assert.Throws<ArgumentException>(() => cp.ProveBoundMinimum(50_000, 100_000, opening, "income"));
    }

    // ── two-sided bound range (both bounds cryptographically proven) ─────────

    [Theory]
    [InlineData(100)] // lower edge
    [InlineData(150)] // interior
    [InlineData(200)] // upper edge
    public void VerifyBound_Accepts_TwoSidedRange_WithinBounds(long value)
    {
        var cp = new CredentialProof();
        var (commitment, opening) = cp.CommitValue(value);
        var bundle = cp.ProveBoundRange(value, 100, 200, opening, "age");
        Assert.NotNull(bundle.UpperRangeProof);
        Assert.True(cp.VerifyBound(commitment, bundle));
    }

    [Theory]
    [InlineData(99)]   // below min
    [InlineData(201)]  // above max
    public void ProveBoundRange_Rejects_OutOfRangeValue(long value)
    {
        var cp = new CredentialProof();
        var (_, opening) = cp.CommitValue(value);
        Assert.Throws<ArgumentOutOfRangeException>(() => cp.ProveBoundRange(value, 100, 200, opening, "age"));
    }

    [Fact]
    public void VerifyBound_Rejects_RangeWithoutUpperProof()
    {
        // A Range bundle stripped of its upper proof is not a valid two-sided proof.
        var cp = new CredentialProof();
        var (commitment, opening) = cp.CommitValue(150);
        var bundle = cp.ProveBoundRange(150, 100, 200, opening, "age");
        var stripped = new CredentialBundle
        {
            Label = bundle.Label,
            Commitment = bundle.Commitment,
            RangeProof = bundle.RangeProof,
            UpperRangeProof = null, // removed
            Threshold = bundle.Threshold,
            UpperBound = bundle.UpperBound,
            ProofType = CredentialProofType.Range,
        };
        Assert.False(cp.VerifyBound(commitment, stripped));
    }

    [Fact]
    public void VerifyBound_Rejects_TwoSidedRange_BoundToDifferentCommitment()
    {
        var cp = new CredentialProof();
        var (_, opening) = cp.CommitValue(150);
        var bundle = cp.ProveBoundRange(150, 100, 200, opening, "age");
        var (otherCommitment, _) = cp.CommitValue(150);
        Assert.False(cp.VerifyBound(otherCommitment, bundle));
    }

    [Fact]
    public void TwoSidedRange_SurvivesSerializationRoundTrip()
    {
        var cp = new CredentialProof();
        var (commitment, opening) = cp.CommitValue(150);
        var bundle = cp.ProveBoundRange(150, 100, 200, opening, "age");

        var restored = cp.Deserialize(cp.Serialize(bundle));
        Assert.NotNull(restored.UpperRangeProof);
        Assert.True(cp.VerifyBound(commitment, restored));
    }

    // ── Bitcoin satoshi amounts (proof-of-Bitcoin via Sources.Bitcoin) ───────
    //
    // The 64-bit range proof holds any satoshi balance: 100 BTC, and even the whole 21M-BTC
    // supply, fit far below 2^64. These are the bound proofs the btc_balance attestation drives.

    [Fact]
    public void ProveBoundMinimum_HundredBtcInSats_AboveOneBtc_VerifiesBound()
    {
        var cp = new CredentialProof();
        const long hundredBtc = 10_000_000_000; // 100 BTC in sats
        const long oneBtc = 100_000_000;        // 1 BTC threshold

        var (commitment, opening) = cp.CommitValue(hundredBtc);
        var bundle = cp.ProveBoundMinimum(hundredBtc, oneBtc, opening, "btc_balance");

        Assert.True(cp.VerifyBound(commitment, bundle));
    }

    [Fact]
    public void ProveBoundMinimum_WholeBitcoinSupplyInSats_VerifiesBound()
    {
        var cp = new CredentialProof();
        const long supplySats = 2_100_000_000_000_000; // 21,000,000 BTC in sats (~2^51)
        const long oneBtc = 100_000_000;

        var (commitment, opening) = cp.CommitValue(supplySats);
        var bundle = cp.ProveBoundMinimum(supplySats, oneBtc, opening, "btc_balance");

        Assert.True(cp.VerifyBound(commitment, bundle));
    }

    // ── Homomorphic predicates over combined commitments ─────────────────────
    //
    // Pedersen commitments are additively homomorphic, so a bound proof over a SUM or DIFFERENCE of
    // commitments works with the existing range-proof math. Phrased purely as math (commitmentA/B/C).

    [Fact]
    public void CombinedCommitments_SumOfThree_AboveThreshold_VerifiesBound()
    {
        var cp = new CredentialProof();
        const long valueA = 40, valueB = 35, valueC = 50; // sum = 125
        const long publicThreshold = 100;

        var (commitmentA, openingA) = cp.CommitValue(valueA);
        var (commitmentB, openingB) = cp.CommitValue(valueB);
        var (commitmentC, openingC) = cp.CommitValue(valueC);

        // Verifier side: C = commitmentA + commitmentB + commitmentC.
        var combinedCommitment = CredentialProof.CombineCommitments(
            CredentialProof.CombineCommitments(commitmentA, commitmentB), commitmentC);

        // Prover side: combined opening + combined value, proven ≥ threshold.
        var combinedOpening = CredentialProof.CombineOpenings(
            CredentialProof.CombineOpenings(openingA, openingB), openingC);
        var bundle = cp.ProveBoundMinimum(valueA + valueB + valueC, publicThreshold, combinedOpening, "sum");

        Assert.True(cp.VerifyBound(combinedCommitment, bundle));
    }

    [Fact]
    public void CombinedCommitments_Difference_NonNegative_VerifiesBound()
    {
        var cp = new CredentialProof();
        const long valueA = 120, valueB = 80; // A − B = 40 ≥ 0

        var (commitmentA, openingA) = cp.CommitValue(valueA);
        var (commitmentB, openingB) = cp.CommitValue(valueB);

        var diffCommitment = CredentialProof.CombineCommitments(commitmentA, commitmentB, subtract: true);
        var diffOpening = CredentialProof.CombineOpenings(openingA, openingB, subtract: true);
        var bundle = cp.ProveBoundMinimum(valueA - valueB, 0, diffOpening, "diff");

        Assert.True(cp.VerifyBound(diffCommitment, bundle));
    }

    [Fact]
    public void CombinedCommitments_Difference_Negative_ProverCannotProve()
    {
        var cp = new CredentialProof();
        const long valueA = 60, valueB = 100; // A − B = −40 < 0

        var (_, openingA) = cp.CommitValue(valueA);
        var (_, openingB) = cp.CommitValue(valueB);
        var diffOpening = CredentialProof.CombineOpenings(openingA, openingB, subtract: true);

        // A prover with valueA < valueB cannot produce a passing bundle: the shifted value is negative,
        // so ProveBoundMinimum refuses to build a proof at all.
        Assert.Throws<ArgumentException>(() => cp.ProveBoundMinimum(valueA - valueB, 0, diffOpening, "diff"));
    }
}
