using System.Collections.Concurrent;
using Tessera.Attestations;
using Tessera.Core;

namespace Tessera.Sources.Bitcoin;

/// <summary>
/// Turns a holder's control-verified Bitcoin addresses into attestation drafts: a boolean
/// <c>btc_control</c> (carrying the proven address count only), and Pedersen-committed
/// <c>btc_balance</c> and <c>btc_hodl_age</c>. Mirrors the other Layer-2 sources but adds the
/// commitment+opening handling the committed types need.
/// </summary>
/// <remarks>
/// <para><b>Two ways to drive it.</b> The committed flow needs the openings delivered to the holder,
/// which the generic <see cref="IAttestationSource"/> contract cannot carry (it returns only public
/// drafts). So:</para>
/// <list type="bullet">
///   <item><see cref="ResolveForAsync"/> — the primary, direct API: pass the verified addresses and
///   get back the drafts, the per-type Pedersen openings, and the underlying facts in one call.
///   This is what the <c>BitcoinCreditLine</c> example uses.</item>
///   <item><see cref="ResolveAsync"/> — the pipeline path: reads the verified addresses from the
///   injected <see cref="IBitcoinControlStore"/> and returns only the public drafts; the openings
///   from that call are stashed and retrievable via <see cref="TryGetOpenings"/>.</item>
/// </list>
/// <para><b>Privacy invariant.</b> No address, txid, script, or plaintext amount is ever placed in a
/// draft payload — balances and ages appear only as Pedersen commitments, and <c>btc_control</c>
/// carries the address count, not the addresses. The facts (with plaintext values) are returned to
/// the issuer/holder out of band, never serialized into an attestation.</para>
/// </remarks>
public sealed class BitcoinAttestationSource : IAttestationSource
{
    private readonly IBitcoinProvider _provider;
    private readonly IBitcoinControlStore? _controlStore;
    private readonly CredentialProof _credentialProof;
    private readonly BitcoinSourceOptions _options;
    private readonly TimeProvider _clock;
    private readonly ConcurrentDictionary<string, IReadOnlyDictionary<string, byte[]>> _lastOpenings =
        new(StringComparer.Ordinal);

    /// <summary>
    /// Create a source over <paramref name="provider"/>. <paramref name="controlStore"/> is required
    /// only for the <see cref="ResolveAsync"/> pipeline path; <paramref name="credentialProof"/> and
    /// <paramref name="clock"/> default to fresh instances / the system clock.
    /// </summary>
    public BitcoinAttestationSource(
        IBitcoinProvider provider,
        IBitcoinControlStore? controlStore = null,
        BitcoinSourceOptions? options = null,
        CredentialProof? credentialProof = null,
        TimeProvider? clock = null)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _controlStore = controlStore;
        _options = options ?? new BitcoinSourceOptions();
        _credentialProof = credentialProof ?? new CredentialProof();
        _clock = clock ?? TimeProvider.System;
    }

    /// <inheritdoc/>
    public string SourceId => "btc.control";

    /// <summary>
    /// Compute facts over <paramref name="verified"/> and produce the drafts, the per-type Pedersen
    /// openings (keyed by attestation type — <c>btc_balance</c>, <c>btc_hodl_age</c>), and the facts.
    /// Returns an empty result when no addresses are verified (nothing is attested).
    /// </summary>
    public async Task<BitcoinAttestationResult> ResolveForAsync(
        DidId subject,
        IReadOnlyList<VerifiedBitcoinAddress> verified,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(verified);
        if (verified.Count == 0)
        {
            return new BitcoinAttestationResult
            {
                Drafts = Array.Empty<AttestationDraft>(),
                Openings = new Dictionary<string, byte[]>(),
                // Nothing is attested when no address is verified, so no chain snapshot is taken.
                Facts = new BitcoinFacts
                {
                    TotalSats = 0,
                    HodlAgeDays = 0,
                    OldestUtxoAgeDays = 0,
                    AddressCount = 0,
                    SnapshotBlockHeight = 0,
                    SnapshotBlockHash = "",
                    SnapshotTimeUtc = default,
                },
            };
        }

        var facts = await BitcoinFactCalculator.ComputeAsync(_provider, verified, _clock, ct).ConfigureAwait(false);

        var drafts = new List<AttestationDraft>();
        var openings = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        // The point-in-time snapshot every draft below binds to. Public chain data (height/hash/time);
        // it carries no address, txid, or amount, so it does not breach the privacy invariant.
        var snapshot = new ChainSnapshot
        {
            BlockHeight = facts.SnapshotBlockHeight,
            BlockHash = facts.SnapshotBlockHash,
            TimeUtc = facts.SnapshotTimeUtc,
        };

        // btc_control — boolean fact (≥1 address proven). Payload carries the COUNT plus the snapshot.
        var controlClaims = new Dictionary<string, object>
        {
            [BitcoinAttestationTypes.AddressCountClaim] = facts.AddressCount,
        };
        snapshot.WriteClaims(controlClaims);
        drafts.Add(new AttestationDraft(
            BitcoinAttestationTypes.Control,
            new AttestationPayload { Method = "btc_signmessage", Claims = controlClaims },
            _options.ControlValidity));

        // btc_balance — Pedersen commitment to total confirmed sats; opening goes to the holder.
        // The snapshot rides in the claims alongside the commitment (no plaintext amount).
        var (balanceCommitment, balanceOpening) = _credentialProof.CommitValue(facts.TotalSats);
        var balanceClaims = new Dictionary<string, object>();
        snapshot.WriteClaims(balanceClaims);
        drafts.Add(new AttestationDraft(
            BitcoinAttestationTypes.Balance,
            new AttestationPayload { Method = "btc_confirmed_sats", Commitment = balanceCommitment, Claims = balanceClaims },
            _options.BalanceValidity));
        openings[BitcoinAttestationTypes.Balance] = balanceOpening;

        // btc_hodl_age — Pedersen commitment to value-weighted holding age (days).
        var (ageCommitment, ageOpening) = _credentialProof.CommitValue(facts.HodlAgeDays);
        var ageClaims = new Dictionary<string, object>();
        snapshot.WriteClaims(ageClaims);
        drafts.Add(new AttestationDraft(
            BitcoinAttestationTypes.HodlAge,
            new AttestationPayload { Method = "btc_value_weighted_hodl_age_days", Commitment = ageCommitment, Claims = ageClaims },
            _options.HodlAgeValidity));
        openings[BitcoinAttestationTypes.HodlAge] = ageOpening;

        return new BitcoinAttestationResult { Drafts = drafts, Openings = openings, Facts = facts };
    }

    /// <summary>
    /// Issuance-pipeline entry point. Resolves the subject's verified addresses from the configured
    /// <see cref="IBitcoinControlStore"/> and returns the public drafts; the openings produced are
    /// retrievable via <see cref="TryGetOpenings"/>. Throws if no control store was configured —
    /// use <see cref="ResolveForAsync"/> for the direct, opening-returning path.
    /// </summary>
    public async Task<IReadOnlyList<AttestationDraft>> ResolveAsync(SubjectContext subject, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(subject);
        if (_controlStore is null)
            throw new InvalidOperationException(
                "BitcoinAttestationSource needs an IBitcoinControlStore for the IAttestationSource pipeline path. " +
                "Construct it with a control store, or call ResolveForAsync(subject, verified) directly.");

        var verified = await _controlStore.GetVerifiedAsync(subject.Subject, ct).ConfigureAwait(false);
        if (verified.Count == 0) return Array.Empty<AttestationDraft>();

        var result = await ResolveForAsync(subject.Subject, verified, ct).ConfigureAwait(false);
        _lastOpenings[subject.Subject.Value] = result.Openings;
        return result.Drafts;
    }

    /// <summary>
    /// Retrieve the Pedersen openings from the most recent <see cref="ResolveAsync"/> for the
    /// subject (keyed by attestation type). The holder needs these to build bound predicate proofs.
    /// </summary>
    public bool TryGetOpenings(DidId subject, out IReadOnlyDictionary<string, byte[]> openings)
        => _lastOpenings.TryGetValue(subject.Value, out openings!);
}

/// <summary>Drafts, per-type Pedersen openings, and the underlying facts from a resolve.</summary>
public sealed record BitcoinAttestationResult
{
    /// <summary>The public attestation drafts (no secrets).</summary>
    public required IReadOnlyList<AttestationDraft> Drafts { get; init; }

    /// <summary>
    /// Pedersen openings for the committed drafts, keyed by attestation type
    /// (<c>btc_balance</c>, <c>btc_hodl_age</c>). The holder keeps these to build bound proofs.
    /// </summary>
    public required IReadOnlyDictionary<string, byte[]> Openings { get; init; }

    /// <summary>The computed facts (plaintext values) — for the issuer/holder, never serialized.</summary>
    public required BitcoinFacts Facts { get; init; }
}

/// <summary>Validity lifetimes for the Bitcoin attestation types.</summary>
public sealed record BitcoinSourceOptions
{
    /// <summary>Lifetime of the <c>btc_control</c> attestation.</summary>
    public TimeSpan ControlValidity { get; init; } = TimeSpan.FromDays(90);

    /// <summary>Lifetime of the <c>btc_balance</c> attestation. Short by default — balances move.</summary>
    public TimeSpan BalanceValidity { get; init; } = TimeSpan.FromDays(7);

    /// <summary>Lifetime of the <c>btc_hodl_age</c> attestation.</summary>
    public TimeSpan HodlAgeValidity { get; init; } = TimeSpan.FromDays(7);
}
