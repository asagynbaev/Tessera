namespace Tessera.Attestations;

using Tessera.Core;

/// <summary>
/// Signed attestation envelope. Generic over type — not balance-specific.
/// Issuer attests something about a subject; holder includes it in their Merkle bundle.
/// </summary>
public sealed record Attestation
{
    public required string Schema { get; init; }
    public required string Type { get; init; }
    public required DidId Issuer { get; init; }
    public required DidId Subject { get; init; }
    public required DateTimeOffset IssuedAt { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }
    public required byte[] Nonce { get; init; }
    public required AttestationPayload Payload { get; init; }
    public required AttestationSignature Signature { get; init; }
}

/// <summary>
/// Public, verifier-readable portion of an attestation. The actual value (income, score, etc.)
/// is committed in <see cref="Commitment"/>; selective disclosure proofs are made against it.
/// </summary>
public sealed record AttestationPayload
{
    public byte[]? Commitment { get; init; }
    public required string Method { get; init; }
    public IReadOnlyDictionary<string, object>? Claims { get; init; }
}

public sealed record AttestationSignature
{
    public required string Algorithm { get; init; }
    public required byte[] Value { get; init; }
}

/// <summary>
/// Well-known attestation type identifiers. Deliberately generic and identity-oriented.
/// Domain- and vendor-specific types (a country's property registry, a named KYC provider's
/// tiers, ...) are NOT defined here — callers register those through <see cref="SchemaRegistry"/>.
/// </summary>
public static class AttestationTypes
{
    public const string HumanVerified = "human_verified";
    public const string PhoneVerified = "phone_verified";
    public const string TelegramVerified = "telegram_verified";
    public const string WalletVerified = "wallet_verified";
    public const string NonUsUser = "non_us_user";
    public const string ReputationScore = "reputation_score";
    public const string TrustedJudge = "trusted_judge";
    public const string AgentIdentity = "agent_identity";

    // ── A5 narrow-generic standard types ──────────────────────────────────
    /// <summary>Subject passed an (unspecified) KYC process. Optional <c>level</c> claim.</summary>
    public const string KycVerified = "kyc_verified";

    /// <summary>Subject's jurisdiction/residency. Requires a <c>country</c> claim (ISO-3166 alpha-2).</summary>
    public const string Jurisdiction = "jurisdiction";

    /// <summary>Subject is an accredited investor. Carries a Pedersen commitment to the income value.</summary>
    public const string Accredited = "accredited";
}
