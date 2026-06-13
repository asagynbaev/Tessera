using Tessera.Attestations;

namespace Tessera.Sources.Bitcoin;

/// <summary>
/// Bitcoin attestation type tags this plugin emits. These are domain-specific, so — like
/// <c>property_right</c>/<c>encumbrance</c> in the X-Road plugin — they live here and register into
/// a <see cref="SchemaRegistry"/> via <see cref="BitcoinSchemas"/>, never in the vendor-neutral core.
/// </summary>
public static class BitcoinAttestationTypes
{
    /// <summary>Proven control of ≥1 Bitcoin address. Boolean fact; payload carries the address count only.</summary>
    public const string Control = "btc_control";

    /// <summary>Pedersen commitment to total confirmed balance (satoshis).</summary>
    public const string Balance = "btc_balance";

    /// <summary>Pedersen commitment to value-weighted holding age (days).</summary>
    public const string HodlAge = "btc_hodl_age";

    /// <summary>Claim key on <see cref="Control"/> carrying the number of proven addresses.</summary>
    public const string AddressCountClaim = "address_count";
}

/// <summary>
/// The Bitcoin attestation schemas, ready to register into any <see cref="SchemaRegistry"/>.
/// <see cref="BitcoinAttestationTypes.Balance"/> and <see cref="BitcoinAttestationTypes.HodlAge"/>
/// carry commitments (predicate proofs run against them); <see cref="BitcoinAttestationTypes.Control"/>
/// carries the <c>address_count</c> claim and no commitment.
/// </summary>
public static class BitcoinSchemas
{
    /// <summary>Base URI namespace for the Bitcoin schemas.</summary>
    public const string SchemaNamespace = "https://schemas.tessera/btc/v1";

    /// <summary>The three Bitcoin schemas this plugin emits.</summary>
    public static IReadOnlyList<AttestationSchema> Schemas { get; } = new[]
    {
        new AttestationSchema
        {
            Type = BitcoinAttestationTypes.Control,
            SchemaUri = $"{SchemaNamespace}/btc_control",
            RequiredClaimKeys = new[] { BitcoinAttestationTypes.AddressCountClaim },
            Description = "Proven control of ≥1 Bitcoin address (BIP-137 signed challenge). Payload carries the proven address count only — never any address, txid, or amount.",
        },
        new AttestationSchema
        {
            Type = BitcoinAttestationTypes.Balance,
            SchemaUri = $"{SchemaNamespace}/btc_balance",
            CarriesCommitment = true,
            Description = "Pedersen commitment to the total confirmed balance (satoshis) across the proven addresses.",
        },
        new AttestationSchema
        {
            Type = BitcoinAttestationTypes.HodlAge,
            SchemaUri = $"{SchemaNamespace}/btc_hodl_age",
            CarriesCommitment = true,
            Description = "Pedersen commitment to the value-weighted holding age (days) of the proven balance.",
        },
    };

    /// <summary>Register the Bitcoin schemas into <paramref name="registry"/>.</summary>
    public static void Register(SchemaRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);
        foreach (var schema in Schemas)
            registry.Register(schema);
    }

    /// <summary>A registry seeded with the standard schemas plus the Bitcoin ones.</summary>
    public static SchemaRegistry CreateStandardWithBitcoin()
    {
        var registry = SchemaRegistry.CreateStandard();
        Register(registry);
        return registry;
    }
}
