namespace Tessera.Attestations;

/// <summary>
/// Describes the shape of an attestation type: its canonical schema URI, whether the payload
/// carries a Pedersen commitment (for predicate proofs), and which claim keys must be present.
/// Domain- and vendor-neutral — concrete domain schemas are registered by callers, not baked
/// into the core.
/// </summary>
public sealed record AttestationSchema
{
    /// <summary>The attestation type tag this schema describes (e.g. <c>"kyc_verified"</c>).</summary>
    public required string Type { get; init; }

    /// <summary>Canonical schema URI stamped onto attestations of this type.</summary>
    public required string SchemaUri { get; init; }

    /// <summary>True when the payload must carry a <see cref="AttestationPayload.Commitment"/> (e.g. accredited income).</summary>
    public bool CarriesCommitment { get; init; }

    /// <summary>Claim keys that must be present in <see cref="AttestationPayload.Claims"/>.</summary>
    public IReadOnlyList<string> RequiredClaimKeys { get; init; } = Array.Empty<string>();

    /// <summary>Human-readable description.</summary>
    public string? Description { get; init; }
}

/// <summary>Result of validating a payload against its schema.</summary>
public sealed record SchemaValidationResult(bool Valid, string? Reason)
{
    public static SchemaValidationResult Ok { get; } = new(true, null);
    public static SchemaValidationResult Fail(string reason) => new(false, reason);
}

/// <summary>Read side of the schema registry: resolves an attestation type to its schema.</summary>
public interface ISchemaRegistry
{
    AttestationSchema? Resolve(string type);
    bool TryResolve(string type, out AttestationSchema schema);
}

/// <summary>
/// Open registry of attestation schemas. Seeded with the narrow-generic standard types
/// (<see cref="AttestationTypes.KycVerified"/>, <see cref="AttestationTypes.Jurisdiction"/>,
/// <see cref="AttestationTypes.Accredited"/>) and extensible with any custom type via
/// <see cref="Register"/> — registering and validating a user schema requires no core changes.
/// </summary>
public sealed class SchemaRegistry : ISchemaRegistry
{
    /// <summary>Base URI namespace for the standard schemas.</summary>
    public const string StandardSchemaNamespace = "https://schemas.tessera/std/v1";

    private readonly Dictionary<string, AttestationSchema> _schemas = new(StringComparer.Ordinal);

    /// <summary>The three narrow-generic standard schemas defined by A5.</summary>
    public static IReadOnlyList<AttestationSchema> StandardSchemas { get; } = new[]
    {
        new AttestationSchema
        {
            Type = AttestationTypes.KycVerified,
            SchemaUri = $"{StandardSchemaNamespace}/kyc_verified",
            Description = "Subject completed a KYC process. Optional 'level' claim.",
        },
        new AttestationSchema
        {
            Type = AttestationTypes.Jurisdiction,
            SchemaUri = $"{StandardSchemaNamespace}/jurisdiction",
            RequiredClaimKeys = new[] { "country" },
            Description = "Subject's jurisdiction/residency. 'country' is ISO-3166 alpha-2.",
        },
        new AttestationSchema
        {
            Type = AttestationTypes.Accredited,
            SchemaUri = $"{StandardSchemaNamespace}/accredited",
            CarriesCommitment = true,
            Description = "Accredited-investor status with a Pedersen commitment to the income value.",
        },
    };

    /// <summary>An empty registry. Use <see cref="CreateStandard"/> for one seeded with the standard schemas.</summary>
    public SchemaRegistry()
    {
    }

    /// <summary>Build a registry pre-populated with the standard schemas.</summary>
    public static SchemaRegistry CreateStandard()
    {
        var registry = new SchemaRegistry();
        foreach (var schema in StandardSchemas)
            registry.Register(schema);
        return registry;
    }

    /// <summary>Register (or replace) a schema. Open to arbitrary custom types — no core edit required.</summary>
    public void Register(AttestationSchema schema)
    {
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentException.ThrowIfNullOrEmpty(schema.Type);
        ArgumentException.ThrowIfNullOrEmpty(schema.SchemaUri);
        _schemas[schema.Type] = schema;
    }

    public AttestationSchema? Resolve(string type)
        => _schemas.TryGetValue(type, out var s) ? s : null;

    public bool TryResolve(string type, out AttestationSchema schema)
    {
        var found = _schemas.TryGetValue(type, out var s);
        schema = s!;
        return found;
    }

    /// <summary>
    /// Validate an attestation's payload against its registered schema. Returns Ok when the type
    /// is unknown to this registry (open-world: unregistered types are not constrained here).
    /// </summary>
    public SchemaValidationResult Validate(Attestation attestation)
    {
        ArgumentNullException.ThrowIfNull(attestation);
        if (!TryResolve(attestation.Type, out var schema))
            return SchemaValidationResult.Ok;

        if (schema.CarriesCommitment && (attestation.Payload.Commitment is null || attestation.Payload.Commitment.Length == 0))
            return SchemaValidationResult.Fail($"schema_{attestation.Type}_missing_commitment");

        foreach (var key in schema.RequiredClaimKeys)
        {
            if (attestation.Payload.Claims is null || !attestation.Payload.Claims.ContainsKey(key))
                return SchemaValidationResult.Fail($"schema_{attestation.Type}_missing_claim:{key}");
        }

        return SchemaValidationResult.Ok;
    }
}
