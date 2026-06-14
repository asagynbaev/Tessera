using Nethereum.ABI.FunctionEncoding.Attributes;
using Nethereum.Contracts;

namespace Tessera.Chains.Evm.Internal;

// Nethereum ABI bindings for the chains/evm IdentityRegistry contract. Parameter names,
// types, and ordinals MUST match contracts/IdentityRegistry.sol exactly — the function
// selector is keccak256(canonical-signature)[:4], so any divergence sends bytes the
// contract rejects. Tessera.Chains.Evm.Tests asserts each selector against the contract.

[Function("registerDid")]
internal sealed class RegisterDidFunction : FunctionMessage
{
    [Parameter("bytes32", "didHash", 1)] public byte[] DidHash { get; set; } = default!;
    [Parameter("bytes32", "attestationRoot", 2)] public byte[] AttestationRoot { get; set; } = default!;
    [Parameter("address", "controller", 3)] public string Controller { get; set; } = default!;
    [Parameter("bytes", "signature", 4)] public byte[] Signature { get; set; } = default!;
}

[Function("updateRoot")]
internal sealed class UpdateRootFunction : FunctionMessage
{
    [Parameter("bytes32", "didHash", 1)] public byte[] DidHash { get; set; } = default!;
    [Parameter("bytes32", "newRoot", 2)] public byte[] NewRoot { get; set; } = default!;
}

[Function("bumpRevocation")]
internal sealed class BumpRevocationFunction : FunctionMessage
{
    [Parameter("bytes32", "didHash", 1)] public byte[] DidHash { get; set; } = default!;
    [Parameter("uint8", "reason", 2)] public byte Reason { get; set; }
}

[Function("registerIssuer")]
internal sealed class RegisterIssuerFunction : FunctionMessage
{
    [Parameter("bytes32", "issuerDidHash", 1)] public byte[] IssuerDidHash { get; set; } = default!;
    [Parameter("bytes32", "signingKey", 2)] public byte[] SigningKey { get; set; } = default!;
    [Parameter("string", "schemaUri", 3)] public string SchemaUri { get; set; } = default!;
}

[Function("deactivateIssuer")]
internal sealed class DeactivateIssuerFunction : FunctionMessage
{
    [Parameter("bytes32", "issuerDidHash", 1)] public byte[] IssuerDidHash { get; set; } = default!;
}

[Function("getAnchor")]
internal sealed class GetAnchorFunction : FunctionMessage
{
    [Parameter("bytes32", "didHash", 1)] public byte[] DidHash { get; set; } = default!;
}

[FunctionOutput]
internal sealed class GetAnchorOutputDTO : IFunctionOutputDTO
{
    [Parameter("bool", "exists", 1)] public bool Exists { get; set; }
    [Parameter("address", "owner", 2)] public string Owner { get; set; } = default!;
    [Parameter("bytes32", "attestationRoot", 3)] public byte[] AttestationRoot { get; set; } = default!;
    [Parameter("uint64", "revocationEpoch", 4)] public ulong RevocationEpoch { get; set; }
    [Parameter("uint64", "createdAt", 5)] public ulong CreatedAt { get; set; }
    [Parameter("uint64", "updatedAt", 6)] public ulong UpdatedAt { get; set; }
}
