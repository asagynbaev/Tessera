// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IdentityRegistry
/// @notice Minimal on-chain anchor for the Tessera identity layer. This is the EVM
///         counterpart of the Solana `identity-registry` Anchor program: it mirrors the same
///         core operations (registerDid / updateRoot / bumpRevocation / registerIssuer), the
///         same owner model, and the same "roots + revocation epochs only" rule.
///         It additionally exposes `deactivateIssuer` (authority-gated issuer revocation); the
///         Solana program is slated to gain an equivalent instruction + an issuer-registered
///         event in a later revision so the two backends are fully symmetric.
///
///         Only commitment roots and revocation epochs live here. DID documents,
///         attestations, reputation scores, and any user-facing or personally
///         identifiable data stay off-chain. This contract performs NO cryptographic
///         proof verification — verification is done off-chain in C# (`Tessera.Sdk`).
///
///         The chain answers exactly one question: *was the holder's attestation root R
///         at revocation epoch E, and is issuer X registered as active?*
///
/// @dev Account layout is intentionally small. Adding fields later is a versioned
///      migration; do not extend a struct without bumping `ACCOUNT_VERSION`.
contract IdentityRegistry {
    /// @notice On-chain record version. Bump on any breaking struct change.
    uint8 public constant ACCOUNT_VERSION = 1;

    /// @notice Maximum schema URI length, matching the Solana program's MAX_SCHEMA_URI_LEN.
    uint256 public constant MAX_SCHEMA_URI_LEN = 200;

    /// @dev Per-DID anchor. `owner` is the only key allowed to update or revoke.
    struct DidAnchor {
        bool exists;
        uint8 accountVersion;
        address owner;
        bytes32 attestationRoot;
        uint64 revocationEpoch;
        uint64 createdAt;
        uint64 updatedAt;
    }

    /// @dev Per-issuer record. `signingKey` is the issuer's off-chain Ed25519
    ///      verification key (32 bytes) — NOT an EVM address. Signature verification
    ///      happens off-chain when verifying attestations.
    struct IssuerRecord {
        bool exists;
        uint8 accountVersion;
        bytes32 signingKey;
        bool active;
        uint64 createdAt;
        string schemaUri;
    }

    /// @notice Authority permitted to register/deactivate issuers. Parity with the
    ///         Solana program's registry `authority` signer.
    address public authority;

    mapping(bytes32 => DidAnchor) private _anchors;
    mapping(bytes32 => IssuerRecord) private _issuers;

    event DidRegistered(bytes32 indexed didHash, address indexed owner, bytes32 attestationRoot);
    event RootUpdated(bytes32 indexed didHash, bytes32 newRoot);
    event RevocationBumped(bytes32 indexed didHash, uint64 newEpoch, uint8 reason);
    event IssuerRegistered(bytes32 indexed issuerDidHash, bytes32 signingKey, bool active, string schemaUri);
    event AuthorityTransferred(address indexed previousAuthority, address indexed newAuthority);

    error AlreadyRegistered();
    error NotRegistered();
    error NotOwner();
    error NotAuthority();
    error SchemaUriTooLong();
    error ZeroAuthority();
    error ZeroController();
    error InvalidSignature();

    modifier onlyAuthority() {
        if (msg.sender != authority) revert NotAuthority();
        _;
    }

    /// @param authority_ initial issuer-registry authority. Cannot be the zero address.
    constructor(address authority_) {
        if (authority_ == address(0)) revert ZeroAuthority();
        authority = authority_;
        emit AuthorityTransferred(address(0), authority_);
    }

    // ── DID anchors ──────────────────────────────────────────────────────────

    /// @notice Create a new DID anchor, binding it to the `controller` who proved control of the DID
    ///         by signing the registration. Because `didHash` is public, anyone could otherwise
    ///         front-run / squat a DID and have the off-chain verifier trust their root; requiring a
    ///         controller signature ensures only the DID controller can create the anchor, and the
    ///         transaction may be relayed by any sender (the controller need not pay gas).
    ///         The `controller` becomes the anchor `owner`; updateRoot / bumpRevocation stay owner-gated.
    ///         Mirrors Solana `register_did`.
    /// @param didHash          SHA-256(utf8(did)) — the chain-agnostic DID hash.
    /// @param attestationRoot  32-byte Merkle root of the holder's attestation bundle.
    /// @param controller       address whose key controls the DID; becomes the anchor owner.
    /// @param signature        65-byte ECDSA signature (r‖s‖v) by `controller` over the EIP-191
    ///                         personal-sign digest of
    ///                         keccak256(abi.encode(didHash, attestationRoot, block.chainid, address(this))).
    ///                         Binding chainid + contract address prevents cross-chain / cross-contract replay.
    function registerDid(
        bytes32 didHash,
        bytes32 attestationRoot,
        address controller,
        bytes calldata signature
    ) external {
        if (controller == address(0)) revert ZeroController();

        DidAnchor storage a = _anchors[didHash];
        if (a.exists) revert AlreadyRegistered();

        bytes32 structHash = keccak256(abi.encode(didHash, attestationRoot, block.chainid, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        if (_recover(digest, signature) != controller) revert InvalidSignature();

        a.exists = true;
        a.accountVersion = ACCOUNT_VERSION;
        a.owner = controller;
        a.attestationRoot = attestationRoot;
        a.revocationEpoch = 0;
        a.createdAt = uint64(block.timestamp);
        a.updatedAt = a.createdAt;

        emit DidRegistered(didHash, controller, attestationRoot);
    }

    /// @dev Recover the signer of `digest` from a 65-byte (r‖s‖v) ECDSA `signature`. Rejects
    ///      malformed lengths, the high-S malleability range (EIP-2), and the zero address.
    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) revert InvalidSignature();

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        // EIP-2: reject the upper half of the curve order to block signature malleability.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert InvalidSignature();
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert InvalidSignature();

        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
        return signer;
    }

    /// @notice Replace the attestation root for an existing DID. Owner-only.
    ///         Mirrors Solana `update_root` (`require_keys_eq!(anchor.owner, signer)`).
    function updateRoot(bytes32 didHash, bytes32 newRoot) external {
        DidAnchor storage a = _anchors[didHash];
        if (!a.exists) revert NotRegistered();
        if (a.owner != msg.sender) revert NotOwner();

        a.attestationRoot = newRoot;
        a.updatedAt = uint64(block.timestamp);

        emit RootUpdated(didHash, newRoot);
    }

    /// @notice Increment the revocation epoch, signalling prior presentations are stale.
    ///         Owner-only. Mirrors Solana `bump_revocation`. The `reason` is an opaque
    ///         tag mirrored from `RevocationReason`; it is emitted but not interpreted.
    /// @dev    Solidity 0.8 checked arithmetic reverts on uint64 overflow — parity with
    ///         the Solana program's explicit `EpochOverflow` guard.
    function bumpRevocation(bytes32 didHash, uint8 reason) external {
        DidAnchor storage a = _anchors[didHash];
        if (!a.exists) revert NotRegistered();
        if (a.owner != msg.sender) revert NotOwner();

        a.revocationEpoch += 1;
        a.updatedAt = uint64(block.timestamp);

        emit RevocationBumped(didHash, a.revocationEpoch, reason);
    }

    // ── Issuer registry ──────────────────────────────────────────────────────

    /// @notice Register (or re-register) an issuer. Authority-gated.
    ///         Mirrors Solana `register_issuer`.
    /// @param issuerDidHash SHA-256(utf8(issuerDid)).
    /// @param signingKey    issuer's 32-byte Ed25519 verification key.
    /// @param schemaUri     schema URI (<= MAX_SCHEMA_URI_LEN bytes).
    function registerIssuer(bytes32 issuerDidHash, bytes32 signingKey, string calldata schemaUri)
        external
        onlyAuthority
    {
        if (bytes(schemaUri).length > MAX_SCHEMA_URI_LEN) revert SchemaUriTooLong();

        IssuerRecord storage i = _issuers[issuerDidHash];
        if (!i.exists) {
            i.exists = true;
            i.createdAt = uint64(block.timestamp);
        }
        i.accountVersion = ACCOUNT_VERSION;
        i.signingKey = signingKey;
        i.schemaUri = schemaUri;
        i.active = true;

        emit IssuerRegistered(issuerDidHash, signingKey, true, schemaUri);
    }

    /// @notice Mark an issuer inactive. Authority-gated. Verification of attestations
    ///         from an inactive issuer fails off-chain.
    function deactivateIssuer(bytes32 issuerDidHash) external onlyAuthority {
        IssuerRecord storage i = _issuers[issuerDidHash];
        if (!i.exists) revert NotRegistered();
        i.active = false;
        emit IssuerRegistered(issuerDidHash, i.signingKey, false, i.schemaUri);
    }

    // ── Reads (flat tuples for robust off-chain ABI decoding) ─────────────────

    /// @notice Read a DID anchor. `exists` is false for unknown DIDs (all other fields zero).
    function getAnchor(bytes32 didHash)
        external
        view
        returns (
            bool exists,
            address owner,
            bytes32 attestationRoot,
            uint64 revocationEpoch,
            uint64 createdAt,
            uint64 updatedAt
        )
    {
        DidAnchor storage a = _anchors[didHash];
        return (a.exists, a.owner, a.attestationRoot, a.revocationEpoch, a.createdAt, a.updatedAt);
    }

    /// @notice Read an issuer record. `exists` is false for unknown issuers.
    function getIssuer(bytes32 issuerDidHash)
        external
        view
        returns (bool exists, bytes32 signingKey, bool active, uint64 createdAt, string memory schemaUri)
    {
        IssuerRecord storage i = _issuers[issuerDidHash];
        return (i.exists, i.signingKey, i.active, i.createdAt, i.schemaUri);
    }

    // ── Admin ────────────────────────────────────────────────────────────────

    /// @notice Transfer the issuer-registry authority to a new address.
    function transferAuthority(address newAuthority) external onlyAuthority {
        if (newAuthority == address(0)) revert ZeroAuthority();
        emit AuthorityTransferred(authority, newAuthority);
        authority = newAuthority;
    }
}
