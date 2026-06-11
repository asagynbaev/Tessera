//// Datums and redeemers for the Tessera identity-registry validators.
////
//// On-chain we store ONLY audit data — the DID hash, the Merkle attestation
//// root, and a monotonic revocation epoch. Never PII, attestations, or DID
//// documents. This is the eUTXO counterpart of the Solana `identity-registry`
//// Anchor program; see docs/architecture.md for the Solana ↔ Cardano mapping.

use aiken/crypto.{VerificationKeyHash}

/// State carried by the single thread-token UTxO that anchors one DID.
/// Mirrors the Solana `DidAnchor` account. `created_at`/`updated_at` are not
/// stored on-chain — on Cardano they are recovered from the anchoring tx's
/// block time via the provider.
pub type DidAnchorDatum {
  did_hash: ByteArray,
  attestation_root: ByteArray,
  revocation_epoch: Int,
  controller: VerificationKeyHash,
}

/// Spend redeemer for an existing DID anchor.
pub type DidRedeemer {
  /// Replace the attestation root; the revocation epoch is unchanged.
  UpdateRoot { new_root: ByteArray }
  /// Increment the revocation epoch by exactly one; the root is unchanged.
  /// `reason` is advisory only (mirrors the Solana program's event field).
  BumpRevocation { reason: Int }
}

/// Mint redeemer for the DID-anchor thread token. Registration is the only
/// minting action — anchors are permanent, like the Solana program's accounts.
pub type AnchorMintRedeemer {
  RegisterDid
}

/// State carried by an issuer-registry UTxO. Mirrors the Solana `Issuer`
/// account and is immutable once created (no spend path), like Solana.
pub type IssuerDatum {
  issuer_did_hash: ByteArray,
  schema_uri_hash: ByteArray,
  issuer_pubkey: ByteArray,
}

/// Mint redeemer for the issuer-registry thread token.
pub type IssuerMintRedeemer {
  RegisterIssuer
}
