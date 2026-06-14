//// Test fixtures shared by the validator test suites. Library-only module;
//// emits no on-chain code. Hash lengths are realistic (28-byte key/script
//// hashes, 32-byte digests) though the validators do not enforce length —
//// that is the off-chain adapter's responsibility.

use cardano/address.{Address, Script}
use cardano/assets.{Value, from_asset, from_lovelace, merge}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}
use identity_registry/types.{DidAnchorDatum, IssuerDatum}

// ── canonical sample bytes ───────────────────────────────────────────────

/// Script hash of the multi-purpose validator == thread-token policy id.
pub const own_hash: ByteArray =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

/// Controller verification-key hash (28 bytes).
pub const controller: ByteArray =
  #"c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"

/// An unrelated key hash, for wrong-signer rejection tests.
pub const other_key: ByteArray =
  #"bebebebebebebebebebebebebebebebebebebebebebebebebebebebe"

/// Governance admin verification-key hash gating issuer registration (C7).
pub const admin_key: ByteArray =
  #"adadadadadadadadadadadadadadadadadadadadadadadadadadadad"

pub const did_hash: ByteArray =
  #"d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"

pub const root_a: ByteArray =
  #"0101010101010101010101010101010101010101010101010101010101010101"

pub const root_b: ByteArray =
  #"0202020202020202020202020202020202020202020202020202020202020202"

pub const tx_id: ByteArray =
  #"1111111111111111111111111111111111111111111111111111111111111111"

pub const issuer_did_hash: ByteArray =
  #"e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"

pub const schema_uri_hash: ByteArray =
  #"5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c"

pub const issuer_pubkey: ByteArray =
  #"9999999999999999999999999999999999999999999999999999999999999999"

/// Output reference of the anchor UTxO being spent in spend-path tests.
pub const anchor_ref: OutputReference =
  OutputReference { transaction_id: tx_id, output_index: 0 }

// ── DID-anchor builders ──────────────────────────────────────────────────

pub fn anchor_datum(epoch: Int, root: ByteArray) -> DidAnchorDatum {
  DidAnchorDatum {
    did_hash,
    attestation_root: root,
    revocation_epoch: epoch,
    controller,
  }
}

/// Min-ADA plus exactly one thread token.
pub fn anchor_value() -> Value {
  merge(from_lovelace(2_000_000), from_asset(own_hash, did_hash, 1))
}

pub fn anchor_output_with(datum: DidAnchorDatum, value: Value) -> Output {
  Output {
    address: Address {
      payment_credential: Script(own_hash),
      stake_credential: None,
    },
    value,
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

pub fn anchor_output(datum: DidAnchorDatum) -> Output {
  anchor_output_with(datum, anchor_value())
}

pub fn anchor_input(datum: DidAnchorDatum) -> Input {
  Input { output_reference: anchor_ref, output: anchor_output(datum) }
}

// ── issuer builders ──────────────────────────────────────────────────────

pub fn issuer_datum() -> IssuerDatum {
  IssuerDatum { issuer_did_hash, schema_uri_hash, issuer_pubkey }
}

pub fn issuer_value() -> Value {
  merge(from_lovelace(2_000_000), from_asset(own_hash, issuer_did_hash, 1))
}

pub fn issuer_output_with(datum: IssuerDatum, value: Value) -> Output {
  Output {
    address: Address {
      payment_credential: Script(own_hash),
      stake_credential: None,
    },
    value,
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

pub fn issuer_output(datum: IssuerDatum) -> Output {
  issuer_output_with(datum, issuer_value())
}
