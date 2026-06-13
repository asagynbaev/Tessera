//// Tessera issuer-registry validator (Plutus V3).
////
//// Mints a unique beacon token (asset name = `issuer_did_hash`) locked at the
//// script address with an immutable `IssuerDatum`. Mirrors the Solana `Issuer`
//// account: register-only, with no on-chain update or deactivate path (the
//// beacon is permanently locked, like the Solana account).
////
//// SECURITY (finding C7): issuer onboarding is GOVERNANCE-GATED. The validator
//// is parameterized by an `admin` verification-key-hash, and registration is
//// authorised only if that admin signs. Without this gate, anyone could mint a
//// beacon for ANY `issuer_did_hash` bound to an attacker-chosen `issuer_pubkey`
//// (the old validator only checked `did_hash == asset_name` and that the
//// attacker's own chosen pubkey signed — a trivially self-satisfiable check).
//// The admin signature anchors the trust decision off-chain: the governance key
//// vets the did_hash ↔ issuer_pubkey ↔ schema binding before co-signing.
////
//// We additionally validate the datum's `schema_uri_hash` length (32 bytes, the
//// SHA-256 the adapter commits) so a registration cannot lock a malformed or
//// empty schema commitment.

use aiken/collection/dict
use aiken/crypto.{VerificationKeyHash, blake2b_224}
use aiken/primitive/bytearray
use cardano/assets.{PolicyId, from_asset, tokens}
use cardano/transaction.{Transaction, placeholder}
use identity_registry/fixtures
use identity_registry/types.{IssuerDatum, IssuerMintRedeemer, RegisterIssuer}
use identity_registry/validation

/// SHA-256 digest length committed in `schema_uri_hash`.
const schema_hash_len: Int = 32

validator issuer_registry(admin: VerificationKeyHash) {
  mint(redeemer: IssuerMintRedeemer, policy_id: PolicyId, self: Transaction) {
    when redeemer is {
      RegisterIssuer -> {
        expect [Pair(asset_name, 1)] =
          dict.to_pairs(tokens(self.mint, policy_id))
        let output =
          validation.single_continuing_output(
            self.outputs,
            policy_id,
            asset_name,
          )
        let datum = validation.output_issuer_datum(output)
        and {
          // the beacon name binds the token to the issuer DID hash,
          datum.issuer_did_hash == asset_name,
          // the schema commitment is a well-formed SHA-256 digest,
          bytearray.length(datum.schema_uri_hash) == schema_hash_len,
          // and the governance admin authorises this registration (C7 gate).
          validation.signed_by(self.extra_signatories, admin),
        }
      }
    }
  }
}

// ───────────────────────────── tests ─────────────────────────────────────

test register_issuer_happy() {
  let tx =
    Transaction {
      ..placeholder,
      mint: from_asset(fixtures.own_hash, fixtures.issuer_did_hash, 1),
      outputs: [fixtures.issuer_output(fixtures.issuer_datum())],
      extra_signatories: [fixtures.admin_key],
    }
  issuer_registry.mint(fixtures.admin_key, RegisterIssuer, fixtures.own_hash, tx)
}

// Without the admin signature, registration is rejected even if the issuer's
// own chosen pubkey signs (this is the C7 attack the gate closes).
test register_issuer_no_admin() fail {
  let tx =
    Transaction {
      ..placeholder,
      mint: from_asset(fixtures.own_hash, fixtures.issuer_did_hash, 1),
      outputs: [fixtures.issuer_output(fixtures.issuer_datum())],
      extra_signatories: [blake2b_224(fixtures.issuer_pubkey)],
    }
  issuer_registry.mint(fixtures.admin_key, RegisterIssuer, fixtures.own_hash, tx)
}

// A foreign signer (neither admin) is rejected.
test register_issuer_wrong_signer() fail {
  let tx =
    Transaction {
      ..placeholder,
      mint: from_asset(fixtures.own_hash, fixtures.issuer_did_hash, 1),
      outputs: [fixtures.issuer_output(fixtures.issuer_datum())],
      extra_signatories: [fixtures.other_key],
    }
  issuer_registry.mint(fixtures.admin_key, RegisterIssuer, fixtures.own_hash, tx)
}

// A malformed (too-short) schema_uri_hash is rejected even with the admin signing.
test register_issuer_bad_schema_hash() fail {
  let bad =
    IssuerDatum {
      issuer_did_hash: fixtures.issuer_did_hash,
      schema_uri_hash: #"deadbeef",
      issuer_pubkey: fixtures.issuer_pubkey,
    }
  let tx =
    Transaction {
      ..placeholder,
      mint: from_asset(fixtures.own_hash, fixtures.issuer_did_hash, 1),
      outputs: [fixtures.issuer_output_with(bad, fixtures.issuer_value())],
      extra_signatories: [fixtures.admin_key],
    }
  issuer_registry.mint(fixtures.admin_key, RegisterIssuer, fixtures.own_hash, tx)
}

test register_issuer_double_mint() fail {
  let tx =
    Transaction {
      ..placeholder,
      mint: from_asset(fixtures.own_hash, fixtures.issuer_did_hash, 2),
      outputs: [fixtures.issuer_output(fixtures.issuer_datum())],
      extra_signatories: [fixtures.admin_key],
    }
  issuer_registry.mint(fixtures.admin_key, RegisterIssuer, fixtures.own_hash, tx)
}
