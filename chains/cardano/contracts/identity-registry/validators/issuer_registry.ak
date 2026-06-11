//// Tessera issuer-registry validator (Plutus V3).
////
//// Mints a unique beacon token (asset name = `issuer_did_hash`) locked at the
//// script address with an immutable `IssuerDatum`. Mirrors the Solana `Issuer`
//// account: register-only, with no on-chain update or deactivate path (the
//// beacon is permanently locked, like the Solana account). Registration is
//// self-sovereign — the issuer authorises it by signing with the key whose
//// hash is committed in the datum, which closes the Solana program's
//// unenforced "admin-gated" intent.

use aiken/collection/dict
use aiken/crypto.{blake2b_224}
use cardano/assets.{PolicyId, from_asset, tokens}
use cardano/transaction.{Transaction, placeholder}
use identity_registry/fixtures
use identity_registry/types.{IssuerMintRedeemer, RegisterIssuer}
use identity_registry/validation

validator issuer_registry {
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
          // and the issuer authorises their own registration.
          validation.signed_by(
            self.extra_signatories,
            blake2b_224(datum.issuer_pubkey),
          ),
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
      extra_signatories: [blake2b_224(fixtures.issuer_pubkey)],
    }
  issuer_registry.mint(RegisterIssuer, fixtures.own_hash, tx)
}

test register_issuer_wrong_signer() fail {
  let tx =
    Transaction {
      ..placeholder,
      mint: from_asset(fixtures.own_hash, fixtures.issuer_did_hash, 1),
      outputs: [fixtures.issuer_output(fixtures.issuer_datum())],
      extra_signatories: [fixtures.other_key],
    }
  issuer_registry.mint(RegisterIssuer, fixtures.own_hash, tx)
}

test register_issuer_double_mint() fail {
  let tx =
    Transaction {
      ..placeholder,
      mint: from_asset(fixtures.own_hash, fixtures.issuer_did_hash, 2),
      outputs: [fixtures.issuer_output(fixtures.issuer_datum())],
      extra_signatories: [blake2b_224(fixtures.issuer_pubkey)],
    }
  issuer_registry.mint(RegisterIssuer, fixtures.own_hash, tx)
}
