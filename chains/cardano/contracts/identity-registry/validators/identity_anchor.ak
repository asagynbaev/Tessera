//// Tessera DID-anchor validator (Plutus V3, multi-purpose).
////
//// One script serves as BOTH the thread-token minting policy and the spending
//// validator, so `policy_id == script_hash == script-address payment
//// credential`. The thread token (policy = own hash, asset name = `did_hash`)
//// makes a live anchor's state unforgeable: continuity and the controller
//// signature are enforced on every spend. Registration uniqueness across
//// separate transactions is resolved off-chain (read-then-register-or-update),
//// exactly like the Solana/EVM adapters — see chains/cardano/README.md for the
//// documented eUTXO trust boundary.

use aiken/collection/dict
use cardano/address.{Address, Script, VerificationKey}
use cardano/assets.{PolicyId, from_asset, quantity_of, tokens, zero}
use cardano/transaction.{Output, OutputReference, Transaction, placeholder}
use identity_registry/fixtures
use identity_registry/types.{
  AnchorMintRedeemer, BumpRevocation, DidAnchorDatum, DidRedeemer, RegisterDid,
  UpdateRoot,
}
use identity_registry/validation

validator identity_anchor {
  // register_did: mint the unique thread token (asset name = did_hash) and
  // create the anchor UTxO at this script's own address.
  mint(redeemer: AnchorMintRedeemer, policy_id: PolicyId, self: Transaction) {
    when redeemer is {
      RegisterDid -> {
        // Exactly one asset minted under this policy, quantity 1; its name is
        // the DID hash that keys the anchor.
        expect [Pair(asset_name, 1)] =
          dict.to_pairs(tokens(self.mint, policy_id))
        let output =
          validation.single_continuing_output(
            self.outputs,
            policy_id,
            asset_name,
          )
        let datum = validation.output_anchor_datum(output)
        and {
          // the token name binds the thread token to the datum's DID,
          datum.did_hash == asset_name,
          // fresh anchors start at epoch 0,
          datum.revocation_epoch == 0,
          // and the controller must authorise their own registration.
          validation.signed_by(self.extra_signatories, datum.controller),
        }
      }
    }
  }

  // update_root / bump_revocation: spend the anchor UTxO and recreate it with
  // mutated state, preserving the thread token and immutable fields.
  spend(
    datum: Option<DidAnchorDatum>,
    redeemer: DidRedeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(state) = datum
    let input = validation.own_input(self.inputs, own_ref)
    expect Script(own_hash) = input.output.address.payment_credential
    // The thread token must be present on the input being spent.
    expect quantity_of(input.output.value, own_hash, state.did_hash) == 1
    // The controller authorises every mutation.
    expect validation.signed_by(self.extra_signatories, state.controller)
    // No thread-token mint/burn during a spend (the token is conserved).
    expect quantity_of(self.mint, own_hash, state.did_hash) == 0
    // Exactly one continuing output carries the token back to the script.
    let output =
      validation.single_continuing_output(
        self.outputs,
        own_hash,
        state.did_hash,
      )
    let next = validation.output_anchor_datum(output)
    // did_hash and controller are immutable across the spend.
    expect next.did_hash == state.did_hash
    expect next.controller == state.controller
    when redeemer is {
      UpdateRoot { new_root } -> and {
          next.revocation_epoch == state.revocation_epoch,
          next.attestation_root == new_root,
        }
      BumpRevocation { reason: _ } -> and {
          next.attestation_root == state.attestation_root,
          next.revocation_epoch == state.revocation_epoch + 1,
        }
    }
  }
}

// ───────────────────────────── tests ─────────────────────────────────────

// register_did — happy path.
test register_did_happy() {
  let tx =
    Transaction {
      ..placeholder,
      mint: from_asset(fixtures.own_hash, fixtures.did_hash, 1),
      outputs: [fixtures.anchor_output(fixtures.anchor_datum(0, fixtures.root_a))],
      extra_signatories: [fixtures.controller],
    }
  identity_anchor.mint(RegisterDid, fixtures.own_hash, tx)
}

// register_did rejects an unsigned/forged controller.
test register_did_wrong_signer() fail {
  let tx =
    Transaction {
      ..placeholder,
      mint: from_asset(fixtures.own_hash, fixtures.did_hash, 1),
      outputs: [fixtures.anchor_output(fixtures.anchor_datum(0, fixtures.root_a))],
      extra_signatories: [fixtures.other_key],
    }
  identity_anchor.mint(RegisterDid, fixtures.own_hash, tx)
}

// register_did rejects a non-zero starting epoch.
test register_did_nonzero_epoch() fail {
  let tx =
    Transaction {
      ..placeholder,
      mint: from_asset(fixtures.own_hash, fixtures.did_hash, 1),
      outputs: [fixtures.anchor_output(fixtures.anchor_datum(1, fixtures.root_a))],
      extra_signatories: [fixtures.controller],
    }
  identity_anchor.mint(RegisterDid, fixtures.own_hash, tx)
}

// register_did rejects minting more than one thread token.
test register_did_double_mint() fail {
  let tx =
    Transaction {
      ..placeholder,
      mint: from_asset(fixtures.own_hash, fixtures.did_hash, 2),
      outputs: [fixtures.anchor_output(fixtures.anchor_datum(0, fixtures.root_a))],
      extra_signatories: [fixtures.controller],
    }
  identity_anchor.mint(RegisterDid, fixtures.own_hash, tx)
}

// register_did rejects two parallel continuing outputs (forged parallel state).
test register_did_two_outputs() fail {
  let out = fixtures.anchor_output(fixtures.anchor_datum(0, fixtures.root_a))
  let tx =
    Transaction {
      ..placeholder,
      mint: from_asset(fixtures.own_hash, fixtures.did_hash, 1),
      outputs: [out, out],
      extra_signatories: [fixtures.controller],
    }
  identity_anchor.mint(RegisterDid, fixtures.own_hash, tx)
}

// update_root — happy path.
test update_root_happy() {
  let state = fixtures.anchor_datum(0, fixtures.root_a)
  let tx =
    Transaction {
      ..placeholder,
      inputs: [fixtures.anchor_input(state)],
      outputs: [fixtures.anchor_output(fixtures.anchor_datum(0, fixtures.root_b))],
      extra_signatories: [fixtures.controller],
      mint: zero,
    }
  identity_anchor.spend(
    Some(state),
    UpdateRoot { new_root: fixtures.root_b },
    fixtures.anchor_ref,
    tx,
  )
}

// update_root rejects a missing controller signature.
test update_root_wrong_signer() fail {
  let state = fixtures.anchor_datum(0, fixtures.root_a)
  let tx =
    Transaction {
      ..placeholder,
      inputs: [fixtures.anchor_input(state)],
      outputs: [fixtures.anchor_output(fixtures.anchor_datum(0, fixtures.root_b))],
      extra_signatories: [fixtures.other_key],
      mint: zero,
    }
  identity_anchor.spend(
    Some(state),
    UpdateRoot { new_root: fixtures.root_b },
    fixtures.anchor_ref,
    tx,
  )
}

// update_root must not change the revocation epoch.
test update_root_changes_epoch() fail {
  let state = fixtures.anchor_datum(0, fixtures.root_a)
  let tx =
    Transaction {
      ..placeholder,
      inputs: [fixtures.anchor_input(state)],
      outputs: [fixtures.anchor_output(fixtures.anchor_datum(1, fixtures.root_b))],
      extra_signatories: [fixtures.controller],
      mint: zero,
    }
  identity_anchor.spend(
    Some(state),
    UpdateRoot { new_root: fixtures.root_b },
    fixtures.anchor_ref,
    tx,
  )
}

// update_root must not let the continuing datum re-key the DID hash.
test update_root_changes_did_hash() fail {
  let state = fixtures.anchor_datum(0, fixtures.root_a)
  // Output keeps the (policy, did_hash) token but the datum claims a new hash.
  let forged =
    DidAnchorDatum {
      did_hash: fixtures.root_b,
      attestation_root: fixtures.root_b,
      revocation_epoch: 0,
      controller: fixtures.controller,
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [fixtures.anchor_input(state)],
      outputs: [fixtures.anchor_output_with(forged, fixtures.anchor_value())],
      extra_signatories: [fixtures.controller],
      mint: zero,
    }
  identity_anchor.spend(
    Some(state),
    UpdateRoot { new_root: fixtures.root_b },
    fixtures.anchor_ref,
    tx,
  )
}

// update_root rejects sneaking an extra thread-token mint into the spend.
test update_root_with_mint() fail {
  let state = fixtures.anchor_datum(0, fixtures.root_a)
  let tx =
    Transaction {
      ..placeholder,
      inputs: [fixtures.anchor_input(state)],
      outputs: [fixtures.anchor_output(fixtures.anchor_datum(0, fixtures.root_b))],
      extra_signatories: [fixtures.controller],
      mint: from_asset(fixtures.own_hash, fixtures.did_hash, 1),
    }
  identity_anchor.spend(
    Some(state),
    UpdateRoot { new_root: fixtures.root_b },
    fixtures.anchor_ref,
    tx,
  )
}

// Token theft: the thread token must not leave the script address.
test update_root_token_theft() fail {
  let state = fixtures.anchor_datum(0, fixtures.root_a)
  let stolen =
    fixtures.anchor_output_with(
      fixtures.anchor_datum(0, fixtures.root_b),
      fixtures.anchor_value(),
    )
  // Re-home the same value+datum to an attacker-controlled key address.
  let theft =
    Output {
      ..stolen,
      address: Address {
        payment_credential: VerificationKey(fixtures.other_key),
        stake_credential: None,
      },
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [fixtures.anchor_input(state)],
      outputs: [theft],
      extra_signatories: [fixtures.controller],
      mint: zero,
    }
  identity_anchor.spend(
    Some(state),
    UpdateRoot { new_root: fixtures.root_b },
    fixtures.anchor_ref,
    tx,
  )
}

// Double satisfaction: two continuing outputs carrying the token.
test update_root_double_satisfaction() fail {
  let state = fixtures.anchor_datum(0, fixtures.root_a)
  let out = fixtures.anchor_output(fixtures.anchor_datum(0, fixtures.root_b))
  let tx =
    Transaction {
      ..placeholder,
      inputs: [fixtures.anchor_input(state)],
      outputs: [out, out],
      extra_signatories: [fixtures.controller],
      mint: zero,
    }
  identity_anchor.spend(
    Some(state),
    UpdateRoot { new_root: fixtures.root_b },
    fixtures.anchor_ref,
    tx,
  )
}

// bump_revocation — happy path (epoch 0 → 1, root unchanged).
test bump_revocation_happy() {
  let state = fixtures.anchor_datum(0, fixtures.root_a)
  let tx =
    Transaction {
      ..placeholder,
      inputs: [fixtures.anchor_input(state)],
      outputs: [fixtures.anchor_output(fixtures.anchor_datum(1, fixtures.root_a))],
      extra_signatories: [fixtures.controller],
      mint: zero,
    }
  identity_anchor.spend(
    Some(state),
    BumpRevocation { reason: 4 },
    fixtures.anchor_ref,
    tx,
  )
}

// bump_revocation must increment by exactly one (no rollback / no stall).
test bump_revocation_no_increment() fail {
  let state = fixtures.anchor_datum(2, fixtures.root_a)
  let tx =
    Transaction {
      ..placeholder,
      inputs: [fixtures.anchor_input(state)],
      outputs: [fixtures.anchor_output(fixtures.anchor_datum(2, fixtures.root_a))],
      extra_signatories: [fixtures.controller],
      mint: zero,
    }
  identity_anchor.spend(
    Some(state),
    BumpRevocation { reason: 0 },
    fixtures.anchor_ref,
    tx,
  )
}

// bump_revocation must not change the attestation root.
test bump_revocation_changes_root() fail {
  let state = fixtures.anchor_datum(0, fixtures.root_a)
  let tx =
    Transaction {
      ..placeholder,
      inputs: [fixtures.anchor_input(state)],
      outputs: [fixtures.anchor_output(fixtures.anchor_datum(1, fixtures.root_b))],
      extra_signatories: [fixtures.controller],
      mint: zero,
    }
  identity_anchor.spend(
    Some(state),
    BumpRevocation { reason: 0 },
    fixtures.anchor_ref,
    tx,
  )
}
