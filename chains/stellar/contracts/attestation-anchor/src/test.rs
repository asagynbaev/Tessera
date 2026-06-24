//! Unit tests for the DID attestation anchor.
//!
//! These mirror the C# `StellarTestnetSmokeTests` scenarios at the contract level:
//! register a fresh DID, re-anchor (root update, epoch unchanged), bump revocation,
//! read an unknown DID, and the owner/`not-found` failure paths. Auth is mocked so
//! `require_auth` succeeds; the owner *binding* (an existing anchor owned by a
//! different account) is still enforced by the contract's explicit check.

use crate::{AnchorError, AttestationAnchor, AttestationAnchorClient};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, Error};

fn setup(env: &Env) -> AttestationAnchorClient<'_> {
    env.mock_all_auths();
    let contract_id = env.register(AttestationAnchor, ());
    AttestationAnchorClient::new(env, &contract_id)
}

fn did_hash(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

fn root(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

#[test]
fn anchor_root_registers_fresh_did() {
    let env = Env::default();
    let client = setup(&env);
    let owner = Address::generate(&env);
    let did = did_hash(&env, 1);
    let r = root(&env, 9);

    client.anchor_root(&owner, &did, &r);

    let anchor = client.get_anchor(&did).unwrap();
    assert_eq!(anchor.owner, owner);
    assert_eq!(anchor.root, r);
    assert_eq!(anchor.epoch, 0);
}

#[test]
fn anchor_root_twice_updates_root_keeps_epoch() {
    let env = Env::default();
    let client = setup(&env);
    let owner = Address::generate(&env);
    let did = did_hash(&env, 2);

    client.anchor_root(&owner, &did, &root(&env, 1));
    client.anchor_root(&owner, &did, &root(&env, 2));

    let anchor = client.get_anchor(&did).unwrap();
    assert_eq!(anchor.root, root(&env, 2));
    assert_eq!(anchor.epoch, 0);
}

#[test]
fn bump_revocation_increments_epoch() {
    let env = Env::default();
    let client = setup(&env);
    let owner = Address::generate(&env);
    let did = did_hash(&env, 3);
    client.anchor_root(&owner, &did, &root(&env, 1));

    assert_eq!(client.bump_revocation(&did, &1), 1);
    assert_eq!(client.bump_revocation(&did, &2), 2);
    assert_eq!(client.get_anchor(&did).unwrap().epoch, 2);
}

#[test]
fn get_anchor_unknown_did_returns_none() {
    let env = Env::default();
    let client = setup(&env);
    assert!(client.get_anchor(&did_hash(&env, 200)).is_none());
}

#[test]
fn anchor_root_by_different_owner_traps() {
    let env = Env::default();
    let client = setup(&env);
    let owner = Address::generate(&env);
    let attacker = Address::generate(&env);
    let did = did_hash(&env, 4);

    client.anchor_root(&owner, &did, &root(&env, 1));

    // mock_all_auths lets the attacker's require_auth pass; the explicit owner check
    // is what rejects the squat.
    // anchor_root returns (), not Result<…, AnchorError>, and fails via panic_with_error!, so the
    // try_ client surfaces the generic soroban Error (from the contract-error code), not the enum.
    let err = client.try_anchor_root(&attacker, &did, &root(&env, 2));
    assert_eq!(err, Err(Ok(Error::from(AnchorError::NotOwner))));
}

#[test]
fn bump_revocation_unknown_did_traps() {
    let env = Env::default();
    let client = setup(&env);
    let err = client.try_bump_revocation(&did_hash(&env, 5), &1);
    assert_eq!(err, Err(Ok(Error::from(AnchorError::AnchorNotFound))));
}
