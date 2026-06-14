//! Unit tests for the Ed25519-based attestation verifier.
//!
//! The contract verifies issuer Ed25519 signatures over the canonical message
//! `data || salt` against an issuer public key held in instance storage. These tests
//! produce real signatures with a *deterministic* in-test issuer key (fixed seed, no
//! `rand`), initialize the contract, register the issuer's public key, and exercise
//! the verification paths. Invalid-signature paths trap (the host reverts), so they
//! are asserted with `#[should_panic]`.

use crate::{VerificationError, ZkpVerifier, ZkpVerifierClient};
use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::{
    testutils::Address as _, Address, Bytes, BytesN, Env, Vec,
};

/// Fixed 32-byte seed for a deterministic in-test issuer signing key.
const ISSUER_SEED: [u8; 32] = [
    0x55, 0x75, 0x43, 0x32, 0xf6, 0x05, 0xd5, 0x14, 0xb1, 0x65, 0x8c, 0x16, 0x2f, 0x87, 0x86,
    0xf7, 0x79, 0xb4, 0x24, 0xa7, 0x4e, 0xf4, 0xa6, 0xd7, 0x42, 0x7d, 0x26, 0x86, 0x0f, 0x84,
    0x5c, 0x77,
];

/// Returns the deterministic in-test issuer signing key.
fn issuer_signing_key() -> SigningKey {
    SigningKey::from_bytes(&ISSUER_SEED)
}

/// Returns the issuer's Ed25519 public key as a Soroban `BytesN<32>`.
fn issuer_public_key(env: &Env) -> BytesN<32> {
    let vk = issuer_signing_key().verifying_key();
    BytesN::from_array(env, &vk.to_bytes())
}

/// Registers the contract, initializes it with an admin, and sets the trusted issuer key.
/// Returns the typed client. Auth is mocked so `require_auth` succeeds in tests.
fn setup(env: &Env) -> ZkpVerifierClient {
    env.mock_all_auths();
    let contract_id = env.register(ZkpVerifier, ());
    let client = ZkpVerifierClient::new(env, &contract_id);
    let admin = Address::generate(env);
    client.initialize(&admin);
    client.set_issuer(&issuer_public_key(env));
    client
}

/// Helper function to create test salt (16 bytes) both as raw bytes and Soroban `Bytes`.
fn test_salt_array() -> [u8; 16] {
    let mut salt = [0u8; 16];
    for i in 0..16u8 {
        salt[i as usize] = i;
    }
    salt
}

fn create_test_salt(env: &Env) -> Bytes {
    Bytes::from_array(env, &test_salt_array())
}

/// Signs the canonical message `data || salt` with the in-test issuer key and returns
/// the 64-byte signature as a Soroban `BytesN<64>`.
fn sign_proof(env: &Env, data: &[u8], salt: &[u8]) -> BytesN<64> {
    let mut message = data.to_vec();
    message.extend_from_slice(salt);
    let signature = issuer_signing_key().sign(&message);
    BytesN::from_array(env, &signature.to_bytes())
}

#[test]
fn test_verify_valid_proof() {
    let env = Env::default();
    let client = setup(&env);

    let salt_arr = test_salt_array();
    let data_arr = [1u8, 2, 3, 4, 5];

    let salt = Bytes::from_array(&env, &salt_arr);
    let data = Bytes::from_array(&env, &data_arr);
    let signature = sign_proof(&env, &data_arr, &salt_arr);

    let result = client.verify_proof(&signature, &data, &salt);

    assert!(result, "Valid issuer signature should verify successfully");
}

#[test]
#[should_panic]
fn test_verify_invalid_proof() {
    let env = Env::default();
    let client = setup(&env);

    let salt = create_test_salt(&env);
    let mut data = Bytes::new(&env);
    data.extend_from_array(&[1, 2, 3, 4, 5]);

    // An all-zero signature is not a valid issuer signature; ed25519_verify traps.
    let invalid_signature = BytesN::from_array(&env, &[0u8; 64]);

    client.verify_proof(&invalid_signature, &data, &salt);
}

#[test]
#[should_panic]
fn test_verify_proof_forged_for_attacker_data() {
    // Regression test for finding C5: the caller cannot forge a valid proof for
    // arbitrary data because they do not hold the issuer's secret key. A signature
    // produced by a *different* (attacker) key must be rejected.
    let env = Env::default();
    let client = setup(&env);

    let salt_arr = test_salt_array();
    let data_arr = [9u8, 9, 9, 9];
    let salt = Bytes::from_array(&env, &salt_arr);
    let data = Bytes::from_array(&env, &data_arr);

    // Attacker signs with their own key (not the registered issuer key).
    let attacker_key = SigningKey::from_bytes(&[0xAAu8; 32]);
    let mut message = data_arr.to_vec();
    message.extend_from_slice(&salt_arr);
    let forged = attacker_key.sign(&message);
    let forged_sig = BytesN::from_array(&env, &forged.to_bytes());

    client.verify_proof(&forged_sig, &data, &salt);
}

#[test]
#[should_panic]
fn test_verify_proof_with_invalid_salt_length() {
    let env = Env::default();
    let client = setup(&env);

    // Salt that's too short (< 16 bytes); verify_proof traps with InvalidSaltLength.
    let short_salt = Bytes::from_array(&env, &[0u8, 1, 2, 3, 4, 5, 6, 7]);
    let mut data = Bytes::new(&env);
    data.extend_from_array(&[1, 2, 3, 4, 5]);

    // Even a syntactically well-formed signature can't pass the length precondition.
    let signature = BytesN::from_array(&env, &[0u8; 64]);

    client.verify_proof(&signature, &data, &short_salt);
}

#[test]
#[should_panic]
fn test_verify_proof_without_issuer_set() {
    // If the issuer key was never configured, verification traps (IssuerNotSet).
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(ZkpVerifier, ());
    let client = ZkpVerifierClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    // NOTE: set_issuer intentionally NOT called.

    let salt_arr = test_salt_array();
    let data_arr = [1u8, 2, 3];
    let salt = Bytes::from_array(&env, &salt_arr);
    let data = Bytes::from_array(&env, &data_arr);
    let signature = sign_proof(&env, &data_arr, &salt_arr);

    client.verify_proof(&signature, &data, &salt);
}

#[test]
#[should_panic]
fn test_initialize_twice_traps() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(ZkpVerifier, ());
    let client = ZkpVerifierClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    // Second initialize must trap with AlreadyInitialized.
    client.initialize(&admin);
}

#[test]
fn test_issuer_and_admin_getters() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(ZkpVerifier, ());
    let client = ZkpVerifierClient::new(&env, &contract_id);

    assert!(client.get_admin().is_none(), "admin unset before init");
    assert!(client.get_issuer().is_none(), "issuer unset before init");

    let admin = Address::generate(&env);
    client.initialize(&admin);
    assert_eq!(client.get_admin(), Some(admin), "admin recorded on init");

    let pk = issuer_public_key(&env);
    client.set_issuer(&pk);
    assert_eq!(client.get_issuer(), Some(pk), "issuer recorded on set_issuer");
}

#[test]
fn test_verify_balance_proof() {
    let env = Env::default();
    let client = setup(&env);

    let salt_arr = test_salt_array();
    let balance_arr = b"1000.0";
    let required_arr = b"500.0";

    let salt = Bytes::from_array(&env, &salt_arr);
    let balance_data = Bytes::from_slice(&env, balance_arr);
    let required_data = Bytes::from_slice(&env, required_arr);

    let signature = sign_proof(&env, balance_arr, &salt_arr);

    let result = client.verify_balance_proof(&signature, &balance_data, &required_data, &salt);

    assert!(result, "Valid balance proof with sufficient balance should verify");
}

#[test]
fn test_verify_balance_proof_insufficient() {
    let env = Env::default();
    let client = setup(&env);

    let salt_arr = test_salt_array();
    let balance_arr = b"99.0";
    let required_arr = b"100.0";

    let salt = Bytes::from_array(&env, &salt_arr);
    let balance_data = Bytes::from_slice(&env, balance_arr);
    let required_data = Bytes::from_slice(&env, required_arr);

    // Signature is valid; only the logical balance check should fail (returns false, no trap).
    let signature = sign_proof(&env, balance_arr, &salt_arr);

    let result = client.verify_balance_proof(&signature, &balance_data, &required_data, &salt);

    assert!(!result, "Balance proof should fail when balance < required");
}

#[test]
fn test_verify_balance_proof_malformed_input() {
    let env = Env::default();
    let client = setup(&env);

    let salt_arr = test_salt_array();
    let salt = Bytes::from_array(&env, &salt_arr);
    let required_data = Bytes::from_slice(&env, b"100.0");

    // "-" is a syntactically signed but numerically malformed balance: the signature
    // verifies, but parse_decimal_to_scaled returns None, so the result is false.
    let dash_arr = b"-";
    let signature = sign_proof(&env, dash_arr, &salt_arr);
    let malformed_balance = Bytes::from_slice(&env, dash_arr);
    let result = client.verify_balance_proof(&signature, &malformed_balance, &required_data, &salt);
    assert!(!result, "Malformed balance '-' should fail verification");

    // Just a decimal point "." — same expectation.
    let dot_arr = b".";
    let signature2 = sign_proof(&env, dot_arr, &salt_arr);
    let dot_only = Bytes::from_slice(&env, dot_arr);
    let result2 = client.verify_balance_proof(&signature2, &dot_only, &required_data, &salt);
    assert!(!result2, "Malformed balance '.' should fail verification");
}

#[test]
fn test_batch_verification_all_valid() {
    let env = Env::default();
    let client = setup(&env);

    let mut signatures = Vec::new(&env);
    let mut data_items = Vec::new(&env);
    let mut salts = Vec::new(&env);

    let salt_arr = test_salt_array();
    for i in 0..3u8 {
        let data_arr = [i, i + 1, i + 2];
        signatures.push_back(sign_proof(&env, &data_arr, &salt_arr));
        data_items.push_back(Bytes::from_array(&env, &data_arr));
        salts.push_back(Bytes::from_array(&env, &salt_arr));
    }

    let result = client.verify_batch(&signatures, &data_items, &salts);

    assert!(result, "All valid proofs should pass batch verification");
}

#[test]
#[should_panic]
fn test_batch_verification_one_invalid() {
    let env = Env::default();
    let client = setup(&env);

    let mut signatures = Vec::new(&env);
    let mut data_items = Vec::new(&env);
    let mut salts = Vec::new(&env);

    let salt_arr = test_salt_array();

    // First proof - valid.
    let data1 = [1u8, 2, 3];
    signatures.push_back(sign_proof(&env, &data1, &salt_arr));
    data_items.push_back(Bytes::from_array(&env, &data1));
    salts.push_back(Bytes::from_array(&env, &salt_arr));

    // Second proof - INVALID (all-zero signature). Batch must trap on it.
    let data2 = [4u8, 5, 6];
    signatures.push_back(BytesN::from_array(&env, &[0u8; 64]));
    data_items.push_back(Bytes::from_array(&env, &data2));
    salts.push_back(Bytes::from_array(&env, &salt_arr));

    client.verify_batch(&signatures, &data_items, &salts);
}

#[test]
#[should_panic]
fn test_batch_verification_length_mismatch() {
    let env = Env::default();
    let client = setup(&env);

    let salt_arr = test_salt_array();
    let data1 = [1u8, 2, 3];

    let mut signatures = Vec::new(&env);
    signatures.push_back(sign_proof(&env, &data1, &salt_arr));

    let mut data_items = Vec::new(&env);
    data_items.push_back(Bytes::from_array(&env, &data1));

    // salts is empty -> length mismatch -> traps with InvalidInput.
    let salts: Vec<Bytes> = Vec::new(&env);

    client.verify_batch(&signatures, &data_items, &salts);
}

#[test]
fn test_error_codes_are_distinct() {
    // Sanity check that the error discriminants are stable / distinct.
    assert_eq!(VerificationError::InvalidProof as u32, 1);
    assert_eq!(VerificationError::InvalidSaltLength as u32, 4);
    assert_eq!(VerificationError::AlreadyInitialized as u32, 7);
    assert_eq!(VerificationError::IssuerNotSet as u32, 9);
}
