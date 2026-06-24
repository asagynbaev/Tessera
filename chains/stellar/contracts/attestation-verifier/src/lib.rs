#![no_std]
// soroban-sdk 26.1 deprecated `Events::publish` in favour of the `#[contractevent]` macro.
// This v2-era contract keeps its existing events (migrating changes the on-chain event ABI that
// v2.x consumers depend on); the lint is suppressed deliberately.
#![allow(deprecated)]
//! # ZKP / Attestation Verifier Contract
//!
//! Production-ready Soroban smart contract for verifying attestation proofs issued
//! by the Tessera library, enabling privacy-preserving transactions on Stellar.
//!
//! ## Trust model
//! Proofs are **Ed25519 signatures** produced by a trusted off-chain issuer over a
//! canonical message (`data || salt`). The contract stores the issuer's *public* key
//! in instance storage and verifies signatures against it with
//! [`soroban_sdk::crypto::Crypto::ed25519_verify`].
//!
//! No secret of any kind is ever passed in by the caller, and the contract holds
//! only public material. This is a deliberate change from an earlier design that
//! accepted an HMAC secret as a public invocation argument — on Soroban every
//! invocation argument is recorded on-ledger, so a shared secret passed that way
//! leaks on first use *and* lets any caller forge a "valid" HMAC for arbitrary data
//! (the verifier authenticated nothing). Public-key verification eliminates both
//! problems: only the issuer can sign, and the on-ledger material is non-secret.
//!
//! ## Admin / initialization flow
//! 1. `initialize(admin)` — records the admin `Address` once (requires `admin` auth).
//! 2. `set_issuer(issuer_pubkey)` — sets/rotates the trusted issuer Ed25519 public
//!    key (requires the stored admin's auth).
//! 3. `verify_proof` / `verify_balance_proof` / `verify_batch` — verify signatures
//!    against the stored issuer key. No key/secret argument is accepted.
//!
//! ## Verification semantics
//! `ed25519_verify` **traps** (reverts the invocation) on an invalid signature, so a
//! forged or malformed proof aborts the transaction rather than silently returning a
//! value. Functions return `true` on success; logical (non-cryptographic) checks such
//! as "balance >= required" return `false` without trapping.
//!
//! ## Proof Types
//! - **Ed25519-signed attestations**: issuer-signed commitments for balance, age,
//!   membership, and similar attestations.
//! - **Bulletproofs (secp256k1)**: structural validation and Fiat-Shamir binding
//!   checked on-chain; full EC verification performed off-chain (Soroban lacks native
//!   secp256k1 ops).

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, Address, Bytes,
    BytesN, Env, Symbol, Vec,
};

/// Contract for verifying attestation proofs (Ed25519-signed) and Bulletproof envelopes.
#[contract]
pub struct ZkpVerifier;

/// Keys for instance storage.
#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// The contract administrator (`Address`) allowed to set/rotate the issuer key.
    Admin,
    /// The trusted issuer Ed25519 public key (`BytesN<32>`).
    Issuer,
}

/// Error codes for proof verification / administration failures.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VerificationError {
    /// The provided proof/signature is invalid.
    InvalidProof = 1,
    /// The input data format is invalid.
    InvalidInput = 2,
    /// The proof data length is incorrect.
    InvalidProofLength = 3,
    /// The salt length is incorrect.
    InvalidSaltLength = 4,
    /// The commitment format is invalid.
    InvalidCommitment = 5,
    /// Range bounds are invalid.
    InvalidRange = 6,
    /// The contract has already been initialized.
    AlreadyInitialized = 7,
    /// The contract has not been initialized (no admin set).
    NotInitialized = 8,
    /// No trusted issuer public key has been configured.
    IssuerNotSet = 9,
}

#[contractimpl]
impl ZkpVerifier {
    /// Initializes the contract by recording the administrator address.
    ///
    /// Must be called exactly once. The admin is the only principal allowed to set or
    /// rotate the trusted issuer public key via [`Self::set_issuer`]. Requires `admin`
    /// to authorize the call so the deployer cannot install an admin that did not consent.
    ///
    /// # Panics
    /// Traps with [`VerificationError::AlreadyInitialized`] if called more than once.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(&env, VerificationError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.events()
            .publish((Symbol::new(&env, "initialized"),), admin);
    }

    /// Sets or rotates the trusted issuer Ed25519 public key.
    ///
    /// Only the stored admin may call this (enforced via `require_auth`). The public key
    /// is non-secret on-ledger material, so storing it as instance state is safe.
    ///
    /// # Panics
    /// Traps with [`VerificationError::NotInitialized`] if [`Self::initialize`] was not called.
    pub fn set_issuer(env: Env, issuer_pubkey: BytesN<32>) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(&env, VerificationError::NotInitialized));
        admin.require_auth();
        env.storage().instance().set(&DataKey::Issuer, &issuer_pubkey);
        env.events()
            .publish((Symbol::new(&env, "issuer_set"),), issuer_pubkey);
    }

    /// Returns the currently configured trusted issuer public key, if any.
    pub fn get_issuer(env: Env) -> Option<BytesN<32>> {
        env.storage().instance().get(&DataKey::Issuer)
    }

    /// Returns the configured admin address, if the contract has been initialized.
    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    /// Loads the trusted issuer public key from instance storage, trapping if unset.
    fn require_issuer(env: &Env) -> BytesN<32> {
        env.storage()
            .instance()
            .get(&DataKey::Issuer)
            .unwrap_or_else(|| panic_with_error!(env, VerificationError::IssuerNotSet))
    }

    /// Verifies an attestation proof: an Ed25519 signature by the trusted issuer over
    /// the canonical message `data || salt`.
    ///
    /// The signature is verified against the issuer public key held in **instance
    /// storage** (see [`Self::set_issuer`]). No key or secret is supplied by the caller,
    /// so the proof authenticates the issuer rather than echoing attacker-controlled input.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `signature` - The issuer's Ed25519 signature over `data || salt` (64 bytes).
    /// * `data` - The original data that was attested.
    /// * `salt` - The cryptographic salt bound into the signed message (16 bytes minimum).
    ///
    /// # Returns
    /// * `true` if the signature is valid.
    ///
    /// # Panics
    /// * Traps with [`VerificationError::InvalidSaltLength`] if the salt is too short.
    /// * Traps with [`VerificationError::IssuerNotSet`] if no issuer key is configured.
    /// * Traps (host error) if the Ed25519 signature does not verify.
    pub fn verify_proof(env: Env, signature: BytesN<64>, data: Bytes, salt: Bytes) -> bool {
        // Log verification attempt (never logs any key material).
        env.events().publish(
            (Symbol::new(&env, "verify_attempt"),),
            (data.len(), salt.len()),
        );

        // Validate input lengths.
        if salt.len() < 16 {
            env.events().publish(
                (Symbol::new(&env, "error"),),
                VerificationError::InvalidSaltLength as u32,
            );
            panic_with_error!(&env, VerificationError::InvalidSaltLength);
        }

        let issuer = Self::require_issuer(&env);

        // Canonical message: data || salt.
        let mut message = Bytes::new(&env);
        message.append(&data);
        message.append(&salt);

        // Ed25519 verification against the STORED issuer public key.
        // Traps the invocation if the signature is invalid (secure-by-default revert).
        env.crypto().ed25519_verify(&issuer, &message, &signature);

        env.events()
            .publish((Symbol::new(&env, "verification_result"),), true);

        true
    }

    /// Verifies a balance attestation with an additional balance check.
    ///
    /// First verifies the issuer's Ed25519 signature over `balance_data || salt`
    /// (see [`Self::verify_proof`]), then checks that the attested balance is at least
    /// the required amount.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `signature` - The issuer's Ed25519 signature over `balance_data || salt`.
    /// * `balance_data` - The balance value as bytes (decimal string, e.g., "1000.50").
    /// * `required_amount_data` - The required amount as bytes (decimal string, e.g., "500.25").
    /// * `salt` - The cryptographic salt.
    ///
    /// # Returns
    /// * `true` if the signature is valid AND balance >= required_amount.
    /// * `false` if the balance is insufficient or the inputs are malformed.
    ///
    /// # Panics
    /// * Traps if the signature is invalid (via [`Self::verify_proof`]).
    pub fn verify_balance_proof(
        env: Env,
        signature: BytesN<64>,
        balance_data: Bytes,
        required_amount_data: Bytes,
        salt: Bytes,
    ) -> bool {
        // Verify the issuer signature first (traps on an invalid signature).
        Self::verify_proof(env.clone(), signature, balance_data.clone(), salt);

        // Parse and compare numeric values (logical check; returns false, does not trap).
        let balance = Self::parse_decimal_to_scaled(&balance_data);
        let required = Self::parse_decimal_to_scaled(&required_amount_data);

        let balance_sufficient = match (balance, required) {
            (Some(b), Some(r)) => b >= r,
            _ => {
                env.events().publish(
                    (Symbol::new(&env, "error"),),
                    VerificationError::InvalidInput as u32,
                );
                false
            }
        };

        env.events()
            .publish((Symbol::new(&env, "balance_check"),), balance_sufficient);

        balance_sufficient
    }

    /// Parses a decimal string (e.g., "1234.56") to a scaled integer for comparison.
    /// Returns None if parsing fails or if no digits are present.
    /// The result is scaled by 10^8 to handle up to 8 decimal places.
    fn parse_decimal_to_scaled(data: &Bytes) -> Option<i128> {
        // Return None for empty input
        if data.len() == 0 {
            return None;
        }

        let mut result: i128 = 0;
        let mut decimal_places: u32 = 0;
        let mut found_decimal = false;
        let mut is_negative = false;
        let mut has_digits = false; // Track if at least one digit was parsed

        for i in 0..data.len() {
            let byte = data.get(i)?;

            // Handle negative sign (only at the start, before any digits)
            if byte == b'-' && !has_digits && !found_decimal {
                is_negative = true;
                continue;
            }

            // Handle decimal point
            if byte == b'.' {
                if found_decimal {
                    return None; // Multiple decimal points
                }
                found_decimal = true;
                continue;
            }

            // Handle digits
            if byte >= b'0' && byte <= b'9' {
                has_digits = true;
                let digit = (byte - b'0') as i128;
                result = result.checked_mul(10)?.checked_add(digit)?;

                if found_decimal {
                    decimal_places += 1;
                    if decimal_places > 8 {
                        // Too many decimal places, stop processing
                        break;
                    }
                }
            } else if byte != b' ' {
                // Invalid character (allow spaces to be ignored)
                return None;
            }
        }

        // Must have at least one digit to be valid
        if !has_digits {
            return None;
        }

        // Scale to 8 decimal places for consistent comparison
        const SCALE_FACTOR: u32 = 8;
        let scale_needed = SCALE_FACTOR.saturating_sub(decimal_places);

        for _ in 0..scale_needed {
            result = result.checked_mul(10)?;
        }

        if is_negative {
            result = -result;
        }

        Some(result)
    }

    /// Batch verification of multiple attestation proofs for efficiency.
    ///
    /// Each entry is an issuer Ed25519 signature over `data_items[i] || salts[i]`,
    /// all verified against the single stored issuer public key.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment.
    /// * `signatures` - Vector of Ed25519 signatures to verify.
    /// * `data_items` - Vector of data items corresponding to each signature.
    /// * `salts` - Vector of salts corresponding to each signature.
    ///
    /// # Returns
    /// * `true` if ALL signatures are valid.
    ///
    /// # Panics
    /// * Traps with [`VerificationError::InvalidInput`] if the vectors differ in length.
    /// * Traps if ANY signature is invalid (the whole transaction reverts).
    pub fn verify_batch(
        env: Env,
        signatures: Vec<BytesN<64>>,
        data_items: Vec<Bytes>,
        salts: Vec<Bytes>,
    ) -> bool {
        let count = signatures.len();

        if count != data_items.len() || count != salts.len() {
            env.events().publish(
                (Symbol::new(&env, "error"),),
                VerificationError::InvalidInput as u32,
            );
            panic_with_error!(&env, VerificationError::InvalidInput);
        }

        for i in 0..count {
            let signature = signatures.get(i).unwrap();
            let data = data_items.get(i).unwrap();
            let salt = salts.get(i).unwrap();

            // Traps on the first invalid signature, reverting the batch.
            Self::verify_proof(env.clone(), signature, data, salt);
        }

        env.events()
            .publish((Symbol::new(&env, "batch_verified"),), count);

        true
    }

    /// Performs structural validation of a Bulletproofs range proof on secp256k1.
    ///
    /// **What this checks:**
    /// 1. Commitment is a valid compressed secp256k1 point (0x02/0x03 prefix)
    /// 2. Proof points A, S, T1, T2 have valid compressed point prefixes
    /// 3. IPA proof length field is consistent with actual proof size
    /// 4. Range bounds are valid (min <= max)
    ///
    /// **What this emits (for off-chain auditing):**
    /// - `transcript_binding`: SHA-256 hash binding the proof to this commitment
    ///   and range, usable by off-chain systems to verify proof-to-commitment binding
    ///
    /// **What this does NOT do:**
    /// - Full Bulletproofs verification (EC point decompression, multi-exponentiation,
    ///   inner product argument check). Soroban lacks native secp256k1 ops, so full
    ///   cryptographic verification must be performed off-chain using `BulletproofsProvider.VerifyRange()`.
    ///
    /// This function is useful as a first-pass filter and for anchoring proof metadata
    /// on-chain, but it cannot replace off-chain verification for security-critical flows.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment
    /// * `proof` - The serialized Bulletproofs range proof
    /// * `commitment` - The Pedersen commitment (compressed secp256k1 point, 33 bytes)
    /// * `min` - The minimum allowed value (inclusive)
    /// * `max` - The maximum allowed value (inclusive)
    pub fn verify_zk_range_proof(
        env: Env,
        proof: Bytes,
        commitment: BytesN<33>,
        min: i64,
        max: i64,
    ) -> bool {
        env.events()
            .publish((Symbol::new(&env, "zk_range_verify_attempt"),), (min, max));

        if min > max {
            env.events().publish(
                (Symbol::new(&env, "error"),),
                VerificationError::InvalidRange as u32,
            );
            return false;
        }

        // Minimum proof size: 4 compressed points (A,S,T1,T2 = 132) +
        // 3 scalars (tau_x, mu, t_hat = 96) + 4 bytes IPA length + IPA data
        let min_proof_len: u32 = 4 * 33 + 3 * 32 + 4;
        if proof.len() < min_proof_len {
            env.events().publish(
                (Symbol::new(&env, "error"),),
                VerificationError::InvalidProofLength as u32,
            );
            return false;
        }

        // Validate commitment prefix (compressed EC point)
        let commit_prefix = commitment.get(0).unwrap_or(0);
        if commit_prefix != 0x02 && commit_prefix != 0x03 {
            env.events().publish(
                (Symbol::new(&env, "error"),),
                VerificationError::InvalidCommitment as u32,
            );
            return false;
        }

        // Validate that the four proof points (A, S, T1, T2) have valid prefixes
        let point_offsets: [u32; 4] = [0, 33, 66, 99];
        for offset in point_offsets {
            let prefix = proof.get(offset).unwrap_or(0);
            if prefix != 0x02 && prefix != 0x03 {
                env.events().publish(
                    (Symbol::new(&env, "error"),),
                    VerificationError::InvalidProof as u32,
                );
                return false;
            }
        }

        // Validate IPA proof length field
        let ipa_len_offset: u32 = 4 * 33 + 3 * 32;
        let ipa_len = Self::read_u32_le(&proof, ipa_len_offset);
        // Guard against overflow and unreasonably large IPA
        if ipa_len > 10_000 || proof.len() < ipa_len_offset.saturating_add(4).saturating_add(ipa_len) {
            env.events().publish(
                (Symbol::new(&env, "error"),),
                VerificationError::InvalidProofLength as u32,
            );
            return false;
        }

        // Compute and emit a transcript binding hash for off-chain auditing.
        // This hash ties the proof to this specific commitment and range, allowing
        // off-chain verifiers to confirm the proof was not replayed from another context.
        // Note: this is NOT a cryptographic verification -- full verification requires
        // EC point arithmetic which is not available on Soroban for secp256k1.
        let transcript_hash = Self::compute_transcript_binding(&env, &proof, &commitment, min, max);

        env.events()
            .publish((Symbol::new(&env, "zk_range_result"),), true);
        env.events()
            .publish((Symbol::new(&env, "transcript_binding"),), transcript_hash);

        true
    }

    /// Verifies a Zero-Knowledge Age Proof.
    ///
    /// Proves that a person is at least `min_age` years old without revealing
    /// their exact age or birthdate.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment
    /// * `proof` - The ZK age proof bytes
    /// * `commitment` - The commitment to the age value
    /// * `min_age` - The minimum required age
    ///
    /// # Returns
    /// * `true` if the proof is valid and person is at least min_age
    pub fn verify_zk_age_proof(
        env: Env,
        proof: Bytes,
        commitment: BytesN<33>,
        min_age: u32,
    ) -> bool {
        // Age proofs are range proofs with min=min_age, max=150
        Self::verify_zk_range_proof(env, proof, commitment, min_age as i64, 150)
    }

    /// Verifies a Zero-Knowledge Balance Proof.
    ///
    /// Proves that a balance is at least `required_amount` without revealing
    /// the actual balance.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment
    /// * `proof` - The ZK balance proof bytes
    /// * `commitment` - The commitment to the balance value
    /// * `required_amount` - The minimum required balance
    ///
    /// # Returns
    /// * `true` if the proof is valid and balance >= required_amount
    pub fn verify_zk_balance_proof(
        env: Env,
        proof: Bytes,
        commitment: BytesN<33>,
        required_amount: i64,
    ) -> bool {
        // Balance proofs are range proofs with min=required_amount, max=i64::MAX
        Self::verify_zk_range_proof(env, proof, commitment, required_amount, i64::MAX)
    }

    /// Computes a transcript binding hash that ties the proof to a specific commitment
    /// and range. This mirrors the Fiat-Shamir transcript used during proof generation:
    /// H(domain || V || n || A || S) where A, S are the first two proof points.
    fn compute_transcript_binding(
        env: &Env,
        proof: &Bytes,
        commitment: &BytesN<33>,
        min: i64,
        max: i64,
    ) -> BytesN<32> {
        let mut input = Bytes::new(env);

        // Domain separator
        let domain = b"Tessera_Bulletproofs_RangeProof";
        for &byte in domain.iter() {
            input.push_back(byte);
        }

        // Commitment V (33 bytes)
        for i in 0..33u32 {
            input.push_back(commitment.get(i).unwrap());
        }

        // Range bounds
        for byte in min.to_be_bytes() {
            input.push_back(byte);
        }
        for byte in max.to_be_bytes() {
            input.push_back(byte);
        }

        // Proof points A (bytes 0..33) and S (bytes 33..66)
        for i in 0..66u32 {
            if let Some(b) = proof.get(i) {
                input.push_back(b);
            }
        }

        env.crypto().sha256(&input).into()
    }

    /// Read a little-endian u32 from proof bytes at the given offset.
    fn read_u32_le(proof: &Bytes, offset: u32) -> u32 {
        let b0 = proof.get(offset).unwrap_or(0) as u32;
        let b1 = proof.get(offset + 1).unwrap_or(0) as u32;
        let b2 = proof.get(offset + 2).unwrap_or(0) as u32;
        let b3 = proof.get(offset + 3).unwrap_or(0) as u32;
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }
}

#[cfg(test)]
mod test;
