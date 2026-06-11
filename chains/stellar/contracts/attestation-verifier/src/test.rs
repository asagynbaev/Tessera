#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, Vec};

    /// Helper function to create a test HMAC key (32 bytes)
    fn create_test_key(env: &Env) -> BytesN<32> {
        BytesN::from_array(
            env,
            &[
                0x55, 0x75, 0x43, 0x32, 0xf6, 0x05, 0xd5, 0x14, 0xb1, 0x65, 0x8c, 0x16, 0x2f,
                0x87, 0x86, 0xf7, 0x79, 0xb4, 0x24, 0xa7, 0x4e, 0xf4, 0xa6, 0xd7, 0x42, 0x7d,
                0x26, 0x86, 0x0f, 0x84, 0x5c, 0x77,
            ],
        )
    }

    /// Helper function to create test salt (16 bytes)
    fn create_test_salt(env: &Env) -> Bytes {
        let mut salt = Bytes::new(env);
        for i in 0..16 {
            salt.push_back(i);
        }
        salt
    }

    /// Computes HMAC-SHA256 for testing - matches the contract's compute_hmac implementation.
    /// This is the same algorithm used in the contract to ensure tests match production behavior.
    fn compute_test_hmac(env: &Env, message: &Bytes, key: &BytesN<32>) -> BytesN<32> {
        const IPAD: u8 = 0x36;
        const OPAD: u8 = 0x5c;
        const BLOCK_SIZE: u32 = 64;

        // Create padded key (64 bytes)
        let mut key_padded = Bytes::new(env);
        for i in 0..32 {
            key_padded.push_back(key.get(i).unwrap());
        }
        for _ in 32..BLOCK_SIZE {
            key_padded.push_back(0);
        }

        // Compute inner hash: H((K ⊕ ipad) || m)
        let mut inner_data = Bytes::new(env);
        for i in 0..BLOCK_SIZE {
            inner_data.push_back(key_padded.get(i).unwrap() ^ IPAD);
        }
        inner_data.append(message);
        
        let inner_hash = env.crypto().sha256(&inner_data);

        // Compute outer hash: H((K ⊕ opad) || inner_hash)
        let mut outer_data = Bytes::new(env);
        for i in 0..BLOCK_SIZE {
            outer_data.push_back(key_padded.get(i).unwrap() ^ OPAD);
        }
        outer_data.append(&inner_hash.to_bytes());

        env.crypto().sha256(&outer_data)
    }

    /// Helper to compute expected HMAC proof for test data
    fn compute_expected_proof(env: &Env, data: &Bytes, salt: &Bytes, key: &BytesN<32>) -> BytesN<32> {
        // Concatenate data and salt (same as contract does)
        let mut message = Bytes::new(env);
        message.append(data);
        message.append(salt);
        
        // Compute HMAC-SHA256 (matching contract's algorithm)
        compute_test_hmac(env, &message, key)
    }

    #[test]
    fn test_verify_valid_proof() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(ZkpVerifier, ());
        let client = ZkpVerifierClient::new(&env, &contract_id);

        let key = create_test_key(&env);
        let salt = create_test_salt(&env);
        
        // Create test data
        let mut data = Bytes::new(&env);
        data.extend_from_array(&[1, 2, 3, 4, 5]);

        // Compute proof using HMAC-SHA256 (same algorithm as contract)
        let proof = compute_expected_proof(&env, &data, &salt, &key);

        // Verify the proof
        let result = client.verify_proof(&proof, &data, &salt, &key);

        assert!(result, "Valid proof should be verified successfully");
    }

    #[test]
    fn test_verify_invalid_proof() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(ZkpVerifier, ());
        let client = ZkpVerifierClient::new(&env, &contract_id);

        let key = create_test_key(&env);
        let salt = create_test_salt(&env);
        
        // Create test data
        let mut data = Bytes::new(&env);
        data.extend_from_array(&[1, 2, 3, 4, 5]);

        // Create an incorrect proof (all zeros)
        let invalid_proof = BytesN::from_array(&env, &[0u8; 32]);

        // Verify the proof - should fail
        let result = client.verify_proof(&invalid_proof, &data, &salt, &key);

        assert!(!result, "Invalid proof should fail verification");
    }

    #[test]
    fn test_verify_proof_with_invalid_salt_length() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(ZkpVerifier, ());
        let client = ZkpVerifierClient::new(&env, &contract_id);

        let key = create_test_key(&env);
        
        // Create salt that's too short (< 16 bytes)
        let mut short_salt = Bytes::new(&env);
        for i in 0..8 {
            short_salt.push_back(i);
        }
        
        let mut data = Bytes::new(&env);
        data.extend_from_array(&[1, 2, 3, 4, 5]);

        let proof = BytesN::from_array(&env, &[0u8; 32]);

        // Should fail due to invalid salt length
        let result = client.verify_proof(&proof, &data, &short_salt, &key);

        assert!(!result, "Proof with short salt should fail");
    }

    #[test]
    fn test_verify_balance_proof() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(ZkpVerifier, ());
        let client = ZkpVerifierClient::new(&env, &contract_id);

        let key = create_test_key(&env);
        let salt = create_test_salt(&env);
        
        // Balance data (e.g., "1000.0")
        let mut balance_data = Bytes::new(&env);
        balance_data.extend_from_array(b"1000.0");

        // Required amount (e.g., "500.0")
        let mut required_data = Bytes::new(&env);
        required_data.extend_from_array(b"500.0");

        // Compute proof using HMAC-SHA256
        let proof = compute_expected_proof(&env, &balance_data, &salt, &key);

        // Verify balance proof
        let result = client.verify_balance_proof(
            &proof,
            &balance_data,
            &required_data,
            &salt,
            &key,
        );

        assert!(result, "Valid balance proof should be verified");
    }

    #[test]
    fn test_verify_balance_proof_insufficient() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(ZkpVerifier, ());
        let client = ZkpVerifierClient::new(&env, &contract_id);

        let key = create_test_key(&env);
        let salt = create_test_salt(&env);
        
        // Balance data - smaller than required
        let mut balance_data = Bytes::new(&env);
        balance_data.extend_from_array(b"99.0");

        // Required amount - larger than balance
        let mut required_data = Bytes::new(&env);
        required_data.extend_from_array(b"100.0");

        // Compute valid proof for the balance
        let proof = compute_expected_proof(&env, &balance_data, &salt, &key);

        // Verify balance proof - should fail because balance < required
        let result = client.verify_balance_proof(
            &proof,
            &balance_data,
            &required_data,
            &salt,
            &key,
        );

        assert!(!result, "Balance proof should fail when balance < required");
    }

    #[test]
    fn test_verify_balance_proof_malformed_input() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(ZkpVerifier, ());
        let client = ZkpVerifierClient::new(&env, &contract_id);

        let key = create_test_key(&env);
        let salt = create_test_salt(&env);
        
        // Test with malformed balance data (just "-")
        let mut malformed_balance = Bytes::new(&env);
        malformed_balance.extend_from_array(b"-");

        let mut required_data = Bytes::new(&env);
        required_data.extend_from_array(b"100.0");

        // Compute proof for the malformed data
        let proof = compute_expected_proof(&env, &malformed_balance, &salt, &key);

        // Should fail because "-" is not a valid number
        let result = client.verify_balance_proof(
            &proof,
            &malformed_balance,
            &required_data,
            &salt,
            &key,
        );

        assert!(!result, "Malformed balance '-' should fail verification");

        // Test with just decimal point "."
        let mut dot_only = Bytes::new(&env);
        dot_only.extend_from_array(b".");
        
        let proof2 = compute_expected_proof(&env, &dot_only, &salt, &key);
        
        let result2 = client.verify_balance_proof(
            &proof2,
            &dot_only,
            &required_data,
            &salt,
            &key,
        );

        assert!(!result2, "Malformed balance '.' should fail verification");
    }

    #[test]
    fn test_batch_verification_all_valid() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(ZkpVerifier, ());
        let client = ZkpVerifierClient::new(&env, &contract_id);

        let key = create_test_key(&env);

        // Create 3 valid proofs
        let mut proofs = Vec::new(&env);
        let mut data_items = Vec::new(&env);
        let mut salts = Vec::new(&env);

        for i in 0..3 {
            let salt = create_test_salt(&env);
            
            let mut data = Bytes::new(&env);
            data.extend_from_array(&[i, i + 1, i + 2]);

            // Compute proof using HMAC-SHA256
            let proof = compute_expected_proof(&env, &data, &salt, &key);

            proofs.push_back(proof);
            data_items.push_back(data);
            salts.push_back(salt);
        }

        // Verify batch
        let result = client.verify_batch(&proofs, &data_items, &salts, &key);

        assert!(result, "All valid proofs should pass batch verification");
    }

    #[test]
    fn test_batch_verification_one_invalid() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(ZkpVerifier, ());
        let client = ZkpVerifierClient::new(&env, &contract_id);

        let key = create_test_key(&env);

        let mut proofs = Vec::new(&env);
        let mut data_items = Vec::new(&env);
        let mut salts = Vec::new(&env);

        // First proof - valid (using HMAC-SHA256)
        let salt1 = create_test_salt(&env);
        let mut data1 = Bytes::new(&env);
        data1.extend_from_array(&[1, 2, 3]);
        let proof1 = compute_expected_proof(&env, &data1, &salt1, &key);

        proofs.push_back(proof1);
        data_items.push_back(data1);
        salts.push_back(salt1);

        // Second proof - INVALID (wrong hash, all zeros)
        let salt2 = create_test_salt(&env);
        let mut data2 = Bytes::new(&env);
        data2.extend_from_array(&[4, 5, 6]);
        let invalid_proof = BytesN::from_array(&env, &[0u8; 32]);

        proofs.push_back(invalid_proof);
        data_items.push_back(data2);
        salts.push_back(salt2);

        // Verify batch - should fail due to one invalid proof
        let result = client.verify_batch(&proofs, &data_items, &salts, &key);

        assert!(!result, "Batch with one invalid proof should fail");
    }

    #[test]
    fn test_constant_time_comparison() {
        let env = Env::default();

        // Create two identical hashes
        let hash1 = BytesN::from_array(&env, &[0xAB; 32]);
        let hash2 = BytesN::from_array(&env, &[0xAB; 32]);

        // Should be equal
        assert!(ZkpVerifier::secure_compare(&hash1, &hash2));

        // Create two different hashes
        let hash3 = BytesN::from_array(&env, &[0xAB; 32]);
        let mut different_bytes = [0xAB; 32];
        different_bytes[31] = 0xAC; // Change last byte
        let hash4 = BytesN::from_array(&env, &different_bytes);

        // Should not be equal
        assert!(!ZkpVerifier::secure_compare(&hash3, &hash4));
    }
}