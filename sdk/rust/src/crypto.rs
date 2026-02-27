use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Verify an Ed25519 signature over a message.
pub fn verify_ed25519(message: &[u8], signature_hex: &str, public_key_hex: &str) -> bool {
    let Ok(sig_bytes) = hex::decode(signature_hex) else { return false };
    let Ok(pub_bytes) = hex::decode(public_key_hex) else { return false };

    let Ok(sig) = Signature::from_slice(&sig_bytes) else { return false };
    let Ok(pub_arr): Result<[u8; 32], _> = pub_bytes.try_into() else { return false };
    let Ok(key) = VerifyingKey::from_bytes(&pub_arr) else { return false };

    key.verify_strict(message, &sig).is_ok()
}

/// SHA-256 hash of data.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// SHA-256 hash of data as hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// A step in a Merkle proof.
pub struct MerkleProofStep {
    pub hash: String,
    pub position: String, // "left" or "right"
}

/// Verify a Merkle proof for leaf_data against root_hex.
pub fn verify_merkle_proof(leaf_data: &str, proof: &[MerkleProofStep], root_hex: &str) -> bool {
    let mut current = sha256(leaf_data.as_bytes());

    for step in proof {
        let Ok(sibling) = hex::decode(&step.hash) else { return false };
        let mut hasher = Sha256::new();
        if step.position == "right" {
            hasher.update(&current);
            hasher.update(&sibling);
        } else {
            hasher.update(&sibling);
            hasher.update(&current);
        }
        current = hasher.finalize().to_vec();
    }

    hex::encode(&current) == root_hex
}

/// HMAC-SHA256 (used internally for HKDF).
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let h = sha256(key);
        key_block[..h.len()].copy_from_slice(&h);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad: Vec<u8> = (0..BLOCK_SIZE).map(|i| 0x36 ^ key_block[i]).collect();
    let mut opad: Vec<u8> = (0..BLOCK_SIZE).map(|i| 0x5c ^ key_block[i]).collect();

    ipad.extend_from_slice(data);
    let inner_hash = sha256(&ipad);
    opad.extend_from_slice(&inner_hash);
    sha256(&opad)
}

/// HKDF-SHA256 (RFC 5869) extract-and-expand. Zero external dependencies.
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    // Extract
    let salt = if salt.is_empty() { vec![0u8; 32] } else { salt.to_vec() };
    let prk = hmac_sha256(&salt, ikm);

    // Expand
    let mut out = Vec::new();
    let mut prev = Vec::new();
    let mut i = 1u8;
    while out.len() < length {
        let mut input = prev.clone();
        input.extend_from_slice(info);
        input.push(i);
        prev = hmac_sha256(&prk, &input);
        out.extend_from_slice(&prev);
        i += 1;
    }
    out.truncate(length);
    out
}

/// Derive a service-specific Ed25519 keypair using HKDF-SHA256.
/// Provides unlinkability: different services see different public keys.
pub fn derive_service_key(master_key_hex: &str, service_domain: &str) -> Result<(String, String), crate::types::SplError> {
    let master_key = hex::decode(master_key_hex)
        .map_err(|e| crate::types::SplError(format!("invalid master key hex: {e}")))?;
    let salt = b"agent-safe-v1";
    let info = service_domain.as_bytes();
    let seed_bytes = hkdf_sha256(&master_key, salt, info, 32);
    let seed: [u8; 32] = seed_bytes.try_into()
        .map_err(|_| crate::types::SplError("HKDF output size mismatch".into()))?;

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    Ok((
        hex::encode(verifying_key.as_bytes()),
        hex::encode(signing_key.as_bytes()),
    ))
}

/// Verify a hash chain receipt.
pub fn verify_hash_chain(
    commitment: &str,
    preimage_hex: &str,
    index: usize,
    chain_length: usize,
) -> bool {
    let Ok(mut current) = hex::decode(preimage_hex) else { return false };
    let steps = chain_length - index;

    for _ in 0..steps {
        current = sha256(&current);
    }

    hex::encode(&current) == commitment
}
