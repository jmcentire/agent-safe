use ed25519_dalek::{Signature, VerifyingKey};
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
