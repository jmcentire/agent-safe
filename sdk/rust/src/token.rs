use ed25519_dalek::{SigningKey, Signer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::crypto::verify_ed25519;
use crate::evaluator::eval_policy;
use crate::parser::parse;
use crate::types::{CryptoCallbacks, Env, Node, SplError};

/// A signed Agent-Safe capability token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub version: String,
    pub policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_chain_commitment: Option<String>,
    pub sealed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    pub public_key: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pop_key: Option<String>,
}

/// Options for minting a token.
#[derive(Default)]
pub struct MintOptions {
    pub merkle_root: Option<String>,
    pub hash_chain_commitment: Option<String>,
    pub sealed: bool,
    pub expires: Option<String>,
    pub pop_key: Option<String>,
}

/// Generate an Ed25519 keypair.
/// Returns (public_key_hex, private_key_hex).
pub fn generate_keypair() -> (String, String) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS RNG failed");
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    (
        hex::encode(verifying_key.as_bytes()),
        hex::encode(signing_key.as_bytes()),
    )
}

/// Build the canonical signing payload for a token.
/// Covers all security-relevant fields so sealed, expires, merkle_root, and
/// hash_chain_commitment cannot be tampered with after signing.
pub fn signing_payload(
    policy: &str,
    merkle_root: &Option<String>,
    hash_chain_commitment: &Option<String>,
    sealed: bool,
    expires: &Option<String>,
) -> Vec<u8> {
    let parts = [
        policy.trim(),
        merkle_root.as_deref().unwrap_or(""),
        hash_chain_commitment.as_deref().unwrap_or(""),
        if sealed { "1" } else { "0" },
        expires.as_deref().unwrap_or(""),
    ];
    parts.join("\0").into_bytes()
}

/// Mint a signed capability token.
pub fn mint(policy: &str, private_key_hex: &str, opts: MintOptions) -> Result<Token, SplError> {
    let seed_bytes = hex::decode(private_key_hex)
        .map_err(|e| SplError(format!("invalid private key hex: {e}")))?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| SplError("private key must be 32 bytes".to_string()))?;

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let payload = signing_payload(
        policy, &opts.merkle_root, &opts.hash_chain_commitment, opts.sealed, &opts.expires,
    );
    let signature = signing_key.sign(&payload);

    Ok(Token {
        version: "0.1.0".to_string(),
        policy: policy.trim().to_string(),
        merkle_root: opts.merkle_root,
        hash_chain_commitment: opts.hash_chain_commitment,
        sealed: opts.sealed,
        expires: opts.expires,
        public_key: hex::encode(verifying_key.as_bytes()),
        signature: hex::encode(signature.to_bytes()),
        pop_key: opts.pop_key,
    })
}

/// Create a PoP presentation signature for a token.
/// The agent signs SHA-256(signing_payload) with its own Ed25519 key.
pub fn create_presentation_signature(
    token: &Token,
    agent_private_key_hex: &str,
) -> Result<String, SplError> {
    let seed_bytes = hex::decode(agent_private_key_hex)
        .map_err(|e| SplError(format!("invalid agent private key hex: {e}")))?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| SplError("agent private key must be 32 bytes".to_string()))?;

    let signing_key = SigningKey::from_bytes(&seed);
    let payload = signing_payload(
        &token.policy, &token.merkle_root, &token.hash_chain_commitment,
        token.sealed, &token.expires,
    );
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let pop_payload = hasher.finalize();

    let sig = signing_key.sign(&pop_payload);
    Ok(hex::encode(sig.to_bytes()))
}

/// Result of token verification.
pub struct VerifyTokenResult {
    pub allow: bool,
    pub sealed: bool,
    pub error: Option<String>,
}

/// Verify a token's signature and evaluate its policy.
pub fn verify_token(
    token: &Token,
    req: HashMap<String, Node>,
    vars: HashMap<String, Node>,
) -> VerifyTokenResult {
    verify_token_with_pop(token, req, vars, None)
}

/// Verify a token with optional PoP presentation signature.
pub fn verify_token_with_pop(
    token: &Token,
    req: HashMap<String, Node>,
    vars: HashMap<String, Node>,
    presentation_signature: Option<&str>,
) -> VerifyTokenResult {
    // Verify signature over full token envelope
    let payload = signing_payload(
        &token.policy, &token.merkle_root, &token.hash_chain_commitment,
        token.sealed, &token.expires,
    );
    if !verify_ed25519(
        &payload,
        &token.signature,
        &token.public_key,
    ) {
        return VerifyTokenResult {
            allow: false,
            sealed: token.sealed,
            error: Some("invalid signature".to_string()),
        };
    }

    // PoP binding: if token has pop_key, require and verify presentation signature
    if let Some(pop_key) = &token.pop_key {
        match presentation_signature {
            None => {
                return VerifyTokenResult {
                    allow: false,
                    sealed: token.sealed,
                    error: Some("PoP binding requires presentation signature".to_string()),
                };
            }
            Some(pres_sig) => {
                let mut hasher = Sha256::new();
                hasher.update(&payload);
                let pop_payload = hasher.finalize();
                if !verify_ed25519(&pop_payload, pres_sig, pop_key) {
                    return VerifyTokenResult {
                        allow: false,
                        sealed: token.sealed,
                        error: Some("invalid presentation signature".to_string()),
                    };
                }
            }
        }
    }

    // Parse policy
    let ast = match parse(&token.policy) {
        Ok(ast) => ast,
        Err(e) => {
            return VerifyTokenResult {
                allow: false,
                sealed: token.sealed,
                error: Some(format!("parse error: {e}")),
            }
        }
    };

    // Evaluate
    let env = Env {
        req,
        vars,
        per_day_count: Box::new(|_, _| 0),
        crypto: CryptoCallbacks::default(),
        max_gas: 10_000,
        sealed: false,
        strict: false,
    };

    match eval_policy(&ast, &env) {
        Ok(result) => VerifyTokenResult {
            allow: result.is_truthy(),
            sealed: token.sealed,
            error: None,
        },
        Err(e) => VerifyTokenResult {
            allow: false,
            sealed: token.sealed,
            error: Some(e.to_string()),
        },
    }
}
