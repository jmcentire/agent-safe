use ed25519_dalek::{SigningKey, Signer};
use serde::{Deserialize, Serialize};
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
}

/// Options for minting a token.
pub struct MintOptions {
    pub merkle_root: Option<String>,
    pub hash_chain_commitment: Option<String>,
    pub sealed: bool,
    pub expires: Option<String>,
}

impl Default for MintOptions {
    fn default() -> Self {
        Self {
            merkle_root: None,
            hash_chain_commitment: None,
            sealed: false,
            expires: None,
        }
    }
}

/// Generate an Ed25519 keypair.
/// Returns (public_key_hex, private_key_hex).
pub fn generate_keypair() -> (String, String) {
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    (
        hex::encode(verifying_key.as_bytes()),
        hex::encode(signing_key.as_bytes()),
    )
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

    let policy_trimmed = policy.trim();
    let signature = signing_key.sign(policy_trimmed.as_bytes());

    Ok(Token {
        version: "0.1.0".to_string(),
        policy: policy_trimmed.to_string(),
        merkle_root: opts.merkle_root,
        hash_chain_commitment: opts.hash_chain_commitment,
        sealed: opts.sealed,
        expires: opts.expires,
        public_key: hex::encode(verifying_key.as_bytes()),
        signature: hex::encode(signature.to_bytes()),
    })
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
    // Verify signature
    if !verify_ed25519(
        token.policy.as_bytes(),
        &token.signature,
        &token.public_key,
    ) {
        return VerifyTokenResult {
            allow: false,
            sealed: token.sealed,
            error: Some("invalid signature".to_string()),
        };
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
