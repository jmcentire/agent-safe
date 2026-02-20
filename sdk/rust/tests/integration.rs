use std::collections::HashMap;
use std::fs;
use std::path::Path;

use agent_safe_spl::types::{CryptoCallbacks, Env, Node};
use agent_safe_spl::parser::parse;
use agent_safe_spl::verifier::verify;
use agent_safe_spl::crypto;

fn make_env() -> Env {
    let mut req = HashMap::new();
    req.insert("actor_pub".into(), Node::Str("K_ai".into()));
    req.insert("action".into(), Node::Str("payments.create".into()));
    req.insert("recipient".into(), Node::Str("niece@example.com".into()));
    req.insert("purpose".into(), Node::Str("giftcard".into()));
    req.insert("amount".into(), Node::Number(50.0));
    req.insert("day".into(), Node::Str("2025-09-29".into()));
    req.insert("device_attested".into(), Node::Bool(true));

    let mut vars = HashMap::new();
    vars.insert(
        "allowed_recipients".into(),
        Node::List(vec![
            Node::Str("niece@example.com".into()),
            Node::Str("mom@example.com".into()),
        ]),
    );
    vars.insert("now".into(), Node::Str("2025-10-01T00:00:00Z".into()));

    Env {
        req,
        vars,
        per_day_count: Box::new(|_, _| 0),
        crypto: CryptoCallbacks::default(),
        max_gas: 10_000,
        sealed: false,
    }
}

fn eval_expr(src: &str, env: Env) -> Result<bool, String> {
    let ast = parse(src).map_err(|e| e.0)?;
    let result = verify(&ast, &env).map_err(|e| e.0)?;
    Ok(result.allow)
}

// --- Parser tests ---

#[test]
fn test_and_true() {
    assert!(eval_expr("(and #t #t #t)", make_env()).unwrap());
}

#[test]
fn test_and_false() {
    assert!(!eval_expr("(and #t #f #t)", make_env()).unwrap());
}

#[test]
fn test_or_true() {
    assert!(eval_expr("(or #f #t #f)", make_env()).unwrap());
}

#[test]
fn test_or_false() {
    assert!(!eval_expr("(or #f #f)", make_env()).unwrap());
}

#[test]
fn test_not() {
    assert!(eval_expr("(not #f)", make_env()).unwrap());
    assert!(!eval_expr("(not #t)", make_env()).unwrap());
}

#[test]
fn test_equal() {
    assert!(eval_expr(r#"(= "hello" "hello")"#, make_env()).unwrap());
    assert!(!eval_expr(r#"(= "hello" "world")"#, make_env()).unwrap());
}

#[test]
fn test_less_equal() {
    assert!(eval_expr("(<= 5 10)", make_env()).unwrap());
    assert!(eval_expr("(<= 10 10)", make_env()).unwrap());
    assert!(!eval_expr("(<= 11 10)", make_env()).unwrap());
}

#[test]
fn test_less_than() {
    assert!(eval_expr("(< 5 10)", make_env()).unwrap());
    assert!(!eval_expr("(< 5 5)", make_env()).unwrap());
}

#[test]
fn test_greater_equal() {
    assert!(eval_expr("(>= 10 10)", make_env()).unwrap());
    assert!(!eval_expr("(>= 9 10)", make_env()).unwrap());
}

#[test]
fn test_greater_than() {
    assert!(eval_expr("(> 10 5)", make_env()).unwrap());
    assert!(!eval_expr("(> 5 5)", make_env()).unwrap());
}

#[test]
fn test_member() {
    assert!(eval_expr(
        r#"(member "niece@example.com" allowed_recipients)"#,
        make_env()
    ).unwrap());
    assert!(!eval_expr(
        r#"(member "stranger@example.com" allowed_recipients)"#,
        make_env()
    ).unwrap());
}

#[test]
fn test_in_alias() {
    assert!(eval_expr(
        r#"(in "mom@example.com" allowed_recipients)"#,
        make_env()
    ).unwrap());
}

#[test]
fn test_subset() {
    let mut env = make_env();
    env.vars.insert(
        "small".into(),
        Node::List(vec![Node::Str("a".into()), Node::Str("b".into())]),
    );
    env.vars.insert(
        "big".into(),
        Node::List(vec![
            Node::Str("a".into()),
            Node::Str("b".into()),
            Node::Str("c".into()),
        ]),
    );
    assert!(eval_expr("(subset? small big)", env).unwrap());
}

#[test]
fn test_before() {
    assert!(eval_expr(
        r#"(before now "2026-01-01T00:00:00Z")"#,
        make_env()
    ).unwrap());
    assert!(!eval_expr(
        r#"(before now "2025-01-01T00:00:00Z")"#,
        make_env()
    ).unwrap());
}

#[test]
fn test_get() {
    assert!(eval_expr(
        r#"(= (get req "actor_pub") "K_ai")"#,
        make_env()
    ).unwrap());
}

#[test]
fn test_crypto_stubs() {
    assert!(eval_expr("(dpop_ok?)", make_env()).unwrap());
    assert!(eval_expr("(thresh_ok?)", make_env()).unwrap());
}

#[test]
fn test_unknown_op() {
    assert!(eval_expr("(bogus 1 2)", make_env()).is_err());
}

#[test]
fn test_gas_budget_exceeded() {
    let mut env = make_env();
    env.max_gas = 3;
    let result = eval_expr("(and #t #t #t #t #t #t #t #t)", env);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("gas budget exceeded"));
}

#[test]
fn test_gas_budget_sufficient() {
    let mut env = make_env();
    env.max_gas = 100;
    assert!(eval_expr("(and #t #t)", env).unwrap());
}

// --- Integration tests ---

#[test]
fn test_family_gifts_allow() {
    let policy_path = Path::new("../../examples/policies/family_gifts.spl");
    if !policy_path.exists() {
        eprintln!("Skipping: example files not found");
        return;
    }
    let policy_src = fs::read_to_string(policy_path).unwrap();
    let ast = parse(policy_src.trim()).unwrap();
    let env = make_env();
    let result = verify(&ast, &env).unwrap();
    assert!(result.allow, "expected ALLOW for gift_50_niece");
}

#[test]
fn test_family_gifts_deny() {
    let policy_path = Path::new("../../examples/policies/family_gifts.spl");
    if !policy_path.exists() {
        eprintln!("Skipping: example files not found");
        return;
    }
    let policy_src = fs::read_to_string(policy_path).unwrap();
    let ast = parse(policy_src.trim()).unwrap();
    let mut env = make_env();
    env.req.insert("amount".into(), Node::Number(100.0));
    let result = verify(&ast, &env).unwrap();
    assert!(!result.allow, "expected DENY for amount=100");
}

// --- Crypto tests ---

#[test]
fn test_ed25519_valid() {
    let vectors_path = Path::new("../../examples/crypto/ed25519_vectors.json");
    if !vectors_path.exists() {
        eprintln!("Skipping: crypto vectors not found");
        return;
    }
    let data: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(vectors_path).unwrap()).unwrap();

    let message = data["message"].as_str().unwrap();
    let sig = data["signature_hex"].as_str().unwrap();
    let pub_key = data["public_key_hex"].as_str().unwrap();

    assert!(crypto::verify_ed25519(message.as_bytes(), sig, pub_key));
}

#[test]
fn test_ed25519_tampered() {
    let vectors_path = Path::new("../../examples/crypto/ed25519_vectors.json");
    if !vectors_path.exists() {
        return;
    }
    let data: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(vectors_path).unwrap()).unwrap();

    let tampered = data["tampered_message"].as_str().unwrap();
    let sig = data["signature_hex"].as_str().unwrap();
    let pub_key = data["public_key_hex"].as_str().unwrap();

    assert!(!crypto::verify_ed25519(tampered.as_bytes(), sig, pub_key));
}

#[test]
fn test_merkle_proof() {
    let vectors_path = Path::new("../../examples/crypto/merkle_vectors.json");
    if !vectors_path.exists() {
        return;
    }
    let data: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(vectors_path).unwrap()).unwrap();
    let root = data["root"].as_str().unwrap();

    for case in data["cases"].as_array().unwrap() {
        let leaf = case["leaf"].as_str().unwrap();
        let expected = case["expected"].as_bool().unwrap();
        let proof: Vec<crypto::MerkleProofStep> = case["proof"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| crypto::MerkleProofStep {
                hash: p["hash"].as_str().unwrap().to_string(),
                position: p["position"].as_str().unwrap().to_string(),
            })
            .collect();

        let result = crypto::verify_merkle_proof(leaf, &proof, root);
        assert_eq!(result, expected, "case: {}", case["name"]);
    }
}

#[test]
fn test_hash_chain() {
    let vectors_path = Path::new("../../examples/crypto/hashchain_vectors.json");
    if !vectors_path.exists() {
        return;
    }
    let data: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(vectors_path).unwrap()).unwrap();
    let commitment = data["commitment"].as_str().unwrap();
    let chain_length = data["chain_length"].as_u64().unwrap() as usize;

    for case in data["cases"].as_array().unwrap() {
        let preimage = case["preimage"].as_str().unwrap();
        let index = case["index"].as_u64().unwrap() as usize;
        let expected = case["expected"].as_bool().unwrap();

        let result = crypto::verify_hash_chain(commitment, preimage, index, chain_length);
        assert_eq!(result, expected, "case: {}", case["name"]);
    }
}
