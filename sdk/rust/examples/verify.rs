use std::collections::HashMap;
use std::env;
use std::fs;
use std::process;

use agent_safe_spl::types::{CryptoCallbacks, Env, Node};
use agent_safe_spl::parser::parse;
use agent_safe_spl::verifier::verify;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: verify <policy.spl> <request.json>");
        process::exit(1);
    }

    let policy_src = fs::read_to_string(&args[1]).unwrap_or_else(|e| {
        eprintln!("Error reading policy: {e}");
        process::exit(1);
    });

    let req_src = fs::read_to_string(&args[2]).unwrap_or_else(|e| {
        eprintln!("Error reading request: {e}");
        process::exit(1);
    });

    let ast = parse(policy_src.trim()).unwrap_or_else(|e| {
        eprintln!("Parse error: {e}");
        process::exit(1);
    });

    let json: serde_json::Value = serde_json::from_str(&req_src).unwrap_or_else(|e| {
        eprintln!("JSON error: {e}");
        process::exit(1);
    });

    let mut req = HashMap::new();
    if let Some(obj) = json.as_object() {
        for (k, v) in obj {
            req.insert(k.clone(), json_to_node(v));
        }
    }

    let mut vars = HashMap::new();
    vars.insert(
        "allowed_recipients".into(),
        Node::List(vec![
            Node::Str("niece@example.com".into()),
            Node::Str("mom@example.com".into()),
        ]),
    );
    vars.insert("now".into(), Node::Str("2025-10-01T00:00:00Z".into()));

    let env = Env {
        req,
        vars,
        per_day_count: Box::new(|_, _| 0),
        crypto: CryptoCallbacks {
            dpop_ok: Box::new(|| true),
            merkle_ok: Box::new(|_| true),
            vrf_ok: Box::new(|_, _| true),
            thresh_ok: Box::new(|| true),
        },
        max_gas: 10_000,
        sealed: false,
        strict: false,
    };

    match verify(&ast, &env) {
        Ok(result) => println!("{}", if result.allow { "ALLOW" } else { "DENY" }),
        Err(e) => {
            eprintln!("Evaluation error: {e}");
            process::exit(1);
        }
    }
}

fn json_to_node(v: &serde_json::Value) -> Node {
    match v {
        serde_json::Value::Bool(b) => Node::Bool(*b),
        serde_json::Value::Number(n) => Node::Number(n.as_f64().unwrap_or(0.0)),
        serde_json::Value::String(s) => Node::Str(s.clone()),
        serde_json::Value::Array(arr) => Node::List(arr.iter().map(json_to_node).collect()),
        serde_json::Value::Null => Node::Nil,
        serde_json::Value::Object(_) => Node::Nil,
    }
}
