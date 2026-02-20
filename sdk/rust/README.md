# Agent-Safe SPL — Rust SDK

Rust implementation of the SPL (Safe Policy Lisp) evaluator for Agent-Safe capability tokens.

## Usage

Add to your `Cargo.toml`:
```toml
[dependencies]
agent-safe-spl = { path = "." }
```

### Library

```rust
use agent_safe_spl::{parse, verify, Env, Node, CryptoCallbacks};
use std::collections::HashMap;

let ast = parse(r#"(and (= (get req "action") "read") (<= (get req "amount") 100))"#).unwrap();

let mut req = HashMap::new();
req.insert("action".into(), Node::Str("read".into()));
req.insert("amount".into(), Node::Number(50.0));

let env = Env {
    req,
    ..Env::default()
};

let result = verify(&ast, &env).unwrap();
println!("{}", if result.allow { "ALLOW" } else { "DENY" });
```

### CLI Example

```bash
cargo run --example verify -- ../../examples/policies/family_gifts.spl ../../examples/requests/gift_50_niece.json
# → ALLOW
```

## Tests

```bash
cargo test
```

## Dependencies

- `serde`, `serde_json` — JSON parsing
- `ed25519-dalek` — Ed25519 signature verification
- `sha2` — SHA-256 hashing
- `hex` — Hex encoding/decoding
