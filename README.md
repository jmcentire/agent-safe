# Agent-Safe: Portable Capability Tokens for AI Agents

Durable, signed capability tokens carrying deterministic policy for AI agent authorization. One function call, microsecond evaluation, offline-verifiable.

## What This Is

Agent-Safe defines **SPL (Safe Policy Lisp)**, a tiny S-expression policy language embedded in signed capability tokens. A verifier calls one function — `verifySPL(request, token, proofs)` — and gets a deterministic yes or no.

SPL is:
- **Total** — every policy terminates (no loops, no recursion, gas-metered)
- **Deterministic** — same inputs, same output (no I/O, no randomness)
- **Portable** — single-file implementations in 6 languages
- **LLM-friendly** — S-expression syntax is unambiguous and easy for language models to generate

## Why Not [Existing System]?

| System | What It Does | How SPL Differs |
|--------|-------------|-----------------|
| **Macaroons** (Google) | Contextual caveats via HMAC chains | No embedded policy language; caveats are opaque conditions |
| **Biscuit** (Eclipse) | Datalog in signed tokens | SPL is simpler: no negation, no unification, total by construction |
| **Cedar** (AWS) | Full policy engine | Not designed for embedding in portable tokens |
| **OPA/Rego** | Server-side policy evaluation | Requires a policy server; not portable or offline-verifiable |
| **SPIFFE/SPIRE** | Workload identity | Identity framework, not authorization policy |

SPL's bet: for AI agent authorization, you want the simplest possible language that is provably total, fits in a signed token, and evaluates in microseconds. Anything more complex belongs in the policy server that *mints* the token, not in the token itself.

## Architecture

```
Agent ──(capability + proofs + DPoP)──> Service
       <──(allow / deny / lease)────────
```

A **capability token** is a signed envelope containing:
- Canonical SPL policy bytes
- Merkle root for fine-grained tuple membership
- Revocation ID and expiration
- Proof-of-possession binding (DPoP/mTLS)

The **verifier** validates the signature, evaluates the SPL policy against the request, checks cryptographic proofs, and returns a boolean.

## Repo Layout

```
SPEC.md         — SPL v0.1 language specification
HOWTO.md        — deployment guide
examples/       — sample policy, request, and crypto test vectors
sdk/js/         — TypeScript SDK (parser, evaluator, verifier, crypto)
sdk/go/         — Go SDK (parser, evaluator, verifier, crypto)
sdk/python/     — Python SDK (parser, evaluator, verifier, crypto)
sdk/rust/       — Rust SDK (parser, evaluator, verifier, crypto)
sdk/java/       — Java SDK (parser, evaluator, verifier, crypto)
sdk/csharp/     — C# SDK (parser, evaluator, verifier, crypto)
docs/           — Landing page (GitHub Pages)
cli/js/         — CLI wrapper for quick local evaluation
```

## Quickstart

### TypeScript
```bash
cd sdk/js && npm i && npm run build
node dist/index.js ../../examples/policies/family_gifts.spl ../../examples/requests/gift_50_niece.json
# → ALLOW
```

### Go
```bash
cd sdk/go
go run ./verify ../../examples/policies/family_gifts.spl ../../examples/requests/gift_50_niece.json
# → ALLOW
```

### Python
```bash
cd sdk/python && pip install -e .
python -m spl ../../examples/policies/family_gifts.spl ../../examples/requests/gift_50_niece.json
# → ALLOW
```

### Rust
```bash
cd sdk/rust
cargo run --example verify -- ../../examples/policies/family_gifts.spl ../../examples/requests/gift_50_niece.json
# → ALLOW
```

### Java
```bash
cd sdk/java && mvn test
```

### C#
```bash
cd sdk/csharp && dotnet test
```

### Tests
```bash
cd sdk/js     && npm test          # 40 tests (parser, eval, gas, crypto, integration)
cd sdk/go     && go test ./spl/    # parser, eval, gas, crypto, integration
cd sdk/python && pytest tests/ -v  # 45 tests
cd sdk/rust   && cargo test        # parser, eval, gas, crypto, integration
cd sdk/java   && mvn test          # JUnit 5
cd sdk/csharp && dotnet test       # xUnit
```

## SPL at a Glance

```lisp
(and
  (= (get req "actor_pub") "K_ai")
  (= (get req "action") "payments.create")
  (<= (get req "amount") 50)
  (member (get req "recipient") allowed_recipients)
  (before now "2025-12-31T00:00:00Z")
  (dpop_ok?)
)
```

Built-ins: `and`, `or`, `not`, `=`, `<`, `<=`, `>`, `>=`, `member`, `in`, `subset?`, `before`, `get`, `tuple`, `per-day-count`, plus crypto predicates (`dpop_ok?`, `merkle_ok?`, `vrf_ok?`, `thresh_ok?`).

See [SPEC.md](SPEC.md) for the full language specification. See [HOWTO.md](HOWTO.md) for deployment patterns.

## Crypto

The SDKs include real cryptographic verification:

| Operation | Algorithm | Used For |
|-----------|-----------|----------|
| **Ed25519** | RFC 8032 | Token signature verification |
| **Merkle proof** | SHA-256 hash tree | Fine-grained set membership |
| **Hash chain** | Iterated SHA-256 | Offline budget receipts |

Shared test vectors in `examples/crypto/` ensure cross-SDK compatibility. `thresh_ok?` remains an interface stub — provide your own k-of-n co-signature implementation.

### Dependency Budget

| SDK | Runtime Deps | Notes |
|-----|-------------|-------|
| TypeScript | None | `node:crypto` built-in |
| Go | None | stdlib only |
| Python | `cryptography` (optional) | Core has zero deps |
| Rust | `serde`, `serde_json`, `ed25519-dalek`, `sha2` | Standard crates |
| Java | None | JDK 21+ has EdDSA + SHA-256 |
| C# | None | .NET 10+ stdlib; Ed25519 behind `AGENTSAFE_ED25519` guard |

## Security Model

**What SPL provides:**
- Deterministic, auditable authorization decisions
- Offline verification (no round-trip to policy server)
- Fine-grained scope via Merkle tuple membership
- Offline budgets via hash-chain receipts
- Threshold co-signatures for step-up
- Revocable leases for reversible actions

**What SPL does not protect against:**
- Key compromise (mitigated by short TTLs, DPoP binding, revocation)
- Side-channel attacks on the evaluator
- Bugs in the host crypto implementations
- Social engineering of the grantor

The threat model assumes an **honest-but-curious operator**: services follow the protocol but attempt to learn from what they observe. SPL tokens are signed by the grantor; services cannot forge or modify policy.

## Status

Reference implementations with real crypto (Ed25519, Merkle, hash-chain) across 6 SDKs. The evaluators (parser, type system, gas budget) are complete and tested. `thresh_ok?` remains an interface stub — see docstrings for the expected protocol.

---

MIT License.
