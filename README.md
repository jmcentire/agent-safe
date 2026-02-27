# Agent-Safe

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12052/badge)](https://www.bestpractices.dev/projects/12052)

**Embed authorization in the token. 150 lines. Zero deps. Microseconds.**

Agent-Safe defines **SPL (Safe Policy Lisp)** — a tiny S-expression policy language that travels inside signed capability tokens. A verifier calls one function and gets a deterministic yes or no. No policy server. No round-trip. No dependencies.

```
Parse + eval: ~15 μs    Eval only: ~2 μs    (10-conjunct production policy, Apple M1)
```

## The Problem

Every authorization decision an AI agent makes currently requires a round-trip to a policy server (OPA, Cedar, custom IAM). At agent scale — thousands of micro-decisions per second across thousands of agents — that's a throughput and latency tax on every operation. It's not that the server might be *down*. It's that the server shouldn't be *in the path*.

SPL moves the policy into the token. The service that receives the request can verify it locally, in microseconds, with zero network I/O. The policy server only matters when **minting** the token, not when **verifying** it.

## Why SPL

| Property | What It Means |
|----------|--------------|
| **Total** | Every policy terminates. No loops, no recursion, gas-metered. You cannot DoS a verifier with a pathological policy. |
| **Deterministic** | Same inputs, same output. No I/O, no randomness, no side effects. |
| **Portable** | Single-file implementations in 6 languages. ~150 lines per evaluator. |
| **Local-first** | Policy evaluates where the request arrives. No round-trip to a policy server. |
| **LLM-friendly** | S-expression syntax is unambiguous and easy for language models to generate and parse. |
| **Sealable** | Tokens can be sealed to prevent further attenuation down the delegation chain. |

## Honest Comparison

| System | How It Works | Where SPL Differs |
|--------|-------------|-------------------|
| **Macaroons** | HMAC-chained caveats | No embedded policy language; caveats are opaque. SPL gives you a real expression language with comparisons, set membership, and crypto predicates. |
| **Biscuit** | Datalog in signed tokens | Closest competitor. Biscuit is more mature, has third-party blocks and revocation IDs. SPL is simpler (150 LOC vs thousands), zero deps (no protobuf), and includes hash-chain offline budgets that Biscuit lacks. |
| **Cedar** | Full policy engine (AWS) | Not designed for portable tokens. Policies live on the server, not in the request. |
| **OPA/Rego** | Server-side policy evaluation | Requires a running OPA server. Every authorization check is a network round-trip. |
| **SPIFFE/SPIRE** | Workload identity | Proves "I am service X," not "I am allowed to do Y." Identity, not authorization. |

SPL's positioning: **the SQLite of agent authorization.** You embed it. It's 150 lines. It evaluates in microseconds. When you outgrow it, you'll know.

## SPL at a Glance

```lisp
(and
  (= (get req "action") "payments.create")
  (<= (get req "amount") 50)
  (member (get req "recipient") allowed_recipients)
  (before now "2025-12-31T00:00:00Z")
  (dpop_ok?)
  (merkle_ok? (tuple (get req "actor_pub") (get req "action")
                     (get req "recipient") 50 "giftcard"))
  (vrf_ok? (get req "day") (get req "amount"))
)
```

20 built-ins: `and`, `or`, `not`, `=`, `<`, `<=`, `>`, `>=`, `member`, `in`, `subset?`, `before`, `get`, `tuple`, `per-day-count`, plus crypto predicates (`dpop_ok?`, `merkle_ok?`, `vrf_ok?`, `thresh_ok?`).

## Architecture

```
Grantor ──(signs token)──> Agent ──(carries token + proofs)──> Service
                                                                  │
                                                            verify(token)
                                                                  │
                                                            ALLOW / DENY
```

A **capability token** is a signed envelope containing:
- Canonical SPL policy bytes
- Merkle root for fine-grained tuple membership
- Hash-chain commitment for offline budgets
- DPoP binding for proof-of-possession
- `sealed` flag to prevent further attenuation

The **verifier** validates the signature, evaluates the SPL policy, checks crypto proofs, and returns a boolean. One function call. No server.

## Performance

Benchmarked on Apple M1 Max with the `family_gifts.spl` reference policy (10 conjuncts including crypto predicates):

| Operation | Go | TypeScript (Node 20) |
|-----------|-----|-----------|
| Parse + Eval | **~15 μs** | **~11 μs** |
| Eval only | **~2 μs** | **~2 μs** |
| Allocations (Go) | 446 allocs, 13.6 KB | — |

For comparison, an OPA REST call typically takes 1-5 ms (network + evaluation). SPL is **100-1000x faster** because there is no network in the path.

## Quickstart

### TypeScript
```bash
npm install agent-safe-spl
```
```typescript
import { parseSExpr, evalPolicy } from 'agent-safe-spl';
import { mint, verifyToken, generateKeypair } from 'agent-safe-spl/token';
```

### Go
```bash
go get github.com/jmcentire/agent-safe/sdk/go
```
```go
import "github.com/jmcentire/agent-safe/sdk/go/spl"
token, _ := spl.Mint(policy, privKeyHex, spl.MintOptions{})
result := spl.VerifyToken(tokenJSON, req, spl.VerifyTokenOptions{Vars: vars})
```

### Python
```bash
pip install agent-safe-spl        # core (zero deps)
pip install agent-safe-spl[crypto] # + Ed25519 signing
```
```python
from spl import mint, verify_token, generate_keypair
pub, priv = generate_keypair()
token = mint(policy, priv, expires="2027-01-01T00:00:00Z")
result = verify_token(token, request, vars={"allowed_recipients": [...]})
```

### Rust
```bash
cargo add agent-safe-spl
```

### Java
```bash
cd sdk/java && mvn install   # JDK 21+
```

### C#
```bash
cd sdk/csharp && dotnet build  # .NET 10+
```

See `examples/e2e/` for full mint-verify-attenuate-seal lifecycle examples in TypeScript, Go, and Python.

## Tests

```
TypeScript   40 tests    npm test
Go           41 tests    go test ./spl/ -v
Python       45 tests    pytest tests/ -v
Rust         38 tests    cargo test
Java         35 tests    mvn test -B
C#           35 tests    dotnet test
─────────────────────────────────────
Total       234 tests
```

## Crypto

Real cryptographic verification, not stubs:

| Operation | Algorithm | Purpose |
|-----------|-----------|---------|
| **Token signature** | Ed25519 (RFC 8032) | Verify the grantor signed this policy |
| **Merkle proof** | SHA-256 hash tree | Prove a tuple is in the authorized set |
| **Hash chain** | Iterated SHA-256 | Offline budget receipts (spend without phoning home) |

Shared test vectors in `examples/crypto/` ensure cross-SDK compatibility. `thresh_ok?` remains an interface — provide your own k-of-n co-signature implementation.

### Dependency Budget

| SDK | Runtime Deps | Notes |
|-----|-------------|-------|
| TypeScript | None | `node:crypto` built-in |
| Go | None | stdlib only |
| Python | `cryptography` (optional) | Core evaluator has zero deps |
| Rust | `serde`, `serde_json`, `ed25519-dalek`, `sha2` | Standard crates |
| Java | None | JDK 21+ has EdDSA + SHA-256 |
| C# | None | .NET 10+ stdlib |

## Repo Layout

```
SPEC.md         — SPL v0.1 language specification
HOWTO.md        — Deployment guide
examples/       — Sample policies, requests, crypto test vectors
sdk/js/         — TypeScript SDK
sdk/go/         — Go SDK
sdk/python/     — Python SDK
sdk/rust/       — Rust SDK
sdk/java/       — Java SDK
sdk/csharp/     — C# SDK
docs/           — Landing page (GitHub Pages)
```

## Security Model

**What SPL provides:**
- Deterministic, auditable authorization decisions
- Local-first verification (no round-trip to policy server)
- Fine-grained scope via Merkle tuple membership
- Offline budgets via hash-chain receipts
- Token sealing to prevent further attenuation
- Threshold co-signatures for step-up

**What SPL does not protect against:**
- Key compromise (mitigated by short TTLs, DPoP binding, revocation)
- Side-channel attacks on the evaluator
- Bugs in host crypto implementations
- Social engineering of the grantor

Threat model: **honest-but-curious operator**. Services follow the protocol but attempt to learn from what they observe. SPL tokens are signed by the grantor; services cannot forge or modify policy.

## Links

- [SPEC.md](SPEC.md) — Full language specification
- [HOWTO.md](HOWTO.md) — Deployment patterns
- [Landing page](https://jmcentire.github.io/agent-safe/) — Interactive demo

---

MIT License
