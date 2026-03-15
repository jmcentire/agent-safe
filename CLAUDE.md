# Agent-Safe

Authorization policy language for AI agents. SPL evaluates in ~2μs with zero runtime dependencies. Six SDK implementations with Ed25519 signing, Merkle proofs, and hash-chain offline budgets.

## Quick Reference

```bash
# TypeScript
cd sdk/js && npm run build && npm test

# Go
cd sdk/go && go test ./spl/ -v

# Python
cd sdk/python && pytest tests/ -v

# Rust
cd sdk/rust && cargo test

# Java
cd sdk/java && mvn test -B

# C#
cd sdk/csharp && dotnet test
```

## Architecture

### SPL (Safe Policy Language) v0.1
Declarative policy language with 20 built-in operators (logical, comparison, set, access, time, crypto predicates).

```
allow action == "purchase" and amount <= sealed.budget and expires > now()
```

### Token Shape
```json
{
  "policy": "allow action == \"purchase\" and amount <= 100",
  "sealed": { "budget": 100, "merchant": "shop.example.com" },
  "expires": "2026-04-01T00:00:00Z",
  "signature": "<ed25519-over-full-envelope>",
  "merkle_root": "<sha256>",
  "hash_chain_commitment": "<sha256>",
  "pop_key": "<ed25519-pubkey>"
}
```

### Crypto Stack
| Feature | Algorithm | Purpose |
|---------|-----------|---------|
| Signing | Ed25519 | Token integrity + authority |
| Merkle proofs | SHA-256 | Selective attribute disclosure |
| Offline budgets | SHA-256 hash chain | Decrementable without server |
| Key derivation | HKDF-SHA-256 | Deterministic child keys |
| Agent binding | PoP (Proof-of-Possession) | Bind token to agent key |

### Safety Limits
- Gas: 10,000 ops max (instruction metering)
- Depth: 64 max (nested expressions)
- Policy size: 64 KB max
- Parse + eval: ~11-15 μs (M1)
- Eval only: ~2 μs

## Structure

```
sdk/
  js/         # TypeScript (agent-safe-spl@0.2.0, zero deps)
  go/         # Go 1.22 (stdlib only)
  python/     # Python 3.10+ (zero core deps, optional: cryptography)
  rust/       # Rust 2021 (ed25519-dalek, sha2, serde)
  java/       # JDK 21+ (JUnit 5)
  csharp/     # .NET 10+ (xUnit)
examples/
  policies/   # Reference SPL policies
  requests/   # Sample request JSON
  crypto/     # Shared cross-SDK test vectors
  e2e/        # Full lifecycle examples
cli/js/       # TypeScript CLI for local verification
docs/         # GitHub Pages landing page
```

## Privacy Stack

| Project | Purpose |
|---------|---------|
| Signet | Cryptographic vault, ZK proofs, Ed25519 root |
| Agent-Safe | Authorization policy in tokens (~2 μs eval) |
| Tessera | Self-validating documents |
| BlindDB | Client-side encryption, opaque storage |
| HermesP2P | Ephemeral P2P messaging |

## Conventions

- Zero runtime dependencies in core evaluators (JS, Go, Python)
- All 6 SDKs share test vectors in examples/crypto/
- Full-envelope signing (policy + sealed + expires + merkle_root + hash_chain_commitment)
- Fail closed on all crypto operations
- Strict symbol resolution mode
- CI: GitHub Actions (all SDKs tested, CodeQL SAST, OpenSSF Scorecard)
- Publish: npm (provenance), PyPI (OIDC), crates.io on GitHub release
- SPEC.md is authoritative — SDKs implement, never extend

## Kindex

Agent-Safe captures discoveries, decisions, and security rationale in [Kindex](~/Code/kindex). Search before adding. Link related concepts.
