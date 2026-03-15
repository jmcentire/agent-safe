# Agent-Safe — Standards of Practice

## Language & Runtime
- 6 SDK implementations must produce identical results
- Zero runtime dependencies in core evaluators
- Minimum language versions: Python 3.10+, Go 1.22+, Rust 2021, JDK 21+, .NET 10+, Node 20+

## Crypto
- Ed25519 for all signing (no RSA, no ECDSA)
- SHA-256 for Merkle proofs and hash chains
- HKDF-SHA-256 (RFC 5869) for key derivation
- Fail closed on all crypto operations (no fallback)
- Full-envelope signing (never sign policy alone)

## Testing
- Shared test vectors in examples/crypto/ (cross-SDK consistency)
- Each SDK has its own test suite using native framework
- CI runs all 6 SDKs on every push

## Security
- SPEC.md is authoritative reference
- Gas metering: max 10k ops per evaluation
- Depth limiting: max 64 nested expressions
- Policy size: max 64 KB
- Strict symbol resolution (no implicit coercion)
- No eval(), no dynamic code generation in evaluators

## Conventions
- Follow each language's idiomatic patterns
- Keep evaluator implementations under ~150 lines
- Document all operators with examples in SPEC.md
