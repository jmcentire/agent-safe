# Changelog

## [0.2.0] - 2026-02-27

### Added
- **PoP (Proof-of-Possession) binding** — tokens can bind to an agent's Ed25519 key via `pop_key`; verifier requires presentation signature
- **HKDF-SHA-256 key derivation** (RFC 5869) — derive per-service unlinkable keypairs from a master key
- **SECURITY.md** — vulnerability disclosure policy with GitHub private reporting
- **OpenSSF Best Practices badge** — passing level certification
- **CodeQL SAST** — static analysis across all 5 compiled languages
- **Dependabot** — automated dependency updates for all 6 SDKs + GitHub Actions
- **OpenSSF Scorecard** — weekly automated security scoring

### Changed
- **Fail-closed crypto defaults** — all crypto callbacks (`dpop_ok?`, `merkle_ok?`, `vrf_ok?`, `thresh_ok?`) default to `false`
- **Full-envelope signing** — token signature now covers `sealed`, `expires`, `merkle_root`, and `hash_chain_commitment` fields
- **Strict symbol resolution** — unresolved symbols raise errors in strict mode instead of passing through
- **Type-aware equality** — `=` operator distinguishes types (string "1" != number 1)
- **Max policy size** — parsers enforce a 64 KB limit on policy source
- **Rust: replaced `rand` with `getrandom`** — avoids `rand_core` version conflict with `ed25519-dalek`
- **CI hardening** — all GitHub Actions SHA-pinned, `permissions: contents: read`, dependency audit steps

### Security
- 249 tests across 6 SDKs (up from 234)
- Cross-SDK HKDF parity verified — all SDKs produce identical keys for same inputs

## [0.1.0] - 2026-02-20

Initial release.

### Added
- **SPL v0.1 specification** — total, deterministic S-expression policy language
- **6 SDK implementations** — TypeScript, Go, Python, Rust, Java, C#
- **Token minting API** — `mint()` and `verifyToken()` with Ed25519 signing
- **Real crypto** — Ed25519 signature verification, SHA-256 Merkle proofs, hash-chain offline budgets
- **Token sealing** — sealed tokens reject further attenuation
- **20 built-in operators** — `and`, `or`, `not`, `=`, `<`, `<=`, `>`, `>=`, `member`, `in`, `subset?`, `before`, `get`, `tuple`, `per-day-count`, `dpop_ok?`, `merkle_ok?`, `vrf_ok?`, `thresh_ok?`
- **234 tests** across 6 SDKs with shared crypto test vectors
- **Benchmarks** — ~2μs eval, ~15μs parse+eval on Apple M1
- **Landing page** with interactive demo at jmcentire.github.io/agent-safe/
- **End-to-end examples** in TypeScript, Go, and Python
- **CI/CD** — GitHub Actions for testing all 6 SDKs, Pages deployment, package publishing
- **Gas metering** (default 10,000 ops) and depth limiting (max 64)
