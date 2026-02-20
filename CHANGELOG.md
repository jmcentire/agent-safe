# Changelog

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
