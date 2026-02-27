# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, use GitHub's private vulnerability reporting:

1. Go to https://github.com/jmcentire/agent-safe/security/advisories
2. Click "Report a vulnerability"
3. Fill in the details and submit

You can also email security@kindex.tools.

## What to Expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 7 days
- **Fix or mitigation** within 90 days of confirmed vulnerability
- Credit in the advisory (unless you prefer anonymity)

## Scope

The following are in scope:

- All 6 SDK implementations (TypeScript, Go, Python, Rust, Java, C#)
- The SPL parser and evaluator (gas exhaustion, depth bypass, malformed input)
- Token signing and verification (Ed25519, signing payload construction)
- Cryptographic primitives (Merkle proofs, hash chains, HKDF, PoP binding)
- Cross-SDK inconsistencies that could lead to authorization bypass

The following are out of scope:

- Vulnerabilities in upstream dependencies (report those upstream)
- Denial of service via large but valid policies (bounded by 64 KB limit and gas metering)
- Social engineering
