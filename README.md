# Agent-Safe IAM: Portable, Signed Policy (SPL) for AI Agents

Reference implementation and SDKs for the approach described in the LinkedIn article:
- Durable, portable **capability tokens** carrying a canonical, signed **S-expression policy (SPL)**
- **Merkle set-membership** for fine-grained tuples (actor, action, object, constraints)
- **Offline-verifiable budgets** (VRF / hash-chain) — stubbed here for demo
- **Threshold co-signatures** for step-up — interface stubbed
- **Revocable leases** (pending → settle/cancel) — interface stubbed

> Goal: make it **easy** to integrate: call one function `verifySPL({request, token, proofs, now})` to get a deterministic yes/no.

## Repo layout
- `SPEC.md` — mini-spec for SPL, token shape, and verifier semantics
- `examples/` — sample policy and request
- `sdk/js` — TypeScript verifier (minimal working)
- `sdk/go` — Go verifier (minimal working)
- `sdk/rust` — placeholder
- `sdk/java` — placeholder
- `cli/js` — simple CLI wrapper around the JS verifier

## Quickstart (JS)
```bash
cd sdk/js
npm i
npm run build
node dist/index.js ../../examples/policies/family_gifts.spl ../../examples/requests/gift_50_niece.json
```

Expected output: `ALLOW`

## Quickstart (Go)
```bash
cd sdk/go
go run ./verify ../../examples/policies/family_gifts.spl ../../examples/requests/gift_50_niece.json
```

Expected output: `ALLOW`

## Status
This is a **scaffold** suitable for pilots and discussion. Crypto checks (`merkle_ok?`, `dpop_ok?`, `vrf_ok?`, `thresh_ok?`) are stubbed to always return true with clear TODOs. Replace with real implementations for production.

---

MIT License.
