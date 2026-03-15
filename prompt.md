# Agent-Safe — System Context

## What It Is
Authorization policy language for AI agents. SPL evaluates in ~2us with zero runtime dependencies. Six SDK implementations with Ed25519 signing, Merkle proofs, and hash-chain offline budgets.

## How It Works
Grantor creates signed token with SPL policy -> Agent receives token -> Agent evaluates policy locally (~2us) -> Allow or deny.

## Key Constraints
- Cross-SDK consistency (C001): all 6 must agree
- Fail closed crypto (C002): reject, never accept silently
- Gas metering (C003): max 10k ops
- Full envelope signing (C006): no partial signatures
- Zero runtime deps (C007): embeddable everywhere
- No eval/codegen (C008): no injection vectors
- SPEC.md authoritative (C010): SDKs implement, never extend

## Architecture
5 logical components replicated across 6 languages: evaluator, parser, crypto, token, CLI verifier.

## Part of Privacy Stack
Signet (vault) -> Agent-Safe (authorization) -> Tessera (documents) -> BlindDB (storage) -> HermesP2P (messaging)

## Done Checklist
- [ ] All 6 SDKs pass shared test vectors
- [ ] Crypto fails closed on all invalid inputs
- [ ] Gas metering prevents runaway evaluation
- [ ] Envelope signing covers all fields
- [ ] No eval() or codegen in any SDK
