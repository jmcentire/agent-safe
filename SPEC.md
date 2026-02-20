# SPL (Safe Policy Lisp) v0.1 Specification

SPL is a small, **total**, deterministic S-expression language used as a **portable policy IR** for AI agent capability tokens. It evaluates a request object plus cryptographic proofs to a boolean decision.

## Design Goals

1. **Totality** — every well-formed policy terminates. No unbounded recursion, no loops, no user-defined functions.
2. **Determinism** — same inputs always produce same output. No I/O, no randomness, no side effects.
3. **Portability** — single-file implementations in any language. No external dependencies.
4. **LLM readability** — S-expression syntax is unambiguous, easy for language models to generate and parse.
5. **Microsecond evaluation** — policy checks must not be a bottleneck.

## Grammar

```
program    := expr
expr       := atom | list
list       := '(' expr* ')'
atom       := boolean | number | string | symbol
boolean    := '#t' | '#f'
number     := '-'? [0-9]+ ('.' [0-9]+)?
string     := '"' char* '"'
symbol     := [a-zA-Z_?!.][a-zA-Z0-9_?!.-]*
char       := any UTF-8 character except unescaped '"'
```

Whitespace (space, tab, newline, carriage return) separates tokens. Parentheses and double quotes are self-delimiting.

## Data Types

| Type | Examples | Notes |
|------|----------|-------|
| Boolean | `#t`, `#f` | |
| Number | `42`, `-3.14`, `0` | IEEE 754 float64 |
| String | `"hello"`, `"K_ai"` | UTF-8, JSON-style escaping |
| List | `(a b c)` | Heterogeneous |
| Symbol | `req`, `allowed_recipients` | Resolved from environment |

## Evaluation Rules

- **Pure**: no side effects, no I/O, no network, no randomness.
- **No user-defined recursion**: only built-in combinators.
- **Gas metered**: implementations **must** enforce an instruction budget. Each `eval` call decrements the counter. When exhausted, evaluation halts with an error. Default budget: 10,000 operations.
- **Depth limited**: implementations **must** enforce a maximum nesting depth (default: 64) to prevent stack overflow.
- **Short-circuit**: `and` stops at first falsy; `or` stops at first truthy.

## Required Built-ins (v0.1)

### Logical

| Built-in | Signature | Returns |
|----------|-----------|---------|
| `and` | `(and expr ...)` | `#t` if all args truthy, else `#f`. Short-circuits. |
| `or` | `(or expr ...)` | `#t` if any arg truthy, else `#f`. Short-circuits. |
| `not` | `(not expr)` | `#t` if arg falsy, else `#f` |

### Comparison

| Built-in | Signature | Returns |
|----------|-----------|---------|
| `=` | `(= a b)` | `#t` if values equal (string comparison) |
| `<=` | `(<= a b)` | `#t` if `a <= b` (numeric) |
| `<` | `(< a b)` | `#t` if `a < b` (numeric) |
| `>=` | `(>= a b)` | `#t` if `a >= b` (numeric) |
| `>` | `(> a b)` | `#t` if `a > b` (numeric) |

### Sets

| Built-in | Signature | Returns |
|----------|-----------|---------|
| `member` | `(member val list)` | `#t` if `val` is in `list` |
| `in` | `(in val list)` | Alias for `member` |
| `subset?` | `(subset? a b)` | `#t` if every element of list `a` is in list `b` |

### Accessors

| Built-in | Signature | Returns |
|----------|-----------|---------|
| `get` | `(get obj "field")` | Value of field in object, or nil |
| `tuple` | `(tuple expr ...)` | List of evaluated expressions |

### Time

| Built-in | Signature | Returns |
|----------|-----------|---------|
| `before` | `(before a b)` | `#t` if ISO 8601 string `a` sorts before `b` |

### Crypto Predicates (host-provided)

| Built-in | Signature | Notes |
|----------|-----------|-------|
| `dpop_ok?` | `(dpop_ok?)` | Proof-of-possession check |
| `merkle_ok?` | `(merkle_ok? tuple)` | Merkle set-membership proof |
| `vrf_ok?` | `(vrf_ok? day amount)` | Offline budget verification |
| `thresh_ok?` | `(thresh_ok?)` | Threshold co-signature check |

Crypto predicates are implemented by the host environment. Reference SDKs stub them to `true` for demonstration.

### Counters (host-provided)

| Built-in | Signature | Notes |
|----------|-----------|-------|
| `per-day-count` | `(per-day-count "action" day)` | Returns count of action on given day |

## Environment

The evaluator receives an environment containing:

- **`req`** — the request object (map of string keys to values)
- **`vars`** — host-provided variables (e.g., `allowed_recipients`, `now`)
- **Crypto functions** — implementations of `dpop_ok?`, `merkle_ok?`, `vrf_ok?`, `thresh_ok?`
- **Counter functions** — implementation of `per-day-count`

Symbols not matching built-in names are resolved from `vars`. Unresolved symbols evaluate to themselves (as string literals).

## Token Sealing

A sealed token cannot be further attenuated. The token envelope includes a `sealed` field:

- If `sealed` is `true`, any attempt to add further restrictions (new policy conjuncts, reduced Merkle root, lower hash-chain length) **must** be rejected by the verifier.
- If `sealed` is `false` or absent, the token may be attenuated before forwarding.
- Sealing is one-way: once set, it cannot be unset without re-signing.

Verifiers that receive a token claiming to be derived from a sealed parent **must** reject it. The expected pattern: an issuer signs a sealed token when the delegation chain is complete and no further narrowing is needed.

```json
{
  "policy": "(and ...)",
  "merkle_root": "0e9a...",
  "sealed": true,
  "signature": "..."
}
```

## Canonicalization

For signing and verification:

1. Parse the policy source to AST
2. Serialize to canonical form: UTF-8, single spaces between tokens, no comments, no trailing whitespace
3. Sign the canonical bytes with the grantor's key
4. Verifiers reconstruct canonical bytes and verify signature before evaluation

## Verifier API

```
verifySPL({ policyBytes, request, proofs, now }) → { allow: boolean, error?: string }
```

1. Verify grantor signature over canonical policy bytes
2. Parse policy to AST
3. Construct environment with request, proofs, host variables
4. Evaluate AST with gas budget
5. Return boolean result

## Error Handling

Implementations must:
- Propagate all evaluation errors (never silently swallow)
- Return descriptive error messages for: unknown operators, type mismatches, gas exhaustion, depth overflow, parse failures
- Use safe type assertions (comma-ok in Go, type guards in TypeScript)
- Never panic on malformed input

## Example Policy

```lisp
(and
  (= (get req "actor_pub") "K_ai")
  (= (get req "action") "payments.create")
  (<= (get req "amount") 50)
  (member (get req "recipient") allowed_recipients)
  (= (get req "purpose") "giftcard")
  (<= (per-day-count "payments.create" (get req "day")) 1)
  (get req "device_attested")
  (dpop_ok?)
  (merkle_ok? (tuple (get req "actor_pub") (get req "action")
                     (get req "recipient") 50 "giftcard" (get req "day")))
  (vrf_ok? (get req "day") (get req "amount"))
)
```

Host variables like `allowed_recipients` are bound by the verifier environment, not embedded in the policy.

## Crypto Verification Requirements

### Token Signature Format

Tokens are signed with Ed25519 (RFC 8032). The signed payload is the canonical policy bytes (see Canonicalization above).

- **Public key**: 32 bytes, hex-encoded
- **Signature**: 64 bytes, hex-encoded
- **Verification**: Ed25519 verify over canonical UTF-8 policy bytes

### Merkle Proof Format

Set membership proofs use SHA-256 binary Merkle trees.

- **Leaf hash**: `SHA-256(leaf_data_bytes)` where leaf data is UTF-8 encoded
- **Proof step**: `{ hash: hex, position: "left" | "right" }`
- **Verification**: Starting from the leaf hash, for each step concatenate `current || sibling` (if position is "right") or `sibling || current` (if "left"), then SHA-256 hash. Final hash must equal the committed root.

### Hash Chain (Offline Budget) Format

Offline budget receipts use iterated SHA-256 hash chains.

- **Chain construction**: `chain[0] = seed`, `chain[i] = SHA-256(chain[i-1])` for `i` in `1..n`
- **Commitment**: `chain[n]` (the endpoint), published when the token is minted
- **Receipt**: To prove usage at step `i`, reveal `chain[i]`
- **Verification**: Hash the revealed preimage `(n - i)` times; result must equal the commitment

### DPoP (Proof-of-Possession) Format

DPoP binding follows RFC 9449. The `dpop_ok?` predicate delegates verification to the host environment. Implementations should verify:

1. The DPoP proof JWT is signed by the agent's key
2. The `htm` and `htu` claims match the request method and URI
3. The `jti` claim has not been seen before (replay protection)

### Threshold Co-signatures

`thresh_ok?` verifies k-of-n co-signatures. The expected protocol:

1. Collect `n` Ed25519 signatures from designated co-signers
2. Verify each signature against its corresponding public key
3. Confirm that the count of valid signatures >= threshold `k`

This predicate remains an interface stub in v0.1. Implementations should provide it via the crypto callbacks.
