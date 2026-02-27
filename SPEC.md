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
- **Policy size limited**: implementations **should** enforce a maximum policy source size. Recommended default: 64 KB. This bounds parse time and memory allocation even before gas metering applies.
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
| `=` | `(= a b)` | `#t` if values equal (type-aware: numbers compare as numbers, strings as strings; cross-type comparisons return `#f`) |
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

Crypto predicates are implemented by the host environment. Reference SDKs default to `false` (fail-closed). Callers **must** provide real implementations for any predicate used in a policy; omitting a callback means the predicate denies.

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

Symbols not matching built-in names are resolved from `vars`. Unresolved symbols evaluate to themselves (as string literals) by default.

### Strict Mode

When `strict` is enabled in the environment, unresolved symbols raise an error instead of falling through. This prevents silent authorization bypass from typos or missing variable bindings (e.g., `(= (get req "role") admin_role)` where `admin_role` is unbound would silently match a request containing `"role": "admin_role"`). Recommended for production deployments.

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
  "pop_key": "a1b2...",
  "signature": "..."
}
```

## Canonicalization

For signing and verification:

1. Parse the policy source to AST
2. Serialize to canonical form: UTF-8, single spaces between tokens, no comments, no trailing whitespace
3. Build the **signing payload** covering all security-relevant fields (see Signing Payload below)
4. Sign the payload with the grantor's key
5. Verifiers reconstruct the payload and verify signature before evaluation

## Signing Payload

The Ed25519 signature covers the **full token envelope**, not just the policy text. This prevents tampering with `sealed`, `expires`, `merkle_root`, or `hash_chain_commitment` after signing.

The canonical signing payload is constructed by joining these fields with null bytes (`\0`):

```
canonical_policy \0 merkle_root \0 hash_chain_commitment \0 sealed_flag \0 expires
```

- **canonical_policy**: trimmed UTF-8 policy string
- **merkle_root**: hex string, or empty string if absent
- **hash_chain_commitment**: hex string, or empty string if absent
- **sealed_flag**: `"1"` if sealed, `"0"` if not
- **expires**: ISO 8601 string, or empty string if absent

All SDKs expose a `signingPayload()` / `SigningPayload()` function for this construction.

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

### Merkle Witness Distribution

The Merkle proof system is designed so sensitive data (e.g., authorized email addresses) never appears in the token or policy text.

**Distribution model:**

1. **Grantor** builds a Merkle tree over canonical tuples at token-minting time.
2. The **root hash** is embedded in the token and signed as part of the envelope.
3. The grantor provides **witness paths** (leaf-to-root proof steps) to the agent alongside the token. These may be delivered in a separate channel or bundled with the token.
4. The **agent** carries the token + relevant witness path(s) when making a request.
5. The **verifier** checks the proof path against the committed root. No bulk leaf list is transmitted or stored at the verifier.

**Privacy property:** The verifier learns only that the presented tuple is a member of the committed set. It does not learn the other members. The token itself reveals nothing about the set contents -- only the root hash.

**Privacy-preserving membership:** For sensitive allowlists (e.g., email recipients), the policy uses `(merkle_ok? (tuple ...))` rather than `(member val recipients)`. The agent supplies the candidate value and proof; the verifier checks inclusion without ever seeing the full allowlist. This is the recommended pattern for any authorization set that constitutes PII or business-sensitive data.

### Proof-of-Possession (PoP) Binding

PoP binding ensures that a token can only be presented by the agent it was issued to. The token envelope includes an optional `pop_key` field containing the agent's Ed25519 public key (hex).

**Token-level PoP (recommended):**

1. **At mint time**, the grantor sets `pop_key` to the agent's Ed25519 public key.
2. **At presentation**, the agent computes a **presentation signature**: `Ed25519.sign(agent_private_key, SHA-256(signing_payload))`.
3. **At verification**, the verifier checks the presentation signature against `pop_key` over `SHA-256(signing_payload)`. If `pop_key` is present but no valid presentation signature is provided, verification fails.

This is a token-layer check that runs before policy evaluation. It prevents stolen tokens from being used by an unauthorized party.

All SDKs expose:
- `createPresentationSignature(token, agentPrivateKeyHex)` — produces the presentation signature
- `verifyToken(..., presentationSignature)` — verifies the PoP binding

**Policy-level DPoP (advanced):**

The `dpop_ok?` predicate delegates to a host callback for more complex proof-of-possession protocols (e.g., RFC 9449 DPoP proofs over HTTP). Implementations should verify:

1. The DPoP proof JWT is signed by the agent's key
2. The `htm` and `htu` claims match the request method and URI
3. The `jti` claim has not been seen before (replay protection)

### Per-Service Key Derivation (HKDF)

Agents can derive service-specific Ed25519 keypairs from a single master key, providing **unlinkability**: different services see different public keys for the same agent.

**Derivation:**

```
seed = HKDF-SHA256(
    salt = "agent-safe-v1",
    ikm  = master_private_key,
    info = service_domain,
    len  = 32
)
keypair = Ed25519.from_seed(seed)
```

All SDKs expose `deriveServiceKey(masterKeyHex, serviceDomain) -> (publicKeyHex, privateKeyHex)`.

**Privacy property:** A verifier at service A cannot determine whether a token was issued by the same agent that presents tokens at service B. The derived public keys are cryptographically independent.

**HKDF implementation:** All SDKs implement HKDF-SHA256 (RFC 5869) using only HMAC-SHA256 from their standard library, maintaining the zero-external-dependency guarantee.

### Threshold Co-signatures

`thresh_ok?` verifies k-of-n co-signatures. The expected protocol:

1. Collect `n` Ed25519 signatures from designated co-signers
2. Verify each signature against its corresponding public key
3. Confirm that the count of valid signatures >= threshold `k`

This predicate remains an interface stub in v0.1. Implementations should provide it via the crypto callbacks.
