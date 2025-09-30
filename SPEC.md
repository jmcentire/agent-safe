# SPL (Safe Policy Lisp) v0.1 Mini-Spec

SPL is a small, **total**, deterministic S-expression language used as a **portable policy IR**.
It evaluates a request + proofs to a boolean decision and optional obligations.

## Data types
- booleans: `#t`, `#f`
- strings: `"text"`
- numbers: integers/decimals
- lists: `(a b c)`
- symbols: `req.actor_pub`, `member`, etc.

## Evaluation
- Pure, no side effects, no I/O, no network, no randomness.
- No user-defined recursion; only bounded combinators.
- Implementations **must** enforce an instruction budget (gas) to prevent pathological inputs.

## Required built-ins (v0.1)
- Logical: `and`, `or`, `not`
- Compare: `=`, `<=`, `<`, `>=`, `>`
- Sets: `member` (string in list), `in` (alias), `subset?`
- Accessors: `(get req "field")` — reads from request object
- Time: `(before now "2025-12-31T00:00:00Z")`
- Crypto stubs (replace with real): `dpop_ok?`, `merkle_ok?`, `vrf_ok?`, `thresh_ok?`
- Counters (host-provided): `(per-day-count "action" day)` — for demo we pass in 0

## Canonicalization
- Policies are encoded as **canonical S-expr bytes** (UTF-8, single spaces, no comments) and signed by the Grantor.
- Verifiers operate on the signed bytes after signature verification (not implemented in scaffold).

## Verifier API (host)
```ts
verifySPL({ policyBytes, request, proofs, now }): { allow: boolean, obligations?: any[] }
```

## Example policy
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
  (merkle_ok? (tuple (get req "actor_pub") (get req "action") (get req "recipient") 50 "giftcard" (get req "day")))
  (vrf_ok? (get req "day") (get req "amount"))
)
```

Implementations must provide host variables like `allowed_recipients` via the environment bound to the policy.
