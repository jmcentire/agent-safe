# Pro‑Trust HOWTO: Agent‑Safe IAM in Practice

This guide shows how to deploy the **Proactive Trust (Pro‑Trust)** model for AI agents: portable capability tokens, Merkle proofs, offline budgets, threshold co‑signatures, revocable leases, and a tiny deterministic policy language (SPL). It’s written to double as a LinkedIn technical article and a repository HOWTO.

---

## Who this is for

- **Security & IAM engineers** who need machine‑speed decisions with auditable controls.  
- **Agent builders** who want deterministic yes/no answers without shipping long‑lived secrets.  
- **Tech leaders** who want adoption in hours, not weeks.

> You keep your IdP/SSO and Zero Trust posture. Pro‑Trust adds **portable, signed authorization** that services can verify locally in microseconds.

---

## 0) Try the demo (≈5 minutes)

Clone or download the repo, then run either the JS or Go verifier against a sample policy and request.

### JS / TypeScript
```bash
cd sdk/js
npm i
npm run build
node dist/index.js ../../examples/policies/family_gifts.spl ../../examples/requests/gift_50_niece.json
# -> ALLOW
```

### Go
```bash
cd sdk/go
go run ./verify ../../examples/policies/family_gifts.spl ../../examples/requests/gift_50_niece.json
# -> ALLOW
```

The crypto hooks are stubbed for clarity (`dpop_ok?`, `merkle_ok?`, `vrf_ok?`, `thresh_ok?`). Replace them with your production libraries to go live.

---

## 1) Concepts in five minutes

**Agent** – a non‑human actor with its own key pair.  
**Grantor** – your policy server that mints **capability tokens** bound to an agent’s key.  
**Capability** – a signed envelope that encodes **actor, action, object, context** and constraints.  
**SPL** – a tiny, deterministic S‑expression policy evaluated by verifiers to return **true/false**.  
**Proofs** – cryptographic facts carried with each request:  
- **DPoP/mTLS** – binds the call to the agent’s key (proof‑of‑possession).  
- **Merkle inclusion** – proves an exact `(actor, action, object, constraints)` tuple is allowed.  
- **Offline budgets** – one‑time tags (VRF/hash‑chain) to enforce frequency/amount without a round‑trip.  
- **Threshold co‑signatures** – add human/policy/risk signatures for sensitive actions.  
- **Revocable lease** – stage risky actions; auto‑settle unless canceled within a window.

**Flow (happy path):**

```
Agent --(capability + proofs + DPoP)--> Service
      <-(lease pending / allow)-------
[optional: user cancel lease within T]
```

---

## 2) Capability token shape

A capability is a signed object that carries policy-as-data (canonical SPL bytes) and ancillary material (Merkle root, revocation id, bindings). Example (illustrative):

```json
{
  "cap": {
    "sub": "pub:K_ai",
    "act": ["payments.create"],
    "obj": ["recipient:niece@example.com"],
    "caveats": {
      "amount_max": 50,
      "purpose": ["giftcard"],
      "per_day": 1,
      "exp": "2025-10-31T00:00:00Z",
      "device_attested": true
    },
    "policy_spl": "(and (= (get req \"actor_pub\") \"K_ai\") (= (get req \"action\") \"payments.create\") (<= (get req \"amount\") 50) (member (get req \"recipient\") allowed_recipients) (= (get req \"purpose\") \"giftcard\") (<= (per-day-count \"payments.create\" (get req \"day\")) 1) (get req \"device_attested\") (dpop_ok?) (merkle_ok? (tuple (get req \"actor_pub\") (get req \"action\") (get req \"recipient\") 50 \"giftcard\" (get req \"day\"))) (vrf_ok? (get req \"day\") (get req \"amount\")))",
    "set_root": "merkle_root_hex",
    "pop": { "type": "DPoP", "jkt": "thumbprint(K_ai)" },
    "rev": "rev_id_123"
  },
  "sig": "GrantorSignature"
}
```

The verifier must validate the signature over the **canonical bytes** before evaluating SPL.

---

## 3) SPL: the tiny policy language

SPL is a pure, total, deterministic S‑expression subset. No loops, no I/O, no side effects. Verifiers must enforce an instruction budget.

**Example** (same policy as above, pretty‑printed):

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

**Host values** like `allowed_recipients`, `per-day-count`, and crypto predicates are provided by the verifier environment.

---

## 4) Merkle proofs (fine‑grained allow)

- Build a Merkle tree over canonicalized tuples.  
- Sign the root in the capability.  
- Each request includes the tuple + inclusion proof; the verifier checks the path against `set_root`.

If your allow‑set is large, shard by object or date; include the shard id in the capability.

---

## 5) Offline budgets (no round‑trip)

Use one of the two patterns:

1. **Hash‑chain receipts:** the grantor provides a seed; each spend reveals the next preimage. Verifier checks the chain and rejects reuse.  
2. **VRF tags:** the grantor signs a VRF public key; the agent produces a per‑day tag (e.g., `VRF(day || amount || nonce)`); verifier checks and enforces cardinality/amount limits.

Both are deterministic and stateless on the hot path.

---

## 6) Threshold co‑signatures (step‑up when it matters)

Define a policy threshold like `2 of {agent_key, policy_key, human_webauthn_key}`. Low‑risk actions clear with `agent+policy`. High‑risk add the human signature. Attach co‑signatures to the request; verifiers check the set against the threshold, locally.

---

## 7) Revocable leases (undo without blocking)

For actions that should be cancelable:

- Service returns `202 Accepted` with a **lease**:
  ```json
  { "lease_id":"L-abc", "expires_at":"2025-09-29T20:00:00Z", "state":"pending" }
  ```
- If not canceled before `expires_at`, the service **settles** the action.  
- Provide `POST /leases/{id}/cancel` and ensure idempotency.

If a provider cannot stage/undo, force a **step‑up** instead of leasing.

---

## 8) Integrating a service (one function)

Add a verifier SDK and gate the protected action:

### Node/TypeScript
```ts
import { parseSExpr } from "@agentsafe/spl-verifier/dist/spl.js";
import { verify } from "@agentsafe/spl-verifier/dist/verify.js";

export async function handlePayment(req, res) {
  const token = req.body.token;            // your signed capability object
  const policyAst = parseSExpr(token.cap.policy_spl);

  const env = {
    allowed_recipients: ["niece@example.com","mom@example.com"],
    now: new Date().toISOString(),
    per_day_count: (_action: string, _day: string) => 0,
    crypto: {
      dpop_ok: () => true,                 // TODO: real DPoP check
      merkle_ok: (_tuple:any) => true,     // TODO: real inclusion check
      vrf_ok: (_day:string,_amt:number)=> true,
      thresh_ok: ()=> true
    }
  };

  const { allow } = verify(policyAst, req.body.request, env);
  if (!allow) return res.status(403).json({ error: "denied" });

  // Create a lease for reversible actions
  return res.status(202).json({ lease_id: "L-abc", expires_at: "..." });
}
```

### Go
```go
ast, _ := spl.Parse(token.Cap.PolicySPL)

env := spl.Env{
  Req: reqBody.Request,
  AllowedRecipients: []string{"niece@example.com","mom@example.com"},
  PerDayCount: func(action, day string) int { return 0 },
}
env.Crypto.DPoPOk = func() bool { return true }      // TODO
env.Crypto.MerkleOk = func(tuple []any) bool { return true }
env.Crypto.VRFOk = func(day string, amount float64) bool { return true }

allow, err := spl.Verify(ast, env)
if err != nil || !allow { w.WriteHeader(403); return }
// 202 with lease for reversible actions
```

---

## 9) The Grantor: issuing capabilities

A minimal grantor exposes two APIs:

- `POST /capabilities` — compile a template (e.g., “family gifts ≤ $50/day”) to canonical SPL, compute Merkle roots, attach budget metadata, and **sign** the capability.  
- `POST /capabilities/revoke` — add `rev_id` to a CRL; short token TTLs ensure fast convergence.

Templates keep humans out of raw SPL. Example fields: recipients, amount_max, per_day, time windows, device attestation, lease window, escalation threshold.

---

## 10) Observability & audit

Every accepted request should append an immutable event:

```json
{
  "ts":"2025-09-29T15:00:00Z",
  "policy_hash":"sha256:...",
  "actor_pub":"K_ai",
  "action":"payments.create",
  "object":"recipient:niece@example.com",
  "inputs_digest":"sha256:...",
  "proofs": { "dpop": "ok", "merkle": "ok", "budget": "ok", "thresh": "n/a" },
  "decision":"allow",
  "lease_id":"L-abc"
}
```

Metrics to export: `spl_allow_total`, `spl_deny_total`, `spl_eval_ms` (p50/p99), `lease_cancel_rate`.

---

## 11) Security hardening checklist

- Enforce **signature verification** over canonical policy bytes before SPL evaluation.  
- Bind callers with **DPoP/mTLS**; reject bearer‑only tokens.  
- SPL evaluator must be **total** and **gas‑metered**; no I/O, no recursion.  
- Keep **token TTLs short**; use `rev_id` + CRLs for immediate kill.  
- Implement **nonce/idempotency** on write APIs.  
- Require **step‑up** where leases are impossible (wire‑transfers, irreversible emails).  
- Consider **attestation** (WebAuthn for humans; TEE for high‑risk agent runtimes).

---

## 12) Performance notes

- SPL evaluation is a few dozen ops → microseconds per call in Go/Node.  
- Merkle proofs verify in O(log N); typical proofs are <1 KB.  
- VRF/hash‑chain checks are constant‑time.  
- With PoP verification on the same host, end‑to‑end authZ adds sub‑millisecond overhead.

---

## 13) FAQ

**Is this a replacement for my IdP?** No. It sits beside your IAM to provide portable authorization proofs.  
**Do I have to learn Lisp?** No. Use templates; the grantor compiles to SPL.  
**What if the agent is compromised?** PoP binding + short TTLs + revocation + budgets + leases limit blast radius.  
**Can I start small?** Yes—pilot on payments or email, then add services incrementally.

---

## 14) What’s in this repo

- `SPEC.md` — SPL v0.1 mini‑spec and verifier API.  
- `examples/` — a working policy + request.  
- `sdk/js`, `sdk/go` — minimal verifiers (crypto stubs).  
- `cli/js` — quick local runs against policies/requests.

---

## 15) Next steps

- Replace crypto stubs with your libraries (Merkle, DPoP, VRF, threshold).  
- Add real signature verification for `policy_spl` bytes.  
- Stand up a simple **grantor** that compiles templates → signed capabilities.  
- Add `POST /intent` and `POST /leases/{id}/cancel` to your first service and ship a small pilot.

That’s it. You now have a path to **yes at machine speed, no with proofs, and undo when you need it**.
