import { parseSExpr, evalPolicy } from './spl.js';
import { performance } from 'node:perf_hooks';

const policy = `(and
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
)`;

const ctx = {
  req: {
    actor_pub: 'K_ai',
    action: 'payments.create',
    amount: 50,
    recipient: 'niece@example.com',
    purpose: 'giftcard',
    day: '2025-01-15',
    device_attested: true,
  },
  vars: {
    allowed_recipients: ['niece@example.com', 'mom@example.com'],
    now: '2025-06-01T00:00:00Z',
  },
  per_day_count: () => 0,
  crypto: {
    dpop_ok: () => true,
    merkle_ok: () => true,
    vrf_ok: () => true,
    thresh_ok: () => true,
  },
};

// Warmup
const ast = parseSExpr(policy);
for (let i = 0; i < 10000; i++) evalPolicy(ast, { ...ctx });

// Benchmark: parse + eval
const N = 100000;
const t0 = performance.now();
for (let i = 0; i < N; i++) {
  const a = parseSExpr(policy);
  evalPolicy(a, { ...ctx });
}
const t1 = performance.now();
console.log(`Parse+Eval: ${((t1 - t0) / N * 1000).toFixed(0)} μs/op  (${N} iterations)`);

// Benchmark: eval only
const t2 = performance.now();
for (let i = 0; i < N; i++) {
  evalPolicy(ast, { ...ctx });
}
const t3 = performance.now();
console.log(`Eval only:  ${((t3 - t2) / N * 1000).toFixed(0)} μs/op  (${N} iterations)`);
