#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseSExpr } from '../../../sdk/js/dist/spl.js';
import { verify } from '../../../sdk/js/dist/verify.js';

const [,, policyPath, requestPath] = process.argv;
if (!policyPath || !requestPath) {
  console.error('Usage: spl <policy.spl> <request.json>');
  process.exit(1);
}
const policy = parseSExpr(readFileSync(resolve(policyPath), 'utf8').trim());
const request = JSON.parse(readFileSync(resolve(requestPath), 'utf8'));
const env = {
  vars: {
    allowed_recipients: ['niece@example.com', 'mom@example.com'],
  },
  now: new Date().toISOString(),
  per_day_count: (_action: string, _day: string) => 0,
  crypto: {
    dpop_ok: () => true,
    merkle_ok: () => true,
    vrf_ok: () => true,
    thresh_ok: () => true,
  },
};
const { allow } = verify(policy, request, env);
console.log(allow ? 'ALLOW' : 'DENY');
