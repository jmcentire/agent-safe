import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseSExpr, evalPolicy } from './spl.js';
import { verify } from './verify.js';

const [,, policyPath, requestPath] = process.argv;
if (!policyPath || !requestPath) {
  console.error('Usage: node dist/index.js <policy.spl> <request.json>');
  process.exit(1);
}

const policyBytes = readFileSync(resolve(policyPath), 'utf8').trim();
const policy = parseSExpr(policyBytes);

const request = JSON.parse(readFileSync(resolve(requestPath), 'utf8'));

const env = {
  allowed_recipients: ['niece@example.com','mom@example.com'],
  now: new Date().toISOString(),
  per_day_count: (action, day)=>0,
  crypto: {
    dpop_ok: ()=>true, // TODO: implement
    merkle_ok: (_tuple)=>true, // TODO: implement
    vrf_ok: (_day,_amount)=>true, // TODO: implement
    thresh_ok: ()=>true // TODO
  }
};

const { allow, obligations } = verify(policy, request, env);
console.log(allow ? 'ALLOW' : 'DENY');
if (obligations && obligations.length) {
  console.log('OBLIGATIONS', obligations);
}
