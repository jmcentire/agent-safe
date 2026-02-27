import { evalPolicy } from './spl.js';

export function verify(policyAst: any, req: any, env: any) {
  if (env.sealed) {
    return { allow: false, sealed: true, error: 'token is sealed and cannot be attenuated' };
  }
  const crypto = env.crypto || {};
  const ctx = {
    req,
    vars: env.vars || {},
    now: env.now,
    per_day_count: env.per_day_count || (() => 0),
    crypto: {
      dpop_ok: crypto.dpop_ok || (() => false),
      merkle_ok: crypto.merkle_ok || (() => false),
      vrf_ok: crypto.vrf_ok || (() => false),
      thresh_ok: crypto.thresh_ok || (() => false),
    },
    maxGas: env.maxGas,
    strict: env.strict || false,
  };
  const allow = !!evalPolicy(policyAst, ctx);
  return { allow, sealed: false };
}
