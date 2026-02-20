import { evalPolicy } from './spl.js';

export function verify(policyAst: any, req: any, env: any) {
  if (env.sealed) {
    return { allow: false, sealed: true, error: 'token is sealed and cannot be attenuated' };
  }
  const ctx = {
    req,
    vars: env.vars || {},
    now: env.now,
    per_day_count: env.per_day_count,
    crypto: env.crypto,
    maxGas: env.maxGas,
  };
  const allow = !!evalPolicy(policyAst, ctx);
  return { allow, sealed: false };
}
