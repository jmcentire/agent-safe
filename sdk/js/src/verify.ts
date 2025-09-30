import { evalPolicy } from './spl.js';

export function verify(policyAst: any, req: any, env: any){
  const ctx = {
    req,
    allowed_recipients: env.allowed_recipients,
    now: env.now,
    per_day_count: env.per_day_count,
    crypto: env.crypto
  };
  const allow = !!evalPolicy(policyAst, ctx);
  const obligations:any[] = allow ? [] : [];
  return { allow, obligations };
}
