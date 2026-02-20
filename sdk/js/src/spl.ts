// Minimal S-expression parser & evaluator for SPL subset
type S = string | number | boolean | S[];

const DEFAULT_MAX_GAS = 10000;
const MAX_DEPTH = 64;

export function parseSExpr(src: string): S {
  const tokens = tokenize(src);
  let i = 0;

  function atom(tok: string): S {
    if (tok === '#t') return true;
    if (tok === '#f') return false;
    if (/^-?\d+(\.\d+)?$/.test(tok)) return Number(tok);
    if (tok.startsWith('"') && tok.endsWith('"')) return JSON.parse(tok);
    return tok;
  }

  function parse(): S {
    if (i >= tokens.length) throw new Error('unexpected EOF');
    const tok = tokens[i++];
    if (tok === '(') {
      const arr: S[] = [];
      while (tokens[i] !== ')') {
        if (i >= tokens.length) throw new Error('unterminated (');
        arr.push(parse());
      }
      i++;
      return arr;
    }
    if (tok === ')') throw new Error('unexpected )');
    return atom(tok);
  }

  const out = parse();
  if (i !== tokens.length) throw new Error('extra tokens');
  return out;
}

function tokenize(src: string): string[] {
  const toks: string[] = [];
  let buf = '';
  let inStr = false;
  for (let j = 0; j < src.length; j++) {
    const ch = src[j];
    if (inStr) {
      buf += ch;
      if (ch === '"' && src[j - 1] !== '\\') {
        inStr = false;
        toks.push(buf);
        buf = '';
      }
      continue;
    }
    if (ch === '"') {
      if (buf.trim()) toks.push(...buf.trim().split(/\s+/));
      buf = '"';
      inStr = true;
      continue;
    }
    if (ch === '(' || ch === ')') {
      if (buf.trim()) toks.push(...buf.trim().split(/\s+/));
      toks.push(ch); buf = ''; continue;
    }
    buf += ch;
  }
  if (buf.trim()) toks.push(...buf.trim().split(/\s+/));
  return toks;
}

export function evalPolicy(ast: S, ctx: any): any {
  return evalS(ast, ctx);
}

function evalS(node: S, ctx: any): any {
  if (ctx._gas === undefined) ctx._gas = ctx.maxGas || DEFAULT_MAX_GAS;
  ctx._gas--;
  if (ctx._gas < 0) throw new Error('gas budget exceeded');
  if (ctx._depth === undefined) ctx._depth = 0;
  ctx._depth++;
  if (ctx._depth > MAX_DEPTH) {
    ctx._depth--;
    throw new Error('max nesting depth exceeded');
  }
  try {
    return evalInner(node, ctx);
  } finally {
    ctx._depth--;
  }
}

function evalInner(node: S, ctx: any): any {
  if (!Array.isArray(node)) return resolveSymbol(node, ctx);
  if (node.length === 0) return null;
  const [op, ...args] = node;
  switch (op) {
    case 'and': return args.every(a => truthy(evalS(a, ctx)));
    case 'or': return args.some(a => truthy(evalS(a, ctx)));
    case 'not': return !truthy(evalS(args[0], ctx));
    case '=': return evalS(args[0], ctx) === evalS(args[1], ctx);
    case '<=': return evalS(args[0], ctx) <= evalS(args[1], ctx);
    case '<': return evalS(args[0], ctx) < evalS(args[1], ctx);
    case '>=': return evalS(args[0], ctx) >= evalS(args[1], ctx);
    case '>': return evalS(args[0], ctx) > evalS(args[1], ctx);
    case 'member':
    case 'in': {
      const v = evalS(args[0], ctx);
      const lst = evalS(args[1], ctx);
      return Array.isArray(lst) && lst.includes(v);
    }
    case 'subset?': {
      const a = evalS(args[0], ctx);
      const b = evalS(args[1], ctx);
      if (!Array.isArray(a) || !Array.isArray(b)) return false;
      return a.every(item => b.includes(item));
    }
    case 'before': {
      const a = evalS(args[0], ctx);
      const b = evalS(args[1], ctx);
      return a < b;
    }
    case 'get': {
      const obj = resolveSymbol(args[0], ctx);
      const key = evalS(args[1], ctx);
      return obj?.[key];
    }
    case 'per-day-count': {
      const action = evalS(args[0], ctx);
      const day = evalS(args[1], ctx);
      return ctx.per_day_count(action, day);
    }
    case 'dpop_ok?': return ctx.crypto.dpop_ok();
    case 'merkle_ok?': return ctx.crypto.merkle_ok(args.map(a => evalS(a, ctx)));
    case 'vrf_ok?': return ctx.crypto.vrf_ok(...args.map(a => evalS(a, ctx)));
    // thresh_ok? — Threshold co-signature verification.
    // Expected protocol: k-of-n co-signatures where the verifier checks each
    // signature against its corresponding public key and confirms count >= threshold.
    // Not implemented in v0.1 — remains an interface stub. Provide your own
    // implementation via ctx.crypto.thresh_ok when integrating.
    case 'thresh_ok?': return ctx.crypto.thresh_ok();
    case 'tuple': return args.map(a => evalS(a, ctx));
    default:
      throw new Error('Unknown op: ' + op);
  }
}

function resolveSymbol(x: S, ctx: any): any {
  if (typeof x === 'string') {
    if (x === '#t') return true;
    if (x === '#f') return false;
    if (x === 'req') return ctx.req;
    if (x === 'now') return ctx.vars?.now ?? x;
    if (ctx.vars && x in ctx.vars) return ctx.vars[x];
  }
  return x;
}

function truthy(v: any) { return !!v; }
