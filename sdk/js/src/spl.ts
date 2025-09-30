// Minimal S-expression parser & evaluator for SPL subset
type S = string | number | boolean | S[];

export function parseSExpr(src: string): S {
  const tokens = src.replace(/\n/g,' ').replace(/\t/g,' ').split(/\s+/).filter(Boolean);
  let i = 0;
  function atom(tok: string): S {
    if (tok === '#t') return true;
    if (tok === '#f') return false;
    if (/^-?\d+(\.\d+)?$/.test(tok)) return Number(tok);
    if (tok.startsWith('"') && tok.endsWith('"')) return JSON.parse(tok);
    return tok;
  }
  function parse(): S {
    const tok = tokens[i++];
    if (tok === '(') {
      const arr: S[] = [];
      while (tokens[i] !== ')') arr.push(parse());
      i++; return arr;
    }
    if (tok === ')') throw new Error('unexpected )');
    return atom(tok);
  }
  // Wrap tokens with parens if not already tokenized
  const balanced = src.trim().startsWith('(') ? src : `(${src})`;
  // re-tokenize correctly by handling parentheses as separate tokens
  const toks: string[] = [];
  let buf = '';
  let inStr = false;
  for (const ch of balanced) {
    if (inStr) {
      buf += ch;
      if (ch === '"' && !buf.endsWith('\\"')) inStr = false;
      continue;
    }
    if (ch === '"') { inStr = true; buf += ch; continue; }
    if (ch === '(' || ch === ')') {
      if (buf.trim()) toks.push(...buf.trim().split(/\s+/));
      toks.push(ch); buf=''; continue;
    }
    buf += ch;
  }
  if (buf.trim()) toks.push(...buf.trim().split(/\s+/));
  // replace tokens & parse
  (tokens as any).length = 0;
  tokens.push(...toks);
  i = 0;
  const out = parse();
  if (i !== tokens.length) throw new Error('extra tokens');
  return out;
}

export function evalPolicy(ast: S, ctx: any): any {
  // Not used directly; see verify()
  return evalS(ast, ctx);
}

function evalS(node: S, ctx: any): any {
  if (!Array.isArray(node)) return resolveSymbol(node, ctx);
  if (node.length === 0) return null;
  const [op, ...args] = node;
  switch (op) {
    case 'and': return args.every(a=>truthy(evalS(a, ctx)));
    case 'or': return args.some(a=>truthy(evalS(a, ctx)));
    case 'not': return !truthy(evalS(args[0], ctx));
    case '=': return evalS(args[0], ctx) === evalS(args[1], ctx);
    case '<=': return evalS(args[0], ctx) <= evalS(args[1], ctx);
    case '<': return evalS(args[0], ctx) < evalS(args[1], ctx);
    case '>=': return evalS(args[0], ctx) >= evalS(args[1], ctx);
    case '>': return evalS(args[0], ctx) > evalS(args[1], ctx);
    case 'member': {
      const v = evalS(args[0], ctx);
      const lst = resolveSymbol(args[1], ctx);
      return Array.isArray(lst) && lst.includes(v);
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
    case 'merkle_ok?': return ctx.crypto.merkle_ok(args.map(a=>evalS(a,ctx)));
    case 'vrf_ok?': return ctx.crypto.vrf_ok(...args.map(a=>evalS(a,ctx)));
    case 'tuple': return args.map(a=>evalS(a,ctx));
    default:
      throw new Error('Unknown op: '+op);
  }
}

function resolveSymbol(x: S, ctx:any): any {
  if (typeof x === 'string') {
    if (x === '#t') return true;
    if (x === '#f') return false;
    if (x === 'req') return ctx.req;
    if (x === 'allowed_recipients') return ctx.allowed_recipients;
    // fallthrough: treat as symbol literal
  }
  return x;
}

function truthy(v:any){ return !!v; }
