import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { parseSExpr, evalPolicy, Sym } from './spl.js';
import { verify } from './verify.js';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

function makeEnv() {
  return {
    vars: {
      allowed_recipients: ['niece@example.com', 'mom@example.com'],
      now: '2025-10-01T00:00:00Z',
    },
    now: '2025-10-01T00:00:00Z',
    per_day_count: (_action: string, _day: string) => 0,
    crypto: {
      dpop_ok: () => true,     // explicit opt-in for tests
      merkle_ok: (_tuple: any) => true,
      vrf_ok: (_day: string, _amount: number) => true,
      thresh_ok: () => true,
    },
  };
}

function evalExpr(src: string, env?: any): boolean {
  const ast = parseSExpr(src);
  const e = env || makeEnv();
  const { allow } = verify(ast, { amount: 0 }, e);
  return allow;
}

// --- Parser tests ---

describe('Parser', () => {
  it('parses numbers', () => {
    assert.equal(parseSExpr('42'), 42);
    assert.equal(parseSExpr('-3.14'), -3.14);
  });

  it('parses strings', () => {
    assert.equal(parseSExpr('"hello"'), 'hello');
  });

  it('parses booleans', () => {
    assert.equal(parseSExpr('#t'), true);
    assert.equal(parseSExpr('#f'), false);
  });

  it('parses symbols', () => {
    const s = parseSExpr('foo');
    assert.ok(s instanceof Sym);
    assert.equal((s as Sym).name, 'foo');
  });

  it('parses lists', () => {
    const ast = parseSExpr('(and #t #f)');
    assert.ok(Array.isArray(ast));
    assert.equal((ast as any[]).length, 3);
    assert.ok((ast as any[])[0] instanceof Sym);
    assert.equal(((ast as any[])[0] as Sym).name, 'and');
  });

  it('parses nested lists', () => {
    const ast = parseSExpr('(and (= 1 2) (> 3 1))');
    assert.ok(Array.isArray(ast));
    const inner = (ast as any[])[1];
    assert.ok(Array.isArray(inner));
    assert.ok(inner[0] instanceof Sym);
    assert.equal((inner[0] as Sym).name, '=');
  });

  it('parses strings with spaces', () => {
    const ast = parseSExpr('(= "hello world" "hello world")');
    assert.equal((ast as any[])[1], 'hello world');
  });

  it('throws on unterminated paren', () => {
    assert.throws(() => parseSExpr('(and #t'), /unterminated/);
  });

  it('throws on unexpected close paren', () => {
    assert.throws(() => parseSExpr(')'), /unexpected/);
  });

  it('throws on extra tokens', () => {
    assert.throws(() => parseSExpr('#t #f'), /extra tokens/);
  });
});

// --- Eval tests ---

describe('Eval', () => {
  it('and - all true', () => {
    assert.equal(evalExpr('(and #t #t #t)'), true);
  });

  it('and - one false', () => {
    assert.equal(evalExpr('(and #t #f #t)'), false);
  });

  it('or - one true', () => {
    assert.equal(evalExpr('(or #f #t #f)'), true);
  });

  it('or - all false', () => {
    assert.equal(evalExpr('(or #f #f)'), false);
  });

  it('not', () => {
    assert.equal(evalExpr('(not #f)'), true);
    assert.equal(evalExpr('(not #t)'), false);
  });

  it('= strings', () => {
    assert.equal(evalExpr('(= "hello" "hello")'), true);
    assert.equal(evalExpr('(= "hello" "world")'), false);
  });

  it('<=', () => {
    assert.equal(evalExpr('(<= 5 10)'), true);
    assert.equal(evalExpr('(<= 10 10)'), true);
    assert.equal(evalExpr('(<= 11 10)'), false);
  });

  it('<', () => {
    assert.equal(evalExpr('(< 5 10)'), true);
    assert.equal(evalExpr('(< 5 5)'), false);
  });

  it('>=', () => {
    assert.equal(evalExpr('(>= 10 10)'), true);
    assert.equal(evalExpr('(>= 9 10)'), false);
  });

  it('>', () => {
    assert.equal(evalExpr('(> 10 5)'), true);
    assert.equal(evalExpr('(> 5 5)'), false);
  });

  it('member', () => {
    assert.equal(evalExpr('(member "niece@example.com" allowed_recipients)'), true);
    assert.equal(evalExpr('(member "stranger@example.com" allowed_recipients)'), false);
  });

  it('in (alias for member)', () => {
    assert.equal(evalExpr('(in "mom@example.com" allowed_recipients)'), true);
  });

  it('subset?', () => {
    const env = makeEnv();
    (env.vars as any).small = ['a', 'b'];
    (env.vars as any).big = ['a', 'b', 'c'];
    assert.equal(evalExpr('(subset? small big)', env), true);
    assert.equal(evalExpr('(subset? big small)', env), false);
  });

  it('before', () => {
    assert.equal(evalExpr('(before now "2026-01-01T00:00:00Z")'), true);
    assert.equal(evalExpr('(before now "2025-01-01T00:00:00Z")'), false);
  });

  it('get', () => {
    const env = makeEnv();
    const ast = parseSExpr('(= (get req "actor_pub") "K_ai")');
    const req = { actor_pub: 'K_ai', action: 'test' };
    const { allow } = verify(ast, req, env);
    assert.equal(allow, true);
  });

  it('crypto callbacks (explicit true)', () => {
    assert.equal(evalExpr('(dpop_ok?)'), true);
    assert.equal(evalExpr('(thresh_ok?)'), true);
  });

  it('crypto defaults are fail-closed', () => {
    const env = {
      vars: {},
      now: '2025-10-01T00:00:00Z',
      per_day_count: (_action: string, _day: string) => 0,
      crypto: {},
    };
    const ast = parseSExpr('(dpop_ok?)');
    const { allow } = verify(ast, {}, env);
    assert.equal(allow, false);
  });

  it('unknown op throws', () => {
    assert.throws(() => evalExpr('(bogus 1 2)'), /Unknown op/);
  });
});

// --- Gas budget tests ---

describe('Gas budget', () => {
  it('exceeds gas budget', () => {
    const env = makeEnv();
    (env as any).maxGas = 3;
    assert.throws(() => evalExpr('(and #t #t #t #t #t #t #t #t)', env), /gas budget exceeded/);
  });

  it('sufficient gas budget', () => {
    const env = makeEnv();
    (env as any).maxGas = 100;
    assert.equal(evalExpr('(and #t #t)', env), true);
  });
});

// --- Strict mode tests ---

describe('Strict mode', () => {
  it('errors on unresolved symbol when strict', () => {
    const env = makeEnv();
    (env as any).strict = true;
    assert.throws(() => evalExpr('(= "foo" unbound_var)', env), /Unresolved symbol: unbound_var/);
  });

  it('allows unresolved symbols when not strict', () => {
    const env = makeEnv();
    // unbound_var resolves to "unbound_var" string, which != "foo"
    assert.equal(evalExpr('(= "foo" unbound_var)', env), false);
  });
});

// --- Integration test ---

describe('Integration', () => {
  it('family_gifts.spl ALLOW', () => {
    let policyBytes: string;
    let reqBytes: string;
    try {
      policyBytes = readFileSync(resolve(import.meta.dirname!, '../../..', 'examples/policies/family_gifts.spl'), 'utf8').trim();
      reqBytes = readFileSync(resolve(import.meta.dirname!, '../../..', 'examples/requests/gift_50_niece.json'), 'utf8');
    } catch {
      return; // skip if files not found
    }

    const ast = parseSExpr(policyBytes);
    const req = JSON.parse(reqBytes);
    const env = makeEnv();
    const { allow } = verify(ast, req, env);
    assert.equal(allow, true);
  });

  it('family_gifts.spl DENY on high amount', () => {
    let policyBytes: string;
    let reqBytes: string;
    try {
      policyBytes = readFileSync(resolve(import.meta.dirname!, '../../..', 'examples/policies/family_gifts.spl'), 'utf8').trim();
      reqBytes = readFileSync(resolve(import.meta.dirname!, '../../..', 'examples/requests/gift_50_niece.json'), 'utf8');
    } catch {
      return; // skip if files not found
    }

    const ast = parseSExpr(policyBytes);
    const req = JSON.parse(reqBytes);
    req.amount = 100;
    const env = makeEnv();
    const { allow } = verify(ast, req, env);
    assert.equal(allow, false);
  });
});
