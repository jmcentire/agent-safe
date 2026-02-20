import pytest
from spl.parser import parse
from spl.verifier import verify


def make_env():
    return {
        "vars": {
            "allowed_recipients": ["niece@example.com", "mom@example.com"],
            "now": "2025-10-01T00:00:00Z",
        },
        "now": "2025-10-01T00:00:00Z",
        "per_day_count": lambda _a, _d: 0,
        "crypto": {
            "dpop_ok": lambda: True,
            "merkle_ok": lambda _t: True,
            "vrf_ok": lambda _d, _a: True,
            "thresh_ok": lambda: True,
        },
    }


def eval_expr(src, env=None):
    ast = parse(src)
    e = env or make_env()
    result = verify(ast, {"amount": 0}, e)
    return result["allow"]


# --- Logical ---

def test_and_all_true():
    assert eval_expr("(and #t #t #t)") is True


def test_and_one_false():
    assert eval_expr("(and #t #f #t)") is False


def test_or_one_true():
    assert eval_expr("(or #f #t #f)") is True


def test_or_all_false():
    assert eval_expr("(or #f #f)") is False


def test_not_false():
    assert eval_expr("(not #f)") is True


def test_not_true():
    assert eval_expr("(not #t)") is False


# --- Comparison ---

def test_equal_strings():
    assert eval_expr('(= "hello" "hello")') is True


def test_equal_strings_false():
    assert eval_expr('(= "hello" "world")') is False


def test_less_equal():
    assert eval_expr("(<= 5 10)") is True
    assert eval_expr("(<= 10 10)") is True
    assert eval_expr("(<= 11 10)") is False


def test_less_than():
    assert eval_expr("(< 5 10)") is True
    assert eval_expr("(< 5 5)") is False


def test_greater_equal():
    assert eval_expr("(>= 10 10)") is True
    assert eval_expr("(>= 9 10)") is False


def test_greater_than():
    assert eval_expr("(> 10 5)") is True
    assert eval_expr("(> 5 5)") is False


# --- Sets ---

def test_member_true():
    assert eval_expr('(member "niece@example.com" allowed_recipients)') is True


def test_member_false():
    assert eval_expr('(member "stranger@example.com" allowed_recipients)') is False


def test_in_alias():
    assert eval_expr('(in "mom@example.com" allowed_recipients)') is True


def test_subset_true():
    env = make_env()
    env["vars"]["small"] = ["a", "b"]
    env["vars"]["big"] = ["a", "b", "c"]
    assert eval_expr("(subset? small big)", env) is True


def test_subset_false():
    env = make_env()
    env["vars"]["small"] = ["a", "b"]
    env["vars"]["big"] = ["a", "b", "c"]
    assert eval_expr("(subset? big small)", env) is False


# --- Time ---

def test_before_true():
    assert eval_expr('(before now "2026-01-01T00:00:00Z")') is True


def test_before_false():
    assert eval_expr('(before now "2025-01-01T00:00:00Z")') is False


# --- Accessors ---

def test_get():
    env = make_env()
    ast = parse('(= (get req "actor_pub") "K_ai")')
    req = {"actor_pub": "K_ai", "action": "test"}
    result = verify(ast, req, env)
    assert result["allow"] is True


# --- Crypto stubs ---

def test_crypto_stubs():
    assert eval_expr("(dpop_ok?)") is True
    assert eval_expr("(thresh_ok?)") is True


# --- Unknown op ---

def test_unknown_op():
    with pytest.raises(Exception, match="Unknown op"):
        eval_expr("(bogus 1 2)")
