import pytest
from spl.parser import parse
from spl.verifier import verify
from spl.evaluator import GasExhausted, SPLError


def make_env(**overrides):
    env = {
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
    env.update(overrides)
    return env


def test_gas_budget_exceeded():
    env = make_env(maxGas=3)
    ast = parse("(and #t #t #t #t #t #t #t #t)")
    with pytest.raises(GasExhausted, match="gas budget exceeded"):
        verify(ast, {"amount": 0}, env)


def test_gas_budget_sufficient():
    env = make_env(maxGas=100)
    ast = parse("(and #t #t)")
    result = verify(ast, {"amount": 0}, env)
    assert result["allow"] is True


def test_error_propagation_in_and():
    env = make_env()
    ast = parse("(and #t (bogus))")
    with pytest.raises(SPLError, match="Unknown op"):
        verify(ast, {"amount": 0}, env)


def test_error_propagation_in_or():
    env = make_env()
    ast = parse("(or #f (bogus))")
    with pytest.raises(SPLError, match="Unknown op"):
        verify(ast, {"amount": 0}, env)


def test_get_non_map():
    env = make_env()
    ast = parse('(= (get "notamap" "key") "value")')
    result = verify(ast, {"amount": 0}, env)
    assert result["allow"] is False
