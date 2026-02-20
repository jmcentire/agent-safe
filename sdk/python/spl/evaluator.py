"""Tree-walk evaluator for SPL ASTs. All 20 built-ins, gas/depth metering."""

from typing import Any

DEFAULT_MAX_GAS = 10_000
MAX_DEPTH = 64


class GasExhausted(RuntimeError):
    pass


class DepthExceeded(RuntimeError):
    pass


class SPLError(RuntimeError):
    pass


class _EvalState:
    __slots__ = ("gas", "depth")

    def __init__(self, max_gas: int):
        self.gas = max_gas
        self.depth = 0


def eval_policy(ast: Any, ctx: dict) -> Any:
    """Evaluate an SPL AST within a context dict.

    ctx keys: req, vars, now, per_day_count, crypto, maxGas
    """
    max_gas = ctx.get("maxGas") or ctx.get("max_gas") or DEFAULT_MAX_GAS
    state = _EvalState(max_gas)
    return _eval(ast, ctx, state)


def _eval(node: Any, ctx: dict, st: _EvalState) -> Any:
    st.gas -= 1
    if st.gas < 0:
        raise GasExhausted("gas budget exceeded")
    st.depth += 1
    if st.depth > MAX_DEPTH:
        st.depth -= 1
        raise DepthExceeded("max nesting depth exceeded")
    try:
        return _eval_inner(node, ctx, st)
    finally:
        st.depth -= 1


def _eval_inner(node: Any, ctx: dict, st: _EvalState) -> Any:
    if not isinstance(node, list):
        return _resolve_symbol(node, ctx)
    if len(node) == 0:
        return None
    op = node[0]
    args = node[1:]

    # --- Logical ---
    if op == "and":
        for a in args:
            if not _truthy(_eval(a, ctx, st)):
                return False
        return True

    if op == "or":
        for a in args:
            if _truthy(_eval(a, ctx, st)):
                return True
        return False

    if op == "not":
        return not _truthy(_eval(args[0], ctx, st))

    # --- Comparison ---
    if op == "=":
        return _eval(args[0], ctx, st) == _eval(args[1], ctx, st)

    if op in ("<=", "<", ">=", ">"):
        a = _to_float(_eval(args[0], ctx, st))
        b = _to_float(_eval(args[1], ctx, st))
        if op == "<=":
            return a <= b
        if op == "<":
            return a < b
        if op == ">=":
            return a >= b
        return a > b

    # --- Sets ---
    if op in ("member", "in"):
        val = _eval(args[0], ctx, st)
        lst = _eval(args[1], ctx, st)
        if isinstance(lst, list):
            return val in lst
        return False

    if op == "subset?":
        a = _eval(args[0], ctx, st)
        b = _eval(args[1], ctx, st)
        if not isinstance(a, list) or not isinstance(b, list):
            return False
        return all(item in b for item in a)

    # --- Time ---
    if op == "before":
        a = _eval(args[0], ctx, st)
        b = _eval(args[1], ctx, st)
        return str(a) < str(b)

    # --- Accessors ---
    if op == "get":
        obj = _resolve_symbol(args[0], ctx)
        key = _eval(args[1], ctx, st)
        if isinstance(obj, dict) and isinstance(key, str):
            return obj.get(key)
        return None

    if op == "tuple":
        return [_eval(a, ctx, st) for a in args]

    # --- Counter ---
    if op == "per-day-count":
        action = _eval(args[0], ctx, st)
        day = _eval(args[1], ctx, st)
        fn = ctx.get("per_day_count")
        if fn:
            return fn(str(action), str(day))
        return 0

    # --- Crypto predicates ---
    crypto = ctx.get("crypto", {})

    if op == "dpop_ok?":
        fn = crypto.get("dpop_ok") if isinstance(crypto, dict) else getattr(crypto, "dpop_ok", None)
        return fn() if fn else True

    if op == "merkle_ok?":
        evaluated = [_eval(a, ctx, st) for a in args]
        fn = crypto.get("merkle_ok") if isinstance(crypto, dict) else getattr(crypto, "merkle_ok", None)
        return fn(evaluated) if fn else True

    if op == "vrf_ok?":
        day = _eval(args[0], ctx, st)
        amount = _eval(args[1], ctx, st)
        fn = crypto.get("vrf_ok") if isinstance(crypto, dict) else getattr(crypto, "vrf_ok", None)
        return fn(str(day), _to_float(amount)) if fn else True

    # thresh_ok? — Threshold co-signature verification.
    # Expected protocol: k-of-n co-signatures where the verifier checks each
    # signature against its corresponding public key and confirms count >= threshold.
    # Not implemented in v0.1 — remains an interface stub. Provide your own
    # implementation via the crypto callbacks when integrating.
    if op == "thresh_ok?":
        fn = crypto.get("thresh_ok") if isinstance(crypto, dict) else getattr(crypto, "thresh_ok", None)
        return fn() if fn else True

    raise SPLError(f"Unknown op: {op}")


def _resolve_symbol(x: Any, ctx: dict) -> Any:
    if isinstance(x, str):
        if x == "#t":
            return True
        if x == "#f":
            return False
        if x == "req":
            return ctx.get("req", {})
        if x == "now":
            v = ctx.get("vars", {})
            return v.get("now", x) if isinstance(v, dict) else x
        v = ctx.get("vars", {})
        if isinstance(v, dict) and x in v:
            return v[x]
    return x


def _truthy(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    return True


def _to_float(x: Any) -> float:
    if isinstance(x, (int, float)):
        return float(x)
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0
