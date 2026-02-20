"""Top-level verify API for SPL policies."""

from typing import Any
from .evaluator import eval_policy


def verify(policy_ast: Any, req: dict, env: Any) -> dict:
    """Evaluate an SPL policy AST against a request.

    Args:
        policy_ast: Parsed SPL AST (from spl.parse)
        req: Request dict (e.g. {"actor_pub": "K_ai", "action": "payments.create", ...})
        env: Environment — either an Env dataclass or a dict with keys:
             vars, now, per_day_count, crypto, max_gas/maxGas

    Returns:
        {"allow": bool, "obligations": list}
    """
    if isinstance(env, dict):
        ctx = {
            "req": req,
            "vars": env.get("vars", {}),
            "now": env.get("now", ""),
            "per_day_count": env.get("per_day_count", lambda _a, _d: 0),
            "crypto": env.get("crypto", {}),
            "maxGas": env.get("maxGas") or env.get("max_gas"),
        }
    else:
        # Env dataclass
        ctx = {
            "req": req,
            "vars": env.vars if hasattr(env, "vars") else {},
            "now": env.now if hasattr(env, "now") else "",
            "per_day_count": env.per_day_count if hasattr(env, "per_day_count") else (lambda _a, _d: 0),
            "crypto": env.crypto if hasattr(env, "crypto") else {},
            "maxGas": env.max_gas if hasattr(env, "max_gas") else None,
        }
    sealed = False
    if isinstance(env, dict):
        sealed = env.get("sealed", False)
    elif hasattr(env, "sealed"):
        sealed = env.sealed

    if sealed:
        return {"allow": False, "sealed": True, "error": "token is sealed and cannot be attenuated"}

    result = eval_policy(policy_ast, ctx)
    allow = bool(result) if result is not None else False
    return {"allow": allow, "sealed": False}
