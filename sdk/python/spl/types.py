from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# AST node types: bool, int, float, str, list (heterogeneous), None
# No wrapper needed — Python's native types map directly.

@dataclass
class CryptoCallbacks:
    dpop_ok: Callable[[], bool] = lambda: True
    merkle_ok: Callable[[list], bool] = lambda _t: True
    vrf_ok: Callable[[str, float], bool] = lambda _d, _a: True
    thresh_ok: Callable[[], bool] = lambda: True

@dataclass
class Env:
    req: dict[str, Any] = field(default_factory=dict)
    vars: dict[str, Any] = field(default_factory=dict)
    now: str = ""
    per_day_count: Callable[[str, str], int] = lambda _a, _d: 0
    crypto: CryptoCallbacks = field(default_factory=CryptoCallbacks)
    max_gas: int = 10_000
