# === SPL AST Evaluator (sdk_python_spl_evaluator) v1 ===
#  Dependencies: typing
# Tree-walk evaluator for SPL (Security Policy Language) ASTs with gas and depth metering. Implements 20 built-in operations including logical operators, comparisons, set operations, time operations, accessors, counters, and cryptographic predicates. Enforces resource limits via gas budget (default 10,000) and maximum recursion depth (64).

# Module invariants:
#   - DEFAULT_MAX_GAS = 10,000
#   - MAX_DEPTH = 64
#   - Gas is decremented by 1 for each _eval call
#   - Depth is incremented before evaluation and decremented after
#   - Evaluation stops when gas < 0 or depth > MAX_DEPTH

class GasExhausted:
    """Exception raised when gas budget is exhausted during evaluation"""
    pass

class DepthExceeded:
    """Exception raised when maximum nesting depth is exceeded during evaluation"""
    pass

class SPLError:
    """Exception raised for SPL evaluation errors (unknown operations, unresolved symbols in strict mode)"""
    pass

class _EvalState:
    """Internal state for tracking gas consumption and recursion depth during evaluation"""
    gas: int                                 # required, Remaining gas budget
    depth: int                               # required, Current recursion depth

def __init__(
    self: _EvalState,
    max_gas: int,
) -> None:
    """
    Initialize evaluation state with a maximum gas budget and zero depth

    Postconditions:
      - self.gas == max_gas
      - self.depth == 0

    Side effects: mutates_state
    Idempotent: no
    """
    ...

def eval_policy(
    ast: Any,
    ctx: dict,
) -> Any:
    """
    Evaluate an SPL AST within a context dictionary. Entry point for policy evaluation with automatic gas/depth metering setup.

    Preconditions:
      - ctx is a dict

    Postconditions:
      - Returns evaluation result of AST

    Errors:
      - gas_exhausted (GasExhausted): Gas budget is exhausted during evaluation
      - depth_exceeded (DepthExceeded): Recursion depth exceeds MAX_DEPTH (64)
      - unknown_operation (SPLError): AST contains unknown operation
      - unresolved_symbol (SPLError): Symbol cannot be resolved and ctx['strict'] is True

    Side effects: Calls functions from ctx['per_day_count'] and ctx['crypto'] if present
    Idempotent: no
    """
    ...

def _eval(
    node: Any,
    ctx: dict,
    st: _EvalState,
) -> Any:
    """
    Internal recursive evaluator with gas and depth metering. Decrements gas, increments depth, delegates to _eval_inner, and restores depth.

    Postconditions:
      - st.depth is restored to original value after evaluation
      - st.gas is decremented by 1

    Errors:
      - gas_exhausted (GasExhausted): st.gas < 0 after decrement
          message: gas budget exceeded
      - depth_exceeded (DepthExceeded): st.depth > MAX_DEPTH (64) after increment
          message: max nesting depth exceeded

    Side effects: Mutates st.gas and st.depth
    Idempotent: no
    """
    ...

def _eval_inner(
    node: Any,
    ctx: dict,
    st: _EvalState,
) -> Any:
    """
    Core evaluation logic handling all 20 SPL built-in operations: logical (and, or, not), comparison (=, <=, <, >=, >), sets (member, in, subset?), time (before), accessors (get, tuple), counter (per-day-count), and crypto predicates (dpop_ok?, merkle_ok?, vrf_ok?, thresh_ok?)

    Postconditions:
      - Returns evaluated result based on operation type

    Errors:
      - unknown_operation (SPLError): node[0] does not match any known operation
          message: Unknown op: {op}
      - index_error (IndexError): Insufficient arguments for operation (e.g., 'not' with no args)

    Side effects: May call ctx['per_day_count'] function, May call ctx['crypto'] callbacks (dpop_ok, merkle_ok, vrf_ok, thresh_ok)
    Idempotent: no
    """
    ...

def _resolve_symbol(
    x: Any,
    ctx: dict,
) -> Any:
    """
    Resolve a symbol to its value from context. Handles special symbols (#t, #f, req, now) and variable lookups from ctx['vars']. In strict mode, raises SPLError for unresolved symbols.

    Postconditions:
      - Returns resolved value or original input if not a symbol

    Errors:
      - unresolved_symbol (SPLError): x is a string symbol not in vars and ctx['strict'] is True
          message: Unresolved symbol: {x}

    Side effects: none
    Idempotent: no
    """
    ...

def _truthy(
    v: Any,
) -> bool:
    """
    Convert a value to boolean using SPL truthiness rules: None is false, booleans as-is, numbers are false if zero, all other values are true.

    Postconditions:
      - Returns boolean representation of value

    Side effects: none
    Idempotent: no
    """
    ...

def _to_float(
    x: Any,
) -> float:
    """
    Convert a value to float. Returns 0.0 if conversion fails (TypeError or ValueError).

    Postconditions:
      - Returns float representation, or 0.0 on conversion failure

    Side effects: none
    Idempotent: no
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['GasExhausted', 'DepthExceeded', 'SPLError', '_EvalState', 'eval_policy', '_eval', '_eval_inner', '_resolve_symbol', '_truthy', '_to_float']
