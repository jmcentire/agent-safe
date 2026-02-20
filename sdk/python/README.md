# Agent-Safe SPL — Python SDK

Python implementation of the SPL (Safe Policy Lisp) evaluator for Agent-Safe capability tokens.

## Install

```bash
pip install -e .               # core (zero runtime deps)
pip install -e ".[crypto]"     # with Ed25519/Merkle/hash-chain support
pip install -e ".[dev]"        # with test dependencies
```

## Usage

### As a library

```python
from spl import parse, verify

policy = parse('(and (= (get req "action") "read") (<= (get req "amount") 100))')
request = {"action": "read", "amount": 50}
env = {
    "vars": {},
    "per_day_count": lambda action, day: 0,
    "crypto": {
        "dpop_ok": lambda: True,
        "merkle_ok": lambda t: True,
        "vrf_ok": lambda d, a: True,
        "thresh_ok": lambda: True,
    },
}

result = verify(policy, request, env)
print("ALLOW" if result["allow"] else "DENY")
```

### As a CLI

```bash
python -m spl examples/policies/family_gifts.spl examples/requests/gift_50_niece.json
# → ALLOW
```

## Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Requirements

- Python 3.10+
- Zero runtime dependencies for core evaluator
- `cryptography` package optional for real Ed25519 verification
