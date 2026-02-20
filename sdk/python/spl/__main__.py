"""CLI: python -m spl <policy.spl> <request.json>"""

import json
import sys
from pathlib import Path

from .parser import parse
from .verifier import verify


def main():
    if len(sys.argv) < 3:
        print("Usage: python -m spl <policy.spl> <request.json>", file=sys.stderr)
        sys.exit(1)

    policy_path = Path(sys.argv[1])
    request_path = Path(sys.argv[2])

    policy_src = policy_path.read_text().strip()
    ast = parse(policy_src)

    req = json.loads(request_path.read_text())

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

    result = verify(ast, req, env)
    print("ALLOW" if result["allow"] else "DENY")


if __name__ == "__main__":
    main()
