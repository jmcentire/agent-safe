import json
from pathlib import Path

import pytest
from spl.parser import parse
from spl.verifier import verify

EXAMPLES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "examples"


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


@pytest.fixture
def policy_ast():
    policy_path = EXAMPLES_DIR / "policies" / "family_gifts.spl"
    if not policy_path.exists():
        pytest.skip("example files not found")
    return parse(policy_path.read_text().strip())


@pytest.fixture
def request_data():
    req_path = EXAMPLES_DIR / "requests" / "gift_50_niece.json"
    if not req_path.exists():
        pytest.skip("example files not found")
    return json.loads(req_path.read_text())


def test_family_gifts_allow(policy_ast, request_data):
    env = make_env()
    result = verify(policy_ast, request_data, env)
    assert result["allow"] is True


def test_family_gifts_deny_high_amount(policy_ast, request_data):
    request_data["amount"] = 100
    env = make_env()
    result = verify(policy_ast, request_data, env)
    assert result["allow"] is False
