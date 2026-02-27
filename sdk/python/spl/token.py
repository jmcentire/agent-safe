"""Token minting and verification for Agent-Safe capability tokens.

Ed25519 signing requires the `cryptography` package:
    pip install agent-safe-spl[crypto]
"""

import json
from datetime import datetime, timezone
from typing import Any, Optional

from .parser import parse
from .evaluator import eval_policy
from .crypto import verify_ed25519, sha256


def generate_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair.

    Returns:
        (public_key_hex, private_key_hex)

    Requires the `cryptography` package.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption,
    )

    private_key = Ed25519PrivateKey.generate()
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    # Extract the 32-byte seed from PKCS8 DER
    priv_der = private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    priv_seed = priv_der[-32:]  # Last 32 bytes of PKCS8 DER is the seed
    return pub_bytes.hex(), priv_seed.hex()


def signing_payload(
    policy: str,
    merkle_root: Optional[str] = None,
    hash_chain_commitment: Optional[str] = None,
    sealed: bool = False,
    expires: Optional[str] = None,
) -> bytes:
    """Build the canonical signing payload for a token.

    Covers all security-relevant fields so sealed, expires, merkle_root, and
    hash_chain_commitment cannot be tampered with after signing.
    """
    parts = [
        policy.strip(),
        merkle_root or "",
        hash_chain_commitment or "",
        "1" if sealed else "0",
        expires or "",
    ]
    return "\0".join(parts).encode("utf-8")


def create_presentation_signature(token: dict, agent_private_key_hex: str) -> str:
    """Create a PoP presentation signature for a token.

    The agent signs SHA-256(signing_payload) with its own Ed25519 key.

    Returns:
        Hex-encoded presentation signature
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    payload = signing_payload(
        token["policy"],
        token.get("merkle_root"),
        token.get("hash_chain_commitment"),
        token.get("sealed", False),
        token.get("expires"),
    )
    pop_payload = sha256(payload)

    seed = bytes.fromhex(agent_private_key_hex)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    sig = private_key.sign(pop_payload)
    return sig.hex()


def mint(
    policy: str,
    private_key_hex: str,
    *,
    merkle_root: Optional[str] = None,
    hash_chain_commitment: Optional[str] = None,
    sealed: bool = False,
    expires: Optional[str] = None,
    pop_key: Optional[str] = None,
) -> dict[str, Any]:
    """Mint a signed capability token.

    Args:
        policy: SPL policy source string
        private_key_hex: Hex-encoded Ed25519 private key (32-byte seed)
        merkle_root: Optional Merkle root hex
        hash_chain_commitment: Optional hash chain commitment hex
        sealed: Whether the token is sealed (prevents further attenuation)
        expires: Optional ISO 8601 expiration timestamp

    Returns:
        Token dict with signature

    Requires the `cryptography` package.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    seed = bytes.fromhex(private_key_hex)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    payload = signing_payload(policy, merkle_root, hash_chain_commitment, sealed, expires)
    signature = private_key.sign(payload)

    token = {
        "version": "0.1.0",
        "policy": policy.strip(),
        "sealed": sealed,
        "public_key": pub_bytes.hex(),
        "signature": signature.hex(),
    }
    if merkle_root:
        token["merkle_root"] = merkle_root
    if hash_chain_commitment:
        token["hash_chain_commitment"] = hash_chain_commitment
    if expires:
        token["expires"] = expires
    if pop_key:
        token["pop_key"] = pop_key

    return token


def verify_token(
    token: dict | str,
    req: dict[str, Any],
    *,
    vars: Optional[dict[str, Any]] = None,
    per_day_count: Any = None,
    crypto: Optional[dict] = None,
    now: Optional[str] = None,
    presentation_signature: Optional[str] = None,
) -> dict[str, Any]:
    """Verify a token's signature and evaluate its policy.

    Args:
        token: Token dict or JSON string
        req: Request dict
        vars: Host variables (e.g. allowed_recipients)
        per_day_count: Callback(action, day) -> int
        crypto: Dict of crypto callbacks (dpop_ok, merkle_ok, vrf_ok, thresh_ok)
        now: Current time as ISO 8601 string (defaults to now)

    Returns:
        {"allow": bool, "sealed": bool, "error": str | None}
    """
    if isinstance(token, str):
        token = json.loads(token)

    t = token
    sealed = t.get("sealed", False)

    # Check expiration
    if t.get("expires"):
        exp = datetime.fromisoformat(t["expires"])
        current = datetime.fromisoformat(now) if now else datetime.now(timezone.utc)
        if hasattr(current, 'tzinfo') and current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        if hasattr(exp, 'tzinfo') and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if current > exp:
            return {"allow": False, "sealed": sealed, "error": "token expired"}

    # Verify signature over full token envelope
    payload = signing_payload(
        t["policy"],
        t.get("merkle_root"),
        t.get("hash_chain_commitment"),
        sealed,
        t.get("expires"),
    )
    if not verify_ed25519(payload, t["signature"], t["public_key"]):
        return {"allow": False, "sealed": sealed, "error": "invalid signature"}

    # PoP binding: if token has pop_key, require and verify presentation signature
    if t.get("pop_key"):
        if not presentation_signature:
            return {"allow": False, "sealed": sealed, "error": "PoP binding requires presentation signature"}
        pop_payload = sha256(payload)
        if not verify_ed25519(pop_payload, presentation_signature, t["pop_key"]):
            return {"allow": False, "sealed": sealed, "error": "invalid presentation signature"}

    # Parse and evaluate
    ast = parse(t["policy"])

    ctx_vars = dict(vars or {})
    if now:
        ctx_vars["now"] = now

    ctx = {
        "req": req,
        "vars": ctx_vars,
        "now": now or datetime.now(timezone.utc).isoformat(),
        "per_day_count": per_day_count or (lambda _a, _d: 0),
        "crypto": crypto or {},
    }

    result = eval_policy(ast, ctx)
    allow = bool(result) if result is not None else False

    return {"allow": allow, "sealed": sealed}
