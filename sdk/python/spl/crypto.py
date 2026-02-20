"""Real crypto implementations for SPL token verification.

Ed25519: requires `cryptography` package (optional dependency).
Merkle/hash-chain: uses stdlib hashlib only.
"""

import hashlib
import json
from typing import Any


def sha256(data: bytes) -> bytes:
    """SHA-256 hash of data."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """SHA-256 hash of data as hex string."""
    return hashlib.sha256(data).hexdigest()


def verify_ed25519(message: bytes, signature_hex: str, public_key_hex: str) -> bool:
    """Verify an Ed25519 signature over a message.

    Requires the `cryptography` package.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        public_key.verify(sig_bytes, message)
        return True
    except ImportError:
        raise RuntimeError(
            "Ed25519 verification requires the 'cryptography' package. "
            "Install with: pip install agent-safe-spl[crypto]"
        )
    except Exception:
        return False


def verify_merkle_proof(
    leaf_data: str,
    proof: list[dict[str, str]],
    root_hex: str,
) -> bool:
    """Verify a Merkle proof for leaf_data against root_hex.

    Args:
        leaf_data: The leaf value (will be SHA-256 hashed)
        proof: List of {"hash": hex, "position": "left"|"right"}
        root_hex: Expected root hash in hex
    """
    try:
        current = sha256(leaf_data.encode("utf-8"))

        for step in proof:
            sibling = bytes.fromhex(step["hash"])
            if step["position"] == "right":
                current = sha256(current + sibling)
            else:
                current = sha256(sibling + current)

        return current.hex() == root_hex
    except Exception:
        return False


def hash_tuple(values: list[Any]) -> str:
    """Hash a tuple by JSON-serializing then SHA-256."""
    serialized = json.dumps(values, separators=(",", ":"))
    return sha256_hex(serialized.encode("utf-8"))


def verify_hash_chain(
    commitment: str,
    preimage_hex: str,
    index: int,
    chain_length: int,
) -> bool:
    """Verify a hash chain receipt.

    Hashes preimage_hex (chain_length - index) times and checks
    it equals the commitment.
    """
    try:
        current = bytes.fromhex(preimage_hex)
        steps = chain_length - index

        for _ in range(steps):
            current = sha256(current)

        return current.hex() == commitment
    except Exception:
        return False
