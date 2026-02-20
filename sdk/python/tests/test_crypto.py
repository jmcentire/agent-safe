import json
from pathlib import Path

import pytest
from spl.crypto import verify_ed25519, verify_merkle_proof, verify_hash_chain, sha256_hex

VECTORS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "examples" / "crypto"


def load_vectors(name: str) -> dict:
    path = VECTORS_DIR / name
    if not path.exists():
        pytest.skip(f"vector file not found: {path}")
    return json.loads(path.read_text())


class TestEd25519:
    def test_valid_signature(self):
        v = load_vectors("ed25519_vectors.json")
        assert verify_ed25519(
            v["message"].encode("utf-8"),
            v["signature_hex"],
            v["public_key_hex"],
        ) is True

    def test_tampered_message(self):
        v = load_vectors("ed25519_vectors.json")
        assert verify_ed25519(
            v["tampered_message"].encode("utf-8"),
            v["signature_hex"],
            v["public_key_hex"],
        ) is False


class TestMerkleProof:
    def test_cases(self):
        v = load_vectors("merkle_vectors.json")
        for tc in v["cases"]:
            # Verify leaf hash
            leaf_hash = sha256_hex(tc["leaf"].encode("utf-8"))
            assert leaf_hash == tc["leaf_hash"], f"{tc['name']}: leaf hash mismatch"

            result = verify_merkle_proof(tc["leaf"], tc["proof"], v["root"])
            assert result == tc["expected"], f"{tc['name']}: expected {tc['expected']}, got {result}"


class TestHashChain:
    def test_cases(self):
        v = load_vectors("hashchain_vectors.json")
        for tc in v["cases"]:
            result = verify_hash_chain(
                v["commitment"],
                tc["preimage"],
                tc["index"],
                v["chain_length"],
            )
            assert result == tc["expected"], f"{tc['name']}: expected {tc['expected']}, got {result}"
