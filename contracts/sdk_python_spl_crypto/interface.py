# === SPL Crypto Module (sdk_python_spl_crypto) v1 ===
#  Dependencies: hashlib, hmac, json, typing, cryptography.hazmat.primitives.asymmetric.ed25519, cryptography.hazmat.primitives.serialization
# Real cryptographic implementations for SPL token verification, including SHA-256 hashing, Ed25519 signature verification, Merkle proof verification, HKDF key derivation, and hash chain verification. Ed25519 operations require the optional 'cryptography' package, while hash operations use only stdlib (hashlib, hmac).

# Module invariants:
#   - SHA-256 always produces 32-byte (256-bit) digests
#   - HKDF salt defaults to 32 zero bytes when empty or falsy
#   - HKDF uses fixed salt 'agent-safe-v1' for service key derivation
#   - Ed25519 public keys are 32 bytes
#   - Ed25519 private keys are 32 bytes

def sha256(
    data: bytes,
) -> bytes:
    """
    Computes SHA-256 hash of input data and returns raw digest bytes.

    Postconditions:
      - Returns 32-byte SHA-256 digest

    Side effects: none
    Idempotent: no
    """
    ...

def sha256_hex(
    data: bytes,
) -> str:
    """
    Computes SHA-256 hash of input data and returns hex-encoded string.

    Postconditions:
      - Returns 64-character hex string representing SHA-256 digest

    Side effects: none
    Idempotent: no
    """
    ...

def verify_ed25519(
    message: bytes,
    signature_hex: str,
    public_key_hex: str,
) -> bool:
    """
    Verifies an Ed25519 signature over a message using a public key. Requires the 'cryptography' package to be installed.

    Postconditions:
      - Returns True if signature is valid
      - Returns False if signature is invalid or hex decoding fails

    Errors:
      - cryptography_not_installed (RuntimeError): The 'cryptography' package is not installed
          message: Ed25519 verification requires the 'cryptography' package. Install with: pip install agent-safe-spl[crypto]

    Side effects: none
    Idempotent: no
    """
    ...

def verify_merkle_proof(
    leaf_data: str,
    proof: list[dict[str, str]],
    root_hex: str,
) -> bool:
    """
    Verifies a Merkle proof for leaf_data against an expected root hash. Leaf data is UTF-8 encoded and hashed, then combined with proof steps to reconstruct the root.

    Postconditions:
      - Returns True if computed root matches root_hex
      - Returns False on any exception (invalid hex, missing keys, etc.)

    Side effects: none
    Idempotent: no
    """
    ...

def hash_tuple(
    values: list[Any],
) -> str:
    """
    Hashes a list of values by JSON-serializing them (compact format) and then computing SHA-256 hex digest.

    Preconditions:
      - values must be JSON-serializable

    Postconditions:
      - Returns hex-encoded SHA-256 hash of compact JSON representation

    Side effects: none
    Idempotent: no
    """
    ...

def _hkdf_sha256(
    ikm: bytes,
    salt: bytes,
    info: bytes,
    length: int,
) -> bytes:
    """
    HKDF-SHA256 (RFC 5869) extract-and-expand key derivation function. Uses only stdlib (no external dependencies).

    Postconditions:
      - Returns derived key material of exactly 'length' bytes
      - Uses 32 zero bytes as salt if input salt is empty

    Side effects: none
    Idempotent: no
    """
    ...

def derive_service_key(
    master_key_hex: str,
    service_domain: str,
) -> tuple[str, str]:
    """
    Derives a service-specific Ed25519 keypair using HKDF-SHA256 for unlinkability. Different services see different public keys derived from the same master key. Requires the 'cryptography' package.

    Preconditions:
      - master_key_hex must be valid hex encoding 32 bytes

    Postconditions:
      - Returns tuple of (public_key_hex, private_key_hex)
      - Uses fixed salt 'agent-safe-v1' for HKDF
      - Derives 32-byte seed using HKDF with service_domain as info parameter

    Errors:
      - cryptography_not_installed (ImportError): The 'cryptography' package is not installed
      - invalid_hex (ValueError): master_key_hex is not valid hex

    Side effects: none
    Idempotent: no
    """
    ...

def verify_hash_chain(
    commitment: str,
    preimage_hex: str,
    index: int,
    chain_length: int,
) -> bool:
    """
    Verifies a hash chain receipt by hashing the preimage (chain_length - index) times and comparing to the commitment.

    Postconditions:
      - Returns True if hashing preimage (chain_length - index) times equals commitment
      - Returns False on any exception (invalid hex, etc.)

    Side effects: none
    Idempotent: no
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['sha256', 'sha256_hex', 'verify_ed25519', 'verify_merkle_proof', 'hash_tuple', '_hkdf_sha256', 'derive_service_key', 'ImportError', 'verify_hash_chain']
