# === SPL CLI Main Entry Point (sdk_python_spl___main__) v1 ===
#  Dependencies: json, sys, pathlib.Path, .parser.parse, .verifier.verify
# CLI entry point for the SPL (Security Policy Language) interpreter. Parses a policy file and evaluates it against a request JSON file, outputting ALLOW or DENY decisions.

# Module invariants:
#   - Environment dictionary has fixed structure with 'vars', 'now', 'per_day_count', and 'crypto' keys
#   - allowed_recipients is always ['niece@example.com', 'mom@example.com']
#   - now is always hardcoded to '2025-10-01T00:00:00Z'
#   - per_day_count lambda always returns 0
#   - All crypto validation lambdas (dpop_ok, merkle_ok, vrf_ok, thresh_ok) always return True

def main() -> None:
    """
    Main CLI function that reads a policy file and request JSON from command-line arguments, parses the policy, verifies it against the request with a hardcoded environment, and prints ALLOW or DENY to stdout.

    Preconditions:
      - sys.argv must contain at least 3 elements (program name + 2 arguments)
      - sys.argv[1] must be a valid path to a readable .spl file
      - sys.argv[2] must be a valid path to a readable .json file
      - The policy file must contain parseable SPL syntax
      - The request file must contain valid JSON
      - The verify result must be a dict-like object with an 'allow' key

    Postconditions:
      - Prints 'ALLOW' or 'DENY' to stdout based on verification result
      - Does not return (implicitly returns None)

    Errors:
      - InsufficientArguments (SystemExit): len(sys.argv) < 3
          exit_code: 1
          message: Usage: python -m spl <policy.spl> <request.json>
      - PolicyFileNotFound (FileNotFoundError): sys.argv[1] does not exist or is not readable
      - RequestFileNotFound (FileNotFoundError): sys.argv[2] does not exist or is not readable
      - InvalidJSON (json.JSONDecodeError): request file does not contain valid JSON
      - ParseError (Exception): policy file contains invalid SPL syntax
          source: parse function
      - VerificationError (Exception): verify function raises an exception
          source: verify function
      - KeyError (KeyError): verify result does not contain 'allow' key
          key: allow

    Side effects: Reads file from sys.argv[1] (policy file), Reads file from sys.argv[2] (request file), Writes usage message to stderr if argument count < 3, Calls sys.exit(1) if argument count < 3, Writes ALLOW or DENY to stdout
    Idempotent: no
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['main', 'SystemExit']
