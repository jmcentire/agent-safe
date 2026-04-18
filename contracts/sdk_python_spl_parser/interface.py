# === SPL S-Expression Parser (sdk_python_spl_parser) v1 ===
#  Dependencies: typing
# Tokenizer and recursive-descent parser for SPL S-expressions. Converts SPL source code strings into abstract syntax trees (AST) consisting of primitives (bool, int, float, str) and nested lists.

# Module invariants:
#   - MAX_POLICY_BYTES = 65536 - Maximum allowed size for policy source in bytes
#   - Tokenization preserves string literals as complete tokens including quotes
#   - Parentheses '(' and ')' are always separate tokens
#   - Boolean literals '#t' and '#f' are converted to Python True and False
#   - Numeric tokens are converted to int or float based on presence of '.'
#   - Quoted strings have their quotes removed and escape sequences processed
#   - All other tokens are treated as symbols (returned as strings)

AST = bool | int | float | str | list[AST]

def tokenize(
    src: str,
) -> list[str]:
    """
    Tokenizes an SPL S-expression source string into a list of string tokens. Handles parentheses, quoted strings, and whitespace-delimited symbols.

    Postconditions:
      - Returns a list of tokens including '(', ')', quoted strings (with quotes), and symbols
      - String literals are preserved as single tokens with quotes intact
      - Whitespace is used to delimit non-string tokens

    Side effects: none
    Idempotent: yes
    """
    ...

def _atom(
    tok: str,
) -> AST:
    """
    Converts a single token string into an atomic AST value. Handles booleans (#t/#f), numbers (int/float), quoted strings, and symbols.

    Postconditions:
      - Returns True for '#t', False for '#f'
      - Returns int for numeric strings without '.', float for numeric strings with '.'
      - Returns unquoted content for strings starting and ending with '"', with '\"' replaced by '"'
      - Returns the token as-is (as str) for all other cases (symbols)

    Side effects: none
    Idempotent: yes
    """
    ...

def parse(
    src: str,
) -> AST:
    """
    Parse an SPL S-expression string into an AST. Enforces a maximum policy size of 64KB (65536 bytes) and validates syntax.

    Preconditions:
      - Source must not exceed 65536 bytes when UTF-8 encoded
      - Source must contain at least one token after stripping whitespace

    Postconditions:
      - Returns a fully parsed AST representing the S-expression
      - All tokens are consumed (no extra tokens remain)
      - Nested lists are represented as Python lists

    Errors:
      - policy_too_large (SyntaxError): len(src.encode('utf-8')) > MAX_POLICY_BYTES (65536)
          message: policy exceeds maximum size of 65536 bytes
      - empty_source (SyntaxError): No tokens after tokenizing and stripping
          message: unexpected EOF
      - unexpected_eof (SyntaxError): Tokens exhausted during parsing
          message: unexpected EOF
      - unterminated_list (SyntaxError): Opening '(' without matching ')'
          message: unterminated (
      - unexpected_close_paren (SyntaxError): Closing ')' without matching '('
          message: unexpected )
      - extra_tokens (SyntaxError): Tokens remain after parsing complete expression
          message: extra tokens

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['AST', 'tokenize', '_atom', 'parse', 'SyntaxError']
