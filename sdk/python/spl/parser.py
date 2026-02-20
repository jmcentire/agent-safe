"""Tokenizer and recursive-descent parser for SPL S-expressions."""

from typing import Any

# AST type: bool | int | float | str | list[AST]
AST = Any


def tokenize(src: str) -> list[str]:
    tokens: list[str] = []
    buf = ""
    in_str = False
    for ch in src:
        if in_str:
            buf += ch
            if ch == '"':
                in_str = False
                tokens.append(buf)
                buf = ""
            continue
        if ch == '"':
            if buf.strip():
                tokens.extend(buf.strip().split())
            buf = '"'
            in_str = True
            continue
        if ch in ("(", ")"):
            if buf.strip():
                tokens.extend(buf.strip().split())
            tokens.append(ch)
            buf = ""
            continue
        buf += ch
    if buf.strip():
        tokens.extend(buf.strip().split())
    return tokens


def _atom(tok: str) -> AST:
    if tok == "#t":
        return True
    if tok == "#f":
        return False
    # Try number
    try:
        if "." in tok:
            return float(tok)
        return int(tok) if tok.lstrip("-").isdigit() else float(tok)
    except (ValueError, AttributeError):
        pass
    # Quoted string
    if tok.startswith('"') and tok.endswith('"'):
        return tok[1:-1].replace('\\"', '"')
    # Symbol (returned as string)
    return tok


def parse(src: str) -> AST:
    """Parse an SPL S-expression string into an AST."""
    tokens = tokenize(src.strip())
    if not tokens:
        raise SyntaxError("unexpected EOF")
    pos = [0]  # mutable index

    def _parse() -> AST:
        if pos[0] >= len(tokens):
            raise SyntaxError("unexpected EOF")
        tok = tokens[pos[0]]
        pos[0] += 1
        if tok == "(":
            arr: list[AST] = []
            while True:
                if pos[0] >= len(tokens):
                    raise SyntaxError("unterminated (")
                if tokens[pos[0]] == ")":
                    pos[0] += 1
                    break
                arr.append(_parse())
            return arr
        if tok == ")":
            raise SyntaxError("unexpected )")
        return _atom(tok)

    result = _parse()
    if pos[0] != len(tokens):
        raise SyntaxError("extra tokens")
    return result
