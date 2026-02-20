import pytest
from spl.parser import parse


def test_parse_integer():
    assert parse("42") == 42


def test_parse_negative_float():
    assert parse("-3.14") == -3.14


def test_parse_string():
    assert parse('"hello"') == "hello"


def test_parse_bool_true():
    assert parse("#t") is True


def test_parse_bool_false():
    assert parse("#f") is False


def test_parse_symbol():
    assert parse("foo") == "foo"


def test_parse_list():
    ast = parse("(and #t #f)")
    assert isinstance(ast, list)
    assert len(ast) == 3
    assert ast[0] == "and"


def test_parse_nested():
    ast = parse("(and (= 1 2) (> 3 1))")
    assert isinstance(ast, list)
    inner = ast[1]
    assert isinstance(inner, list)
    assert inner[0] == "="


def test_parse_strings_with_spaces():
    ast = parse('(= "hello world" "hello world")')
    assert ast[1] == "hello world"


def test_unterminated_paren():
    with pytest.raises(SyntaxError, match="unterminated"):
        parse("(and #t")


def test_unexpected_close_paren():
    with pytest.raises(SyntaxError, match="unexpected"):
        parse(")")


def test_extra_tokens():
    with pytest.raises(SyntaxError, match="extra tokens"):
        parse("#t #f")
