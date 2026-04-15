"""Tests para el lexer de Habla."""

import pytest
from habla.lexer import Lexer, Token, TokenType


def tokenize(source: str):
    return Lexer(source).tokenize()


def token_types(source: str):
    return [(t.type, t.value) for t in tokenize(source) if t.type not in (TokenType.NEWLINE, TokenType.EOF)]


def test_keywords():
    tokens = token_types("si sino mientras para fn devuelve muestra")
    types = [t for t, _ in tokens]
    assert all(t == TokenType.KEYWORD for t in types)


def test_cyber_keywords():
    tokens = token_types("escanea busca captura ataca analiza genera")
    types = [t for t, _ in tokens]
    assert all(t == TokenType.KEYWORD for t in types)


def test_identifier():
    tokens = token_types("mi_variable x resultado")
    assert all(t == TokenType.IDENTIFIER for t, _ in tokens)


def test_numbers():
    tokens = token_types("42 3.14 0")
    types = [t for t, _ in tokens]
    assert all(t == TokenType.NUMBER for t in types)


def test_string_double_quote():
    tokens = token_types('"hola mundo"')
    assert tokens == [(TokenType.STRING, '"hola mundo"')]


def test_string_single_quote():
    tokens = token_types("'hola'")
    assert tokens == [(TokenType.STRING, "'hola'")]


def test_pipe_operator():
    tokens = token_types("->")
    assert tokens == [(TokenType.PIPE, "->")]


def test_comparison_operators():
    for op in ["==", "!=", ">=", "<=", ">", "<"]:
        tokens = token_types(op)
        assert tokens == [(TokenType.OPERATOR, op)], f"Failed for {op}"


def test_arithmetic_operators():
    for op in ["+", "-", "*", "/"]:
        tokens = token_types(op)
        assert tokens == [(TokenType.OPERATOR, op)]


def test_assignment():
    tokens = token_types("x = 5")
    assert tokens[0] == (TokenType.IDENTIFIER, "x")
    assert tokens[1] == (TokenType.OPERATOR, "=")
    assert tokens[2] == (TokenType.NUMBER, "5")


def test_brackets():
    tokens = token_types("[1, 2, 3]")
    assert tokens[0] == (TokenType.LBRACKET, "[")
    assert tokens[-1] == (TokenType.RBRACKET, "]")


def test_indent_dedent():
    source = "si cierto\n  muestra x\n"
    toks = tokenize(source)
    types = [t.type for t in toks]
    assert TokenType.INDENT in types
    assert TokenType.DEDENT in types


def test_nested_indent():
    source = "si cierto\n  si falso\n    muestra x\n"
    toks = tokenize(source)
    indents = [t for t in toks if t.type == TokenType.INDENT]
    dedents = [t for t in toks if t.type == TokenType.DEDENT]
    assert len(indents) == 2
    assert len(dedents) == 2


def test_comment_skipped():
    source = "x = 1\n// este es un comentario\ny = 2"
    tokens = token_types(source)
    values = [v for _, v in tokens]
    assert "este es un comentario" not in str(values)
    assert "x" in values
    assert "y" in values


def test_eof_at_end():
    toks = tokenize("x = 1")
    assert toks[-1].type == TokenType.EOF


def test_boolean_literals():
    tokens = token_types("cierto falso")
    assert all(t == TokenType.KEYWORD for t, _ in tokens)
    assert tokens[0][1] == "cierto"
    assert tokens[1][1] == "falso"
