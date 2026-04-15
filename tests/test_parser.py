"""Tests para el parser de Habla."""

import pytest
from habla.lexer import Lexer
from habla.parser import Parser
from habla.ast_nodes import *


def parse(source: str) -> Program:
    tokens = Lexer(source).tokenize()
    return Parser(tokens).parse()


def test_show_statement():
    ast = parse('muestra "hola"')
    assert len(ast.statements) == 1
    stmt = ast.statements[0]
    assert isinstance(stmt, ShowStatement)
    assert isinstance(stmt.value, StringLiteral)
    assert stmt.value.value == '"hola"'


def test_assignment():
    ast = parse("x = 42")
    assert len(ast.statements) == 1
    stmt = ast.statements[0]
    assert isinstance(stmt, Assignment)
    assert stmt.name == "x"
    assert isinstance(stmt.value, NumberLiteral)
    assert stmt.value.value == 42


def test_string_assignment():
    ast = parse('nombre = "Carlos"')
    stmt = ast.statements[0]
    assert isinstance(stmt, Assignment)
    assert stmt.name == "nombre"
    assert isinstance(stmt.value, StringLiteral)


def test_boolean_literals():
    ast = parse("activo = cierto")
    stmt = ast.statements[0]
    assert isinstance(stmt.value, BooleanLiteral)
    assert stmt.value.value is True

    ast2 = parse("inactivo = falso")
    stmt2 = ast2.statements[0]
    assert stmt2.value.value is False


def test_if_statement():
    source = "si x > 0\n  muestra x\n"
    ast = parse(source)
    stmt = ast.statements[0]
    assert isinstance(stmt, IfStatement)
    assert isinstance(stmt.condition, BinaryOp)
    assert len(stmt.then_body) == 1


def test_if_else():
    source = "si x > 0\n  muestra x\nsino\n  muestra 0\n"
    ast = parse(source)
    stmt = ast.statements[0]
    assert isinstance(stmt, IfStatement)
    assert len(stmt.else_body) == 1


def test_for_loop():
    source = "para x en lista\n  muestra x\n"
    ast = parse(source)
    stmt = ast.statements[0]
    assert isinstance(stmt, ForStatement)
    assert stmt.var == "x"
    assert isinstance(stmt.iterable, Identifier)


def test_fn_def():
    source = "fn saludar(nombre)\n  muestra nombre\n"
    ast = parse(source)
    stmt = ast.statements[0]
    assert isinstance(stmt, FunctionDef)
    assert stmt.name == "saludar"
    assert "nombre" in stmt.params


def test_pipe_expression():
    source = "resultado = datos -> filtra donde x > 0\n"
    ast = parse(source)
    stmt = ast.statements[0]
    assert isinstance(stmt, Assignment)
    assert isinstance(stmt.value, PipeExpression)
    assert len(stmt.value.steps) >= 2


def test_http_get():
    source = 'datos = desde "https://api.com"\n'
    ast = parse(source)
    stmt = ast.statements[0]
    assert isinstance(stmt, Assignment)
    assert isinstance(stmt.value, HttpGet)


def test_list_literal():
    source = "ports = [22, 80, 443]"
    ast = parse(source)
    stmt = ast.statements[0]
    assert isinstance(stmt.value, ListLiteral)
    assert len(stmt.value.elements) == 3


def test_binary_ops():
    for op_habla, op_py in [("y", "y"), ("o", "o"), ("es", "es")]:
        source = f"resultado = a {op_habla} b\n"
        ast = parse(source)
        stmt = ast.statements[0]
        assert isinstance(stmt.value, BinaryOp)
        assert stmt.value.op == op_habla


def test_return_statement():
    source = "fn doble(x)\n  devuelve x + x\n"
    ast = parse(source)
    fn = ast.statements[0]
    ret = fn.body[0]
    assert isinstance(ret, ReturnStatement)


def test_cyber_scan():
    source = 'escanea target "192.168.1.1" en ports [22, 80]\n'
    ast = parse(source)
    stmt = ast.statements[0]
    assert isinstance(stmt, ExpressionStatement)
    assert isinstance(stmt.expr, CyberScan)
    assert len(stmt.expr.ports) == 2


def test_multiple_statements():
    source = 'x = 1\ny = 2\nmuestra x + y\n'
    ast = parse(source)
    assert len(ast.statements) == 3
