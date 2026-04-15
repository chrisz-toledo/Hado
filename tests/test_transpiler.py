"""Tests para el transpiler de Hado (los cuatro backends: Python, Go, Rust, C)."""

import ast as pyast
import pytest
from hado.runtime import compile_to_source


def py(source: str) -> str:
    return compile_to_source(source, target="python")


def c(source: str) -> str:
    return compile_to_source(source, target="c")


def rs(source: str) -> str:
    return compile_to_source(source, target="rust")


def is_valid_python(code: str) -> bool:
    try:
        pyast.parse(code)
        return True
    except SyntaxError:
        return False


# ─── Python backend ───────────────────────────────────────────────────────────

class TestPythonBackend:

    def test_show(self):
        code = py('muestra "hola"')
        assert "print" in code
        assert "hola" in code
        assert is_valid_python(code)

    def test_assignment(self):
        code = py("x = 42")
        assert "x = 42" in code
        assert is_valid_python(code)

    def test_if_statement(self):
        code = py("si x > 0\n  muestra x\n")
        assert "if x > 0:" in code
        assert "print(x)" in code
        assert is_valid_python(code)

    def test_if_else(self):
        code = py("si x > 0\n  muestra x\nsino\n  muestra 0\n")
        assert "else:" in code
        assert is_valid_python(code)

    def test_for_loop(self):
        code = py("para x en lista\n  muestra x\n")
        assert "for x in lista:" in code
        assert is_valid_python(code)

    def test_fn_def(self):
        code = py("fn saludar(nombre)\n  muestra nombre\n")
        assert "def saludar(nombre):" in code
        assert is_valid_python(code)

    def test_boolean_translation(self):
        code = py("x = cierto")
        assert "True" in code

        code2 = py("y = falso")
        assert "False" in code2

    def test_null_translation(self):
        code = py("x = nulo")
        assert "None" in code

    def test_and_or_not(self):
        code = py("x = a y b\n")
        assert "and" in code

        code2 = py("x = a o b\n")
        assert "or" in code2

        code3 = py("x = no a\n")
        assert "not" in code3

    def test_http_get(self):
        code = py('datos = desde "https://api.com"\n')
        assert "requests.get" in code
        assert "import requests" in code
        assert is_valid_python(code)

    def test_cyber_scan_imports(self):
        code = py('escanea target "127.0.0.1" en ports [22, 80]\n')
        assert "_hado_scan" in code
        assert "from hado.cybersec.scanner import scan as _hado_scan" in code
        assert is_valid_python(code)

    def test_cyber_recon(self):
        code = py('busca subdomains de "example.com"\n')
        assert "_hado_find_subdomains" in code
        assert is_valid_python(code)

    def test_pipe_chain(self):
        code = py("resultado = datos -> filtra donde x > 0\n")
        assert "_pipe_" in code or "resultado" in code
        assert is_valid_python(code)

    def test_list_literal(self):
        code = py("ports = [22, 80, 443]")
        assert "[22, 80, 443]" in code
        assert is_valid_python(code)

    def test_return(self):
        code = py("fn doble(x)\n  devuelve x + x\n")
        assert "return x + x" in code
        assert is_valid_python(code)

    def test_string_preserved(self):
        # Strings con tildes deben preservarse
        code = py('muestra "Año nuevo"')
        assert '"Año nuevo"' in code

    def test_complete_program(self):
        source = """
nombre = "Hado"
version = 1
muestra "Lenguaje: " + nombre
si version >= 1
  muestra "Version estable"
sino
  muestra "Version beta"
"""
        code = py(source)
        assert is_valid_python(code)


# ─── C backend ───────────────────────────────────────────────────────────────

class TestCBackend:

    def test_show(self):
        code = c('muestra "hola"')
        assert "printf" in code
        assert "hola" in code

    def test_includes(self):
        code = c('muestra "test"')
        assert "#include <stdio.h>" in code

    def test_cyber_scan_includes(self):
        code = c('escanea target "127.0.0.1" en ports [22, 80]\n')
        assert "#include <sys/socket.h>" in code
        assert "hado_scan_port" in code

    def test_if_statement(self):
        code = c("si x > 0\n  muestra x\n")
        assert "if" in code
        assert "{" in code

    def test_boolean_values(self):
        code = c("x = cierto")
        assert "1" in code

        code2 = c("y = falso")
        assert "0" in code2

    def test_wraps_in_main(self):
        code = c('muestra "test"')
        assert "int main" in code


# ─── Rust backend ─────────────────────────────────────────────────────────────

class TestRustBackend:

    def test_show(self):
        code = rs('muestra "hola"')
        assert "println!" in code
        assert "hola" in code

    def test_let_assignment(self):
        code = rs("x = 42")
        assert "let" in code
        assert "42" in code

    def test_if_statement(self):
        code = rs("si x > 0\n  muestra x\n")
        assert "if" in code
        assert "{" in code

    def test_cyber_scan(self):
        code = rs('escanea target "127.0.0.1" en ports [22, 80]\n')
        # v0.5+: Tokio async — TcpStream está dentro de scan_ports()
        assert "TcpStream" in code
        assert "scan_ports" in code
        assert "tokio" in code

    def test_wraps_in_main(self):
        code = rs('muestra "test"')
        assert "fn main" in code

    def test_boolean_values(self):
        code = rs("x = cierto")
        assert "true" in code

        code2 = rs("y = falso")
        assert "false" in code2


def go(source: str) -> str:
    return compile_to_source(source, target="go")


# ─── Go backend (stub) ────────────────────────────────────────────────────────

class TestGoBackend:
    def test_package_main(self):
        code = go('muestra "hola"')
        assert "package main" in code

    def test_fmt_import(self):
        code = go('muestra "hola"')
        assert '"fmt"' in code

    def test_show_uses_println(self):
        code = go('muestra "hola go"')
        assert "fmt.Println" in code
        assert "hola go" in code

    def test_assignment_uses_walrus(self):
        code = go("x = 42")
        assert "x :=" in code
        assert "42" in code

    def test_if_uses_braces(self):
        code = go("si x > 0\n  muestra x\n")
        assert "if x > 0 {" in code
        assert "}" in code

    def test_for_range(self):
        code = go("para x en lista\n  muestra x\n")
        assert "range lista" in code
        assert "fmt.Println" in code

    def test_boolean_go_syntax(self):
        code = go("x = cierto")
        assert "true" in code
        code2 = go("y = falso")
        assert "false" in code2

    def test_wraps_in_main(self):
        code = go('muestra "test"')
        assert "func main()" in code

    def test_cyber_scan_generates_real_code(self):
        # Fase 4: ya no genera stub — genera codigo real con goroutines
        code = go('escanea target "127.0.0.1" en ports [22, 80]\n')
        assert "hado_scan(" in code
        assert "func hado_scan(" in code
        assert "sync.WaitGroup" in code

    def test_logical_operators_go(self):
        code = go("si x > 0 y y < 10\n  muestra x\n")
        assert "&&" in code

    def test_targets_registry(self):
        from hado.backends import TARGETS
        assert "python" in TARGETS
        assert "go" in TARGETS
        assert "rust" in TARGETS
        assert "c" in TARGETS
        assert TARGETS["go"]["status"] == "funcional"
        assert TARGETS["python"]["status"] == "funcional"

    def test_base_backend_interface(self):
        from hado.backends.base import HadoBackend, list_backends
        backends = list_backends()
        assert "go" in backends
        assert "python" in backends
        assert backends["go"]["extension"] == ".go"
        assert backends["python"]["compile_cmd"] is None
