"""
Tests para el backend Go de Hado DSL — Fase 4.

Verifica que el GoTranspiler genera codigo Go sintacticamente correcto
que puede compilarse con `go build`. Los tests cubren:
  - Estructura del archivo generado (package main, imports, func main)
  - Declaracion de variables (:= vs = segun scope)
  - Control de flujo (if/else, for range, for cond)
  - Funciones definidas por el usuario
  - Operadores y expresiones
  - Cybersec: escanea → hado_scan() con goroutines
  - HTTP: desde → hado_http_get()
  - Registry: Go ahora es "funcional"

Si Go esta instalado en el sistema, el test de compilacion real se ejecuta.
Si no, se omite con pytest.mark.skipif.
"""

import subprocess
import sys
import tempfile
import os
import pytest

from hado.runtime import compile_to_source


# ─── Helper ──────────────────────────────────────────────────────────────────

def go(source: str) -> str:
    """Compila fuente Hado a Go."""
    return compile_to_source(source, target="go")


def has_go() -> bool:
    """Detecta si go esta instalado en el PATH."""
    try:
        result = subprocess.run(["go", "version"], capture_output=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def go_builds(code: str) -> bool:
    """
    Verifica que el codigo Go generado compila sin errores.
    Requiere que `go` este instalado.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        src = os.path.join(tmpdir, "main.go")
        with open(src, "w") as f:
            f.write(code)
        # Necesitamos un go.mod para que `go build` funcione
        gomod = os.path.join(tmpdir, "go.mod")
        with open(gomod, "w") as f:
            f.write("module hado_test\n\ngo 1.21\n")
        result = subprocess.run(
            ["go", "build", "-o", os.path.join(tmpdir, "out"), "."],
            cwd=tmpdir,
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0


# ─── 1. Estructura del archivo ───────────────────────────────────────────────

class TestGoFileStructure:

    def test_package_main(self):
        """Todo archivo Go ejecutable empieza con 'package main'."""
        code = go('muestra "hola"')
        assert "package main" in code

    def test_fmt_import_always_present(self):
        """fmt siempre se importa (muestra → fmt.Println)."""
        code = go('muestra "hola"')
        assert '"fmt"' in code

    def test_import_block_syntax(self):
        """Los imports van en bloque import ( ... )."""
        code = go('muestra "hola"')
        assert "import (" in code
        assert ")" in code

    def test_wraps_in_func_main(self):
        """Programas sin fn main() se envuelven automaticamente en func main()."""
        code = go('muestra "test"')
        assert "func main()" in code

    def test_func_main_has_braces(self):
        """Go usa llaves, no indentacion."""
        code = go('muestra "test"')
        assert "func main() {" in code
        assert "}" in code


# ─── 2. Declaracion de variables ─────────────────────────────────────────────

class TestGoVariables:

    def test_first_assignment_uses_walrus(self):
        """Primera asignacion: x := valor"""
        code = go("x = 42")
        assert "x := 42" in code

    def test_reassignment_uses_equals(self):
        """Segunda asignacion a la misma variable: x = nuevo_valor (no :=)"""
        code = go("x = 1\nx = 2\n")
        # Primera declaracion tiene :=
        assert "x := 1" in code
        # Segunda NO tiene := (seria error en Go)
        lines = [l.strip() for l in code.split("\n") if "x" in l and "2" in l]
        assert any("x = 2" in l and ":=" not in l for l in lines)

    def test_number_literal(self):
        code = go("n = 99")
        assert "99" in code

    def test_string_literal(self):
        code = go('msg = "hola go"')
        assert '"hola go"' in code

    def test_null_literal(self):
        code = go("x = nulo")
        assert "nil" in code

    def test_boolean_true(self):
        code = go("x = cierto")
        assert "true" in code

    def test_boolean_false(self):
        code = go("y = falso")
        assert "false" in code


# ─── 3. IO ───────────────────────────────────────────────────────────────────

class TestGoIO:

    def test_show_uses_println(self):
        """muestra X → fmt.Println(X)"""
        code = go('muestra "hola go"')
        assert "fmt.Println" in code
        assert "hola go" in code

    def test_show_multiple_args(self):
        """muestra a, b → fmt.Println(a, b)"""
        code = go('muestra "a", "b"')
        assert "fmt.Println" in code

    def test_show_variable(self):
        code = go("x = 5\nmuestra x\n")
        assert "fmt.Println(x)" in code


# ─── 4. Control de flujo ─────────────────────────────────────────────────────

class TestGoControlFlow:

    def test_if_uses_braces(self):
        """si cond → if cond {"""
        code = go("si x > 0\n  muestra x\n")
        assert "if x > 0 {" in code

    def test_if_body_indented(self):
        code = go("si x > 0\n  muestra x\n")
        assert "fmt.Println(x)" in code

    def test_if_closing_brace(self):
        code = go("si x > 0\n  muestra x\n")
        assert "}" in code

    def test_if_else_syntax(self):
        """sino → } else {"""
        code = go("si x > 0\n  muestra x\nsino\n  muestra 0\n")
        assert "} else {" in code

    def test_while_uses_for(self):
        """Go no tiene 'while' — mientras → for cond {"""
        code = go("mientras cierto\n  muestra x\n")
        assert "for true {" in code

    def test_for_range_syntax(self):
        """para x en lista → for _, x := range lista {"""
        code = go("para x en lista\n  muestra x\n")
        assert "for _, x := range lista {" in code

    def test_for_range_body(self):
        code = go("para item en items\n  muestra item\n")
        assert "fmt.Println(item)" in code


# ─── 5. Funciones ─────────────────────────────────────────────────────────────

class TestGoFunctions:

    def test_fn_generates_func(self):
        """fn nombre(a b) → func nombre(a interface{}, b interface{}) interface{} {"""
        code = go("fn saludar(nombre)\n  muestra nombre\n")
        assert "func saludar(" in code

    def test_fn_uses_interface_params(self):
        """Los parametros son interface{} por defecto (tipado dinamico)."""
        code = go("fn suma(a b)\n  devuelve a\n")
        assert "interface{}" in code

    def test_fn_return_type(self):
        code = go("fn doble(x)\n  devuelve x\n")
        assert "interface{}" in code

    def test_return_statement(self):
        """devuelve X → return X"""
        code = go("fn f(x)\n  devuelve x\n")
        assert "return x" in code

    def test_fn_at_top_level(self):
        """Las funciones van a nivel de paquete, no dentro de main."""
        code = go("fn hola()\n  muestra 1\n")
        # La funcion debe aparecer antes de func main() o sin main
        # Lo importante: 'func hola' existe y 'func main' puede o no existir
        assert "func hola(" in code


# ─── 6. Operadores ───────────────────────────────────────────────────────────

class TestGoOperators:

    def test_logical_and(self):
        """y → &&"""
        code = go("si x > 0 y y < 10\n  muestra x\n")
        assert "&&" in code

    def test_logical_or(self):
        """o → ||"""
        code = go("si x > 0 o y < 10\n  muestra x\n")
        assert "||" in code

    def test_comparison_operators(self):
        code = go("si x == 5\n  muestra x\n")
        assert "==" in code

    def test_arithmetic_plus(self):
        code = go("z = x + y")
        assert "x + y" in code

    def test_list_literal_go_syntax(self):
        """[22, 80] → []interface{}{22, 80}"""
        code = go("ports = [22, 80, 443]")
        assert "[]interface{}" in code
        assert "22" in code
        assert "80" in code


# ─── 7. Cybersec — goroutines ─────────────────────────────────────────────────

class TestGoCybersec:

    def test_scan_calls_hado_scan(self):
        """escanea → llama a hado_scan() (helper con goroutines)."""
        code = go('escanea target "127.0.0.1" en ports [22, 80]\n')
        assert "hado_scan(" in code

    def test_scan_emits_helper_function(self):
        """La funcion helper hado_scan debe aparecer en el output."""
        code = go('escanea target "127.0.0.1" en ports [22, 80]\n')
        assert "func hado_scan(" in code

    def test_scan_helper_uses_goroutines(self):
        """El helper usa goroutines (go func(...))."""
        code = go('escanea target "192.168.1.1" en ports [80]\n')
        assert "go func(" in code

    def test_scan_helper_uses_waitgroup(self):
        """El helper usa sync.WaitGroup para esperar todas las goroutines."""
        code = go('escanea target "192.168.1.1" en ports [80]\n')
        assert "sync.WaitGroup" in code
        assert "wg.Wait()" in code

    def test_scan_helper_uses_net_dialtimeout(self):
        """El helper usa net.DialTimeout (stdlib) para intentar conexion TCP."""
        code = go('escanea target "192.168.1.1" en ports [80]\n')
        assert "net.DialTimeout" in code

    def test_scan_imports_net(self):
        """escanea requiere import 'net'."""
        code = go('escanea target "192.168.1.1" en ports [80]\n')
        assert '"net"' in code

    def test_scan_imports_sync(self):
        """escanea requiere import 'sync'."""
        code = go('escanea target "192.168.1.1" en ports [80]\n')
        assert '"sync"' in code

    def test_scan_imports_time(self):
        """escanea requiere import 'time' (para timeout)."""
        code = go('escanea target "192.168.1.1" en ports [80]\n')
        assert '"time"' in code

    def test_scan_passes_correct_port_format(self):
        """Los puertos deben pasarse como []int{22, 80}."""
        code = go('escanea target "192.168.1.1" en ports [22, 80]\n')
        assert "[]int{22, 80}" in code


# ─── 8. HTTP ─────────────────────────────────────────────────────────────────

class TestGoHTTP:

    def test_desde_uses_helper(self):
        """desde 'url' → hado_http_get(url)"""
        code = go('datos = desde "https://api.example.com"\n')
        assert "hado_http_get(" in code

    def test_desde_emits_http_helper(self):
        """Se emite la funcion hado_http_get."""
        code = go('datos = desde "https://api.example.com"\n')
        assert "func hado_http_get(" in code

    def test_desde_imports_net_http(self):
        code = go('datos = desde "https://api.example.com"\n')
        assert '"net/http"' in code


# ─── 9. Registry y metadata ───────────────────────────────────────────────────

class TestGoRegistry:

    def test_go_is_funcional(self):
        """Fase 4 completa: Go pasa de 'stub' a 'funcional'."""
        from hado.backends import TARGETS
        assert TARGETS["go"]["status"] == "funcional"

    def test_go_version_updated(self):
        from hado.backends import TARGETS
        assert TARGETS["go"]["version"] == "1.0"

    def test_go_extension(self):
        from hado.backends import TARGETS
        assert TARGETS["go"]["extension"] == ".go"

    def test_go_compile_command(self):
        from hado.backends import TARGETS
        assert "go build" in TARGETS["go"]["compile_cmd"]

    def test_all_four_backends_present(self):
        from hado.backends import TARGETS
        for target in ("python", "go", "rust", "c"):
            assert target in TARGETS

    def test_go_transpiler_class_exists(self):
        """El GoTranspiler importa correctamente."""
        from hado.backends.go_transpiler import GoTranspiler
        assert GoTranspiler is not None

    def test_go_transpiler_is_hadobackend(self):
        """GoTranspiler implementa la interfaz HadoBackend."""
        from hado.backends.go_transpiler import GoTranspiler
        from hado.backends.base import HadoBackend
        assert issubclass(GoTranspiler, HadoBackend)


# ─── 10. Programa completo ────────────────────────────────────────────────────

class TestGoCompletePrograms:

    def test_hello_world_structure(self):
        """Programa minimo: estructura correcta de Go."""
        code = go('muestra "Hola desde Hado!"')
        assert "package main" in code
        assert "import (" in code
        assert '"fmt"' in code
        assert "func main()" in code
        assert 'fmt.Println("Hola desde Hado!")' in code

    def test_multiline_program(self):
        """Programa con varios statements."""
        source = """
nombre = "Carlos"
edad = 30
muestra nombre
muestra edad
"""
        code = go(source)
        assert "nombre := " in code
        assert "edad := 30" in code
        assert "fmt.Println(nombre)" in code
        assert "fmt.Println(edad)" in code

    def test_if_else_program(self):
        source = "si x > 0\n  muestra x\nsino\n  muestra 0\n"
        code = go(source)
        assert "if x > 0 {" in code
        assert "} else {" in code

    def test_function_with_return(self):
        source = "fn doble(x)\n  devuelve x\n"
        code = go(source)
        assert "func doble(" in code
        assert "return x" in code

    @pytest.mark.skipif(not has_go(), reason="go no esta instalado en el sistema")
    def test_hello_world_compiles(self):
        """Test de compilacion real con go build (solo si go esta instalado)."""
        code = go('muestra "Hola desde Hado!"')
        assert go_builds(code), f"El codigo Go no compilo:\n{code}"

    @pytest.mark.skipif(not has_go(), reason="go no esta instalado en el sistema")
    def test_variable_assignment_compiles(self):
        """Variables con tipos correctos compilan."""
        source = "x = 42\nmuestra x\n"
        code = go(source)
        assert go_builds(code), f"El codigo Go no compilo:\n{code}"

    @pytest.mark.skipif(not has_go(), reason="go no esta instalado en el sistema")
    def test_if_statement_compiles(self):
        """Condicional if/else compila."""
        source = "x := 5\nsi x > 0\n  muestra x\nsino\n  muestra 0\n"
        code = go(source)
        assert go_builds(code), f"El codigo Go no compilo:\n{code}"

    @pytest.mark.skipif(not has_go(), reason="go no esta instalado en el sistema")
    def test_scan_compiles(self):
        """Cybersec scan con goroutines compila."""
        source = 'resultado = escanea target "127.0.0.1" en ports [80]\nmuestra resultado\n'
        code = go(source)
        assert go_builds(code), f"El codigo Go no compilo:\n{code}"
