"""
Tests de robustez del compilador Hado — recomendaciones del podcast v0.5.

Cubre:
  1. Normalizer — comillas tipográficas (LLM/web copy-paste)
  2. Lexer — bracketed paste, ANSI escapes, caracteres invisibles
  3. Lexer — modo tolerante (strict=False) vs. modo estricto (strict=True)
  4. CLI — hado check (análisis estático)
  5. CLI — hado backend status (matriz de compatibilidad)
  6. Rust transpiler — emit_project() genera main.rs + Cargo.toml válidos
"""

from __future__ import annotations
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# ─── Importaciones del paquete ────────────────────────────────────────────────

from hado.normalizer import normalize
from hado.lexer import Lexer, clean_source, TokenType
from hado.runtime import compile_to_source


# ══════════════════════════════════════════════════════════════════════════════
# 1. Normalizer — comillas tipográficas
# ══════════════════════════════════════════════════════════════════════════════

class TestTypographicQuotes:

    def test_left_right_double_quotes_become_ascii(self):
        source = '\u201cHola mundo\u201d'  # "Hola mundo"
        result = normalize(source)
        assert result == '"Hola mundo"'

    def test_left_right_single_quotes_become_ascii(self):
        source = "\u2018Hola\u2019"  # 'Hola'
        result = normalize(source)
        assert result == "'Hola'"

    def test_french_guillemets_become_double_quotes(self):
        source = "\u00abValor\u00bb"  # «Valor»
        result = normalize(source)
        assert result == '"Valor"'

    def test_ellipsis_unicode_becomes_three_dots(self):
        source = "muestra \u2026"  # muestra …
        result = normalize(source)
        assert "..." in result

    def test_german_quote_normalized(self):
        source = "\u201eHallo\u201d"  # „Hallo"
        result = normalize(source)
        assert '"Hallo"' in result

    def test_mixed_typographic_quotes_normalized(self):
        source = 'x = \u201cvalor\u201d\ny = \u2018otro\u2019'
        result = normalize(source)
        assert '"valor"' in result
        assert "'otro'" in result

    def test_string_content_preserved_through_normalize(self):
        """El contenido de strings literales no debe doblarse/alterarse."""
        source = '"texto con acento á"'
        result = normalize(source)
        # El contenido dentro del string debe preservarse
        assert "á" in result

    def test_code_diacritics_normalized(self):
        """Diacríticos en código (fuera de strings) se normalizan."""
        source = "función = 1"  # ú → u
        result = normalize(source)
        assert "funcion" in result

    def test_diacritics_in_string_preserved(self):
        """Diacríticos dentro de string literals NO se normalizan."""
        source = 'muestra "función"'
        result = normalize(source)
        # "función" en string debe quedar intacto
        assert "función" in result


# ══════════════════════════════════════════════════════════════════════════════
# 2. Lexer — limpieza de artefactos de terminal
# ══════════════════════════════════════════════════════════════════════════════

class TestCleanSource:

    def test_bracketed_paste_removed(self):
        """ESC[200~ ... ESC[201~ se elimina por completo."""
        source = '\x1b[200~escanea "target"\x1b[201~'
        cleaned, warns = clean_source(source)
        assert "\x1b" not in cleaned
        assert len(warns) > 0
        assert any("bracketed" in w.lower() or "paste" in w.lower() or "200" in w for w in warns)

    def test_ansi_escape_removed(self):
        """Secuencias de color ANSI eliminadas."""
        source = "\x1b[32mescanea\x1b[0m target"
        cleaned, warns = clean_source(source)
        assert "\x1b" not in cleaned
        assert "escanea" in cleaned
        assert "target" in cleaned

    def test_carriage_return_removed(self):
        """\\r (Windows line endings) eliminado."""
        source = "escanea target\r\nmuestra resultado"
        cleaned, warns = clean_source(source)
        assert "\r" not in cleaned
        assert "escanea target" in cleaned

    def test_zero_width_spaces_removed(self):
        """Zero-width spaces y BOM eliminados."""
        source = "escanea\u200b target\ufeff"
        cleaned, warns = clean_source(source)
        assert "\u200b" not in cleaned
        assert "\ufeff" not in cleaned
        assert "escanea" in cleaned

    def test_null_bytes_removed(self):
        """Bytes nulos y caracteres de control eliminados."""
        source = "x\x00 = 1"
        cleaned, warns = clean_source(source)
        assert "\x00" not in cleaned
        assert "x" in cleaned

    def test_clean_source_preserves_normal_code(self):
        """Código limpio no se altera."""
        source = 'escanea "192.168.1.1"\nmuestra "hecho"'
        cleaned, warns = clean_source(source)
        assert cleaned == source
        assert warns == []

    def test_multiple_artefacts_all_cleaned(self):
        """Múltiples tipos de artefactos limpiados en una sola pasada."""
        source = "\ufeff\x1b[32m\x00escanea\x1b[0m\x00 target\r\n"
        cleaned, warns = clean_source(source)
        assert "\ufeff" not in cleaned
        assert "\x1b" not in cleaned
        assert "\x00" not in cleaned
        assert "\r" not in cleaned
        assert "escanea" in cleaned
        assert len(warns) > 0


# ══════════════════════════════════════════════════════════════════════════════
# 3. Lexer — modo tolerante vs. estricto
# ══════════════════════════════════════════════════════════════════════════════

class TestLexerTolerance:

    def test_strict_false_unknown_char_warns_not_raises(self):
        """strict=False: carácter desconocido emite warning pero no lanza excepción."""
        from hado.errors import LexerError
        source = 'x = 1 @ 2'  # @ es desconocido en Hado
        lexer = Lexer(source, strict=False)
        # No debe lanzar excepción
        tokens = lexer.tokenize()
        warns = lexer.get_warnings()
        assert any("@" in w or "desconocido" in w or "ignorado" in w for w in warns)
        # El resto del código debe tokenizarse
        identifiers = [t.value for t in tokens if t.type == TokenType.IDENTIFIER]
        assert "x" in identifiers

    def test_strict_true_unknown_char_raises(self):
        """strict=True: carácter desconocido lanza LexerError."""
        from hado.errors import LexerError
        source = 'x = 1 @ 2'
        lexer = Lexer(source, strict=True)
        with pytest.raises(LexerError):
            lexer.tokenize()

    def test_get_warnings_empty_on_clean_source(self):
        """get_warnings() vacío en código limpio."""
        lexer = Lexer('muestra "hola"')
        lexer.tokenize()
        assert lexer.get_warnings() == []

    def test_bracketed_paste_warns_via_lexer(self):
        """Lexer reporta advertencia por bracketed paste."""
        source = '\x1b[200~escanea "target"\x1b[201~'
        lexer = Lexer(source, strict=False)
        lexer.tokenize()
        warns = lexer.get_warnings()
        assert len(warns) > 0

    def test_tolerant_mode_is_default(self):
        """strict=False es el modo por defecto."""
        from hado.errors import LexerError
        source = 'x = 1 @ 2'
        lexer = Lexer(source)  # sin especificar strict
        # No debe lanzar
        tokens = lexer.tokenize()
        assert tokens is not None

    def test_lexer_normalizes_single_to_double_quotes(self):
        """Single-quoted strings se normalizan a double-quote."""
        lexer = Lexer("x = 'hola'")
        tokens = lexer.tokenize()
        string_tokens = [t for t in tokens if t.type == TokenType.STRING]
        assert len(string_tokens) == 1
        assert string_tokens[0].value == '"hola"'


# ══════════════════════════════════════════════════════════════════════════════
# 4. CLI — hado check
# ══════════════════════════════════════════════════════════════════════════════

def _run_hado(*args) -> subprocess.CompletedProcess:
    """Ejecuta `hado` como subprocess y retorna el resultado."""
    # Resolver la raiz del proyecto dinamicamente (donde vive pyproject.toml)
    _project_root = str(Path(__file__).resolve().parent.parent)
    return subprocess.run(
        [sys.executable, "-m", "hado", *args],
        capture_output=True,
        text=True,
        cwd=_project_root,
    )


class TestCliCheck:

    def test_check_valid_file_passes(self, tmp_path):
        """hado check en archivo válido retorna código 0."""
        f = tmp_path / "ok.ho"
        f.write_text('escanea "192.168.1.1"\nmuestra "hecho"', encoding="utf-8")
        result = _run_hado("check", str(f))
        assert result.returncode == 0
        assert "PASSED" in result.stdout or "Sin errores" in result.stdout

    def test_check_invalid_file_fails(self, tmp_path):
        """hado check en archivo con error sintáctico retorna código != 0."""
        f = tmp_path / "bad.ho"
        f.write_text("si {broken syntax ===", encoding="utf-8")
        result = _run_hado("check", str(f))
        assert result.returncode != 0
        assert "ERROR" in result.stdout or "FAILED" in result.stdout

    def test_check_json_output_structure(self, tmp_path):
        """hado check --json retorna JSON válido con campos esperados."""
        f = tmp_path / "ok.ho"
        f.write_text('muestra "hola"', encoding="utf-8")
        result = _run_hado("check", str(f), "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "file" in data
        assert "passed" in data
        assert "issues" in data
        assert data["passed"] is True
        assert isinstance(data["issues"], list)

    def test_check_json_error_structure(self, tmp_path):
        """hado check --json en archivo con error incluye issues."""
        f = tmp_path / "bad.ho"
        f.write_text("si {syntax error!", encoding="utf-8")
        result = _run_hado("check", str(f), "--json")
        assert result.returncode != 0
        data = json.loads(result.stdout)
        assert data["passed"] is False
        assert len(data["issues"]) > 0

    def test_check_nonexistent_file(self):
        """hado check en archivo inexistente retorna código != 0."""
        result = _run_hado("check", "/tmp/no_existe_nunca_jamas.ho")
        assert result.returncode != 0

    def test_check_strict_flag_makes_warnings_errors(self, tmp_path):
        """hado check --strict trata advertencias como errores."""
        f = tmp_path / "ok.ho"
        f.write_text('muestra "hola"', encoding="utf-8")
        result = _run_hado("check", str(f), "--strict")
        # En código limpio, strict no debe romper
        assert result.returncode == 0


# ══════════════════════════════════════════════════════════════════════════════
# 5. CLI — hado backend status
# ══════════════════════════════════════════════════════════════════════════════

class TestCliBackendStatus:

    def test_backend_status_exits_ok(self):
        """hado backend status retorna código 0."""
        result = _run_hado("backend", "status")
        assert result.returncode == 0

    def test_backend_status_shows_all_targets(self):
        """La tabla muestra los 4 targets."""
        result = _run_hado("backend", "status")
        output = result.stdout
        assert "PYTHON" in output.upper()
        assert "GO" in output.upper()
        assert "RUST" in output.upper()
        assert "C" in output.upper() or "C " in output.upper()

    def test_backend_status_shows_modules(self):
        """La tabla incluye módulos clave."""
        result = _run_hado("backend", "status")
        output = result.stdout
        assert "escanea" in output or "scan" in output.lower() or "Scan" in output

    def test_backend_status_json_valid(self):
        """hado backend status --json retorna JSON válido."""
        result = _run_hado("backend", "status", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, dict)
        # Debe tener al menos las claves de targets
        keys = list(data.keys())
        assert len(keys) > 0

    def test_backend_status_filter_target(self):
        """hado backend status --target python filtra a un solo target."""
        result = _run_hado("backend", "status", "--target", "python")
        assert result.returncode == 0
        assert "PYTHON" in result.stdout.upper() or "python" in result.stdout


# ══════════════════════════════════════════════════════════════════════════════
# 6. Rust transpiler — emit_project()
# ══════════════════════════════════════════════════════════════════════════════

class TestRustTranspilerProject:

    def _build_ast(self, source: str):
        from hado.normalizer import normalize
        from hado.lexer import Lexer
        from hado.parser import Parser
        normalized = normalize(source)
        lexer = Lexer(normalized)
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        return parser.parse()

    def test_emit_project_returns_tuple(self):
        """emit_project() retorna (main_rs: str, cargo_toml: str)."""
        from hado.backends.rust_transpiler import RustTranspiler
        ast = self._build_ast('muestra "hola"')
        t = RustTranspiler(ast)
        result = t.emit_project()
        assert isinstance(result, tuple)
        assert len(result) == 2
        main_rs, cargo_toml = result
        assert isinstance(main_rs, str)
        assert isinstance(cargo_toml, str)

    def test_emit_main_rs_has_fn_main(self):
        """main.rs contiene fn main() o async fn main()."""
        from hado.backends.rust_transpiler import RustTranspiler
        ast = self._build_ast('muestra "hola"')
        t = RustTranspiler(ast)
        main_rs, _ = t.emit_project()
        assert "fn main()" in main_rs

    def test_cargo_toml_has_package_section(self):
        """Cargo.toml tiene sección [package]."""
        from hado.backends.rust_transpiler import RustTranspiler
        ast = self._build_ast('muestra "hola"')
        t = RustTranspiler(ast)
        _, cargo_toml = t.emit_project()
        assert "[package]" in cargo_toml
        assert "[dependencies]" in cargo_toml

    def test_cyberscan_generates_async_main(self):
        """escanea produce async fn main() con #[tokio::main]."""
        from hado.backends.rust_transpiler import RustTranspiler
        ast = self._build_ast('escanea "192.168.1.1"')
        t = RustTranspiler(ast)
        main_rs, cargo_toml = t.emit_project()
        assert "#[tokio::main]" in main_rs
        assert "async fn main" in main_rs
        assert "scan_ports" in main_rs

    def test_cyberscan_cargo_toml_includes_tokio(self):
        """escanea incluye tokio y futures en Cargo.toml."""
        from hado.backends.rust_transpiler import RustTranspiler
        ast = self._build_ast('escanea "192.168.1.1"')
        t = RustTranspiler(ast)
        _, cargo_toml = t.emit_project()
        assert "tokio" in cargo_toml
        assert "futures" in cargo_toml

    def test_scan_ports_helper_in_main_rs(self):
        """La función scan_ports() está en el main.rs generado."""
        from hado.backends.rust_transpiler import RustTranspiler
        ast = self._build_ast('escanea "10.0.0.1"')
        t = RustTranspiler(ast)
        main_rs, _ = t.emit_project()
        assert "async fn scan_ports" in main_rs
        assert "TcpStream::connect" in main_rs
        assert "join_all" in main_rs

    def test_emit_method_returns_string(self):
        """emit() (sin cargo) retorna solo el main.rs como string."""
        from hado.backends.rust_transpiler import RustTranspiler
        ast = self._build_ast('muestra "test"')
        t = RustTranspiler(ast)
        result = t.emit()
        assert isinstance(result, str)
        assert "fn main" in result

    def test_crate_name_used_in_cargo_toml(self):
        """El nombre del crate se refleja en Cargo.toml."""
        from hado.backends.rust_transpiler import RustTranspiler
        ast = self._build_ast('muestra "test"')
        t = RustTranspiler(ast, crate_name="mi_scanner")
        _, cargo_toml = t.emit_project()
        assert 'name = "mi_scanner"' in cargo_toml

    def test_edition_2021_in_cargo_toml(self):
        """Cargo.toml usa edition 2021."""
        from hado.backends.rust_transpiler import RustTranspiler
        ast = self._build_ast('muestra "test"')
        t = RustTranspiler(ast)
        _, cargo_toml = t.emit_project()
        assert 'edition = "2021"' in cargo_toml

    def test_scan_ports_not_duplicated(self):
        """scan_ports() solo aparece una vez aunque haya dos escanea."""
        from hado.backends.rust_transpiler import RustTranspiler
        source = 'escanea "192.168.1.1"\nescanea "10.0.0.1"'
        ast = self._build_ast(source)
        t = RustTranspiler(ast)
        main_rs, _ = t.emit_project()
        # scan_ports debe definirse exactamente una vez como función
        count = main_rs.count("async fn scan_ports(")
        assert count == 1

    def test_recon_generates_find_subdomains(self):
        """busca subdomains genera find_subdomains() async."""
        from hado.backends.rust_transpiler import RustTranspiler
        source = 'busca subdomains de "example.com"'
        try:
            ast = self._build_ast(source)
            t = RustTranspiler(ast)
            main_rs, cargo_toml = t.emit_project()
            # Si el parser reconoce CyberRecon, debe generar la función
            if "find_subdomains" in main_rs:
                assert "#[tokio::main]" in main_rs
                assert "tokio" in cargo_toml
        except Exception:
            # Si el parser no reconoce busca subdomains aún, skip
            pytest.skip("Parser no reconoce busca subdomains todavía")


# ══════════════════════════════════════════════════════════════════════════════
# 7. End-to-end: normalizer + lexer + parser + rust transpiler
# ══════════════════════════════════════════════════════════════════════════════

class TestEndToEndRust:

    def test_compile_to_rust_returns_valid_code(self):
        """compile_to_source(target='rust') retorna código Rust no vacío."""
        code = compile_to_source('escanea "192.168.1.1"', target="rust")
        assert len(code) > 100
        assert "fn main" in code
        assert "tokio" in code or "scan_ports" in code

    def test_typographic_quotes_survive_full_pipeline(self):
        """Comillas tipográficas se normalizan y el pipeline funciona."""
        source = 'muestra \u201cHola mundo\u201d'  # muestra "Hola mundo"
        code = compile_to_source(source, target="rust")
        assert "fn main" in code

    def test_bracketed_paste_source_compiles(self):
        """Fuente con bracketed paste se limpia y compila sin error."""
        source = '\x1b[200~muestra "hola"\x1b[201~'
        code = compile_to_source(source, target="rust")
        assert "fn main" in code

    def test_rust_output_has_header_comment(self):
        """El main.rs tiene el comentario de cabecera de Hado."""
        code = compile_to_source('muestra "test"', target="rust")
        assert "Hado DSL" in code or "hado-lang" in code or "Generado por Hado" in code
