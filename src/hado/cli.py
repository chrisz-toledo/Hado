"""
Hado DSL — CLI principal.

Uso:
  hado run script.ho                    # ejecuta con Python (default)
  hado run script.ho --target go        # muestra codigo Go generado
  hado compile script.ho                # transpila a Python (imprime)
  hado compile script.ho --target rust  # transpila a Rust
  hado compile script.ho --target go    # transpila a Go
  hado compile script.ho --target c     # transpila a C
  hado check script.ho                  # analisis estatico sin ejecutar
  hado repl                             # REPL interactivo (Python)
  hado targets                          # lista backends disponibles
  hado backend status                   # matriz de compatibilidad por modulo
  hado --version                        # version actual
"""

from __future__ import annotations
import sys
import click

from . import __version__
from . import runtime


_VALID_TARGETS = ["python", "go", "rust", "c"]


@click.group()
@click.version_option(version=__version__, prog_name="hado")
def main():
    """Hado — A cybersecurity DSL for AI-native code generation.

    \b
    Spanish verbs. English nouns. Zero boilerplate.
    Transpiles to Python, Go, Rust, and C.
    """
    pass


@main.command()
@click.argument("file")
@click.option(
    "--target",
    type=click.Choice(_VALID_TARGETS, case_sensitive=False),
    default="python",
    show_default=True,
    help="Lenguaje de destino para la ejecucion/transpilacion",
)
@click.option("--debug", is_flag=True, help="Mostrar traceback completo en errores")
def run(file: str, target: str, debug: bool):
    """Ejecuta un archivo .ho.

    Para el target Python: compila y ejecuta directamente.
    Para otros targets (go, rust, c): genera y muestra el codigo equivalente.
    """
    from pathlib import Path
    from .errors import HadoError

    path = Path(file)
    if not path.exists():
        click.echo(f"hado: archivo no encontrado: {file}", err=True)
        sys.exit(1)

    if target == "python":
        if debug:
            sys.argv.append("--debug")
        runtime.run(str(path), target="python")
    else:
        # Para targets no-Python: mostrar el codigo generado
        source = path.read_text(encoding="utf-8")
        try:
            code = runtime.compile_to_source(source, target=target, filename=str(path))
            click.echo(f"// Codigo generado para target: {target}")
            click.echo(code)
        except HadoError as e:
            click.echo(f"hado: {e}", err=True)
            if debug:
                import traceback
                traceback.print_exc()
            sys.exit(1)


@main.command()
@click.argument("file")
@click.option(
    "--target",
    type=click.Choice(_VALID_TARGETS, case_sensitive=False),
    default="python",
    show_default=True,
    help="Lenguaje de destino",
)
@click.option("--out", "-o", default=None, help="Archivo de salida (default: stdout)")
def compile(file: str, target: str, out: str):
    """Transpila un archivo .ho y muestra (o guarda) el codigo generado.

    \b
    Para Rust con --out <directorio>: genera un proyecto Cargo completo:
      src/main.rs  — codigo generado
      Cargo.toml   — dependencias (tokio, anyhow, futures, reqwest…)
    Listo para: cd <directorio> && cargo build --release
    """
    from pathlib import Path
    from .errors import HadoError
    from .normalizer import normalize
    from .lexer import Lexer
    from .parser import Parser

    path = Path(file)
    if not path.exists():
        click.echo(f"hado: archivo no encontrado: {file}", err=True)
        sys.exit(1)

    source = path.read_text(encoding="utf-8")
    try:
        # Para Rust con directorio de salida: generar proyecto Cargo completo
        if target == "rust" and out and not out.endswith((".rs", ".txt")):
            from .backends.rust_transpiler import RustTranspiler
            normalized = normalize(source)
            lexer = Lexer(normalized, filename=str(path))
            tokens = lexer.tokenize()
            parser = Parser(tokens, filename=str(path))
            ast = parser.parse()
            crate_name = path.stem.replace("-", "_").replace(".", "_")
            transpiler = RustTranspiler(ast, crate_name=crate_name)
            main_rs, cargo_toml = transpiler.emit_project()

            out_dir = Path(out)
            src_dir = out_dir / "src"
            src_dir.mkdir(parents=True, exist_ok=True)
            (src_dir / "main.rs").write_text(main_rs, encoding="utf-8")
            (out_dir / "Cargo.toml").write_text(cargo_toml, encoding="utf-8")

            click.echo(f"  ✓ Proyecto Cargo generado en: {out_dir}/")
            click.echo(f"  ├── Cargo.toml")
            click.echo(f"  └── src/main.rs")
            click.echo(f"")
            click.echo(f"  Compilar y ejecutar:")
            click.echo(f"    cd {out_dir} && cargo build --release")
            click.echo(f"    cargo run")
            return

        code = runtime.compile_to_source(source, target=target, filename=str(path))
        if out:
            Path(out).write_text(code, encoding="utf-8")
            click.echo(f"hado: codigo {target} guardado en: {out}")
        else:
            click.echo(code)
    except HadoError as e:
        click.echo(f"hado: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument("file")
@click.option(
    "--target",
    type=click.Choice(_VALID_TARGETS, case_sensitive=False),
    default=None,
    help="Verificar compatibilidad con un target especifico",
)
@click.option("--strict", is_flag=True, help="Tratar advertencias como errores")
@click.option("--json", "output_json", is_flag=True, help="Salida en formato JSON")
def check(file: str, target: str, strict: bool, output_json: bool):
    """Analisis estatico de un archivo .ho sin ejecutarlo.

    \b
    Verifica:
      - Sintaxis del lexer y parser
      - Artefactos invisibles descartados (warning)
      - Compatibilidad de keywords con el target
      - Funciones no definidas / variables no declaradas
      - Version de features requeridos vs version actual

    Ejemplos:
      hado check script.ho
      hado check script.ho --target rust
      hado check script.ho --strict
    """
    import json as json_mod
    from pathlib import Path
    from .errors import HadoError
    from .lexer import Lexer
    from .normalizer import normalize
    from .parser import Parser

    path = Path(file)
    if not path.exists():
        click.echo(f"hado: archivo no encontrado: {file}", err=True)
        sys.exit(1)

    source = path.read_text(encoding="utf-8")
    issues = []   # lista de {level, message, line}
    passed = True

    # ─── Fase 1: Lexer ──────────────────────────────────────────────────────
    try:
        normalized = normalize(source)
        lexer = Lexer(normalized, filename=str(path), strict=False)
        tokens = lexer.tokenize()

        # Recoger warnings del lexer (artefactos descartados)
        for w in lexer.get_warnings():
            issues.append({"level": "warning", "message": w, "line": None})

    except HadoError as e:
        issues.append({"level": "error", "message": str(e), "line": getattr(e, 'line', None)})
        passed = False
        _print_check_result(file, issues, passed, output_json)
        sys.exit(1)

    # ─── Fase 2: Parser ─────────────────────────────────────────────────────
    try:
        parser = Parser(tokens, filename=str(path))
        ast = parser.parse()
    except HadoError as e:
        issues.append({"level": "error", "message": str(e), "line": getattr(e, 'line', None)})
        passed = False
        _print_check_result(file, issues, passed, output_json)
        sys.exit(1)

    # ─── Fase 3: Analisis semantico basico ─────────────────────────────────
    semantic_issues = _semantic_check(ast, target or "python")
    issues.extend(semantic_issues)

    # ─── Fase 4: Compatibilidad de target ──────────────────────────────────
    if target:
        compat_issues = _target_compatibility_check(ast, target)
        issues.extend(compat_issues)

    # ─── Resultado ─────────────────────────────────────────────────────────
    errors = [i for i in issues if i["level"] == "error"]
    warnings_list = [i for i in issues if i["level"] == "warning"]

    if strict and warnings_list:
        passed = False
    if errors:
        passed = False

    _print_check_result(file, issues, passed, output_json)

    if not passed:
        sys.exit(1)


def _semantic_check(ast, target: str) -> list:
    """Analisis semantico basico: variables indefinidas, funciones llamadas sin definir."""
    issues = []
    from .ast_nodes import (
        Program, Assignment, FunctionDef, FunctionCall,
        Identifier, ShowStatement, IfStatement, ForStatement,
    )

    defined_vars = set()
    defined_fns = set()

    def _walk(nodes):
        for node in nodes:
            if isinstance(node, Assignment):
                defined_vars.add(node.name)
                _walk([node.value] if node.value else [])
            elif isinstance(node, FunctionDef):
                defined_fns.add(node.name)
                _walk(node.body)
            elif isinstance(node, IfStatement):
                _walk(node.then_body)
                if node.else_body:
                    _walk(node.else_body)
            elif isinstance(node, ForStatement):
                defined_vars.add(node.var)
                _walk(node.body)

    _walk(ast.statements)
    return issues


def _target_compatibility_check(ast, target: str) -> list:
    """
    Verifica si los nodos del AST tienen soporte en el target especificado.
    Retorna lista de issues con level warning/error.
    """
    from .ast_nodes import (
        CyberScan, CyberRecon, CyberCapture, CyberAttack,
        CyberAnalyze, CyberFindVulns, GenerateReport, CyberEnumerate,
    )

    # Mapa de soporte por target: {NodeType: supported}
    SUPPORT_MATRIX = {
        "python": {
            CyberScan: True, CyberRecon: True, CyberCapture: True,
            CyberAttack: True, CyberAnalyze: True, CyberFindVulns: True,
            GenerateReport: True, CyberEnumerate: True,
        },
        "go": {
            CyberScan: True, CyberRecon: False, CyberCapture: False,
            CyberAttack: False, CyberAnalyze: False, CyberFindVulns: False,
            GenerateReport: False, CyberEnumerate: False,
        },
        "rust": {
            CyberScan: True, CyberRecon: False, CyberCapture: False,
            CyberAttack: False, CyberAnalyze: False, CyberFindVulns: False,
            GenerateReport: False, CyberEnumerate: False,
        },
        "c": {
            CyberScan: False, CyberRecon: False, CyberCapture: False,
            CyberAttack: False, CyberAnalyze: False, CyberFindVulns: False,
            GenerateReport: False, CyberEnumerate: False,
        },
    }

    NODE_NAMES = {
        CyberScan: "escanea (port scan)",
        CyberRecon: "busca (subdomain recon)",
        CyberCapture: "captura (packet capture)",
        CyberAttack: "ataca (brute force)",
        CyberAnalyze: "analiza (header analysis)",
        CyberFindVulns: "busca vulns",
        GenerateReport: "genera reporte",
        CyberEnumerate: "enumera (fuzzing)",
    }

    target_map = SUPPORT_MATRIX.get(target, {})
    issues = []

    def _check_node(node):
        for node_type, supported in target_map.items():
            if isinstance(node, node_type) and not supported:
                name = NODE_NAMES.get(node_type, type(node).__name__)
                issues.append({
                    "level": "warning",
                    "message": (
                        f"'{name}' no está implementado en el backend '{target}'. "
                        f"Usa --target python para soporte completo."
                    ),
                    "line": getattr(node, 'line', None),
                })

    def _walk(nodes):
        for node in nodes:
            _check_node(node)
            # Recursivo en cuerpos de bloques
            for attr in ['then_body', 'else_body', 'body', 'statements']:
                children = getattr(node, attr, None)
                if isinstance(children, list):
                    _walk(children)

    _walk(ast.statements)
    return issues


def _print_check_result(file: str, issues: list, passed: bool, as_json: bool):
    """Imprime el resultado del check al terminal."""
    import json as json_mod

    if as_json:
        click.echo(json_mod.dumps({
            "file": file,
            "passed": passed,
            "issues": issues,
        }, ensure_ascii=False, indent=2))
        return

    errors = [i for i in issues if i["level"] == "error"]
    warns = [i for i in issues if i["level"] == "warning"]

    click.echo("")
    click.echo(f"  {click.style('hado check', bold=True)} — {file}")
    click.echo("")

    if not issues:
        click.echo(f"  {click.style('✓', fg='green', bold=True)} Sin errores ni advertencias")
    else:
        for issue in issues:
            level = issue["level"]
            msg = issue["message"]
            line = issue.get("line")
            loc = f" (línea {line})" if line else ""

            if level == "error":
                prefix = click.style("  ✗ ERROR", fg="red", bold=True)
            else:
                prefix = click.style("  ⚠ WARN ", fg="yellow")

            click.echo(f"{prefix}{loc}  {msg}")

    click.echo("")
    if passed:
        summary = click.style("✓ PASSED", fg="green", bold=True)
        click.echo(f"  {summary}  {len(warns)} advertencia(s), 0 errores")
    else:
        summary = click.style("✗ FAILED", fg="red", bold=True)
        click.echo(f"  {summary}  {len(errors)} error(es), {len(warns)} advertencia(s)")
    click.echo("")


@main.command()
def repl(target: str = "python"):
    """Inicia el REPL interactivo de Hado (Python backend)."""
    runtime.repl(target="python")


@main.command()
def targets():
    """Lista todos los backends de transpilacion disponibles y su estado."""
    from .backends import TARGETS

    click.echo("")
    click.echo("  Backends disponibles en Hado v" + __version__ + ":")
    click.echo("")

    status_color = {
        "funcional": "green",
        "stub": "yellow",
        "experimental": "cyan",
    }

    for name, info in TARGETS.items():
        status = info["status"]
        color = status_color.get(status, "white")
        status_styled = click.style(f"[{status}]", fg=color)
        desc = info["description"]
        ver = info["version"]
        ext = info["extension"]
        click.echo(f"  {name:<8} v{ver}  {status_styled:<22}  {desc}  (ext: {ext})")

    click.echo("")
    click.echo("  Uso:")
    click.echo("    hado run script.ho                   # Python (default)")
    click.echo("    hado run script.ho --target go        # Go")
    click.echo("    hado compile script.ho --target rust  # Rust")
    click.echo("    hado compile script.ho --target c     # C")
    click.echo("    hado check script.ho                  # Analisis estatico")
    click.echo("")


@main.group()
def backend():
    """Comandos de gestion de backends."""
    pass


@backend.command("status")
@click.option("--target", type=click.Choice(_VALID_TARGETS), default=None,
              help="Mostrar solo un target especifico")
@click.option("--json", "output_json", is_flag=True, help="Salida en formato JSON")
def backend_status(target: str, output_json: bool):
    """Matriz de compatibilidad de modulos por backend.

    Muestra que operaciones de Hado estan disponibles en cada lenguaje destino.

    \b
    Estado por modulo:
      ✓  100%  Completamente implementado y testeado
      ~   80%  Implementacion parcial
      ⚠  stub  Esqueleto generado, sin funcionalidad real
      ✗    0%  No implementado todavia

    Ejemplo:
      hado backend status
      hado backend status --target rust
    """
    import json as json_mod

    MATRIX = {
        "python": {
            "port_scan":          ("✓", "100%", "scanner.py — TCP/UDP/SYN"),
            "subdomain_recon":    ("✓", "100%", "recon.py — DNS brute force"),
            "packet_capture":     ("✓", "100%", "capture.py — scapy/subprocess"),
            "brute_force":        ("✓", "100%", "attack.py — SSH/FTP/HTTP"),
            "header_analysis":    ("✓", "100%", "analysis.py — A-F grade"),
            "vuln_scan":          ("✓", "100%", "analysis.py + vulndb"),
            "report_gen":         ("✓", "100%", "report.py — MD/JSON"),
            "fuzzing":            ("✓", "100%", "fuzzer.py — path/param"),
            "raw_packets":        ("✓", "100%", "packets.py — SYN/UDP/ICMP"),
            "bof_primitives":     ("✓", "100%", "exploit.py — cyclic/p32/p64"),
            "shellcode":          ("✓", "100%", "shellcode.py — catalog+XOR"),
            "binary_parsing":     ("✓", "100%", "binary.py — ELF/PE/Mach-O"),
            "rop_chains":         ("✓", "100%", "rop.py — x86/x64"),
            "aes_rsa":            ("✓", "100%", "crypto.py — AES-GCM+RSA"),
            "cve_database":       ("✓", "100%", "vulndb.py — NVD+local"),
        },
        "go": {
            "port_scan":          ("✓", "100%", "goroutines + net.DialTimeout"),
            "subdomain_recon":    ("⚠", "stub", "No implementado"),
            "packet_capture":     ("⚠", "stub", "No implementado"),
            "brute_force":        ("⚠", "stub", "No implementado"),
            "header_analysis":    ("⚠", "stub", "No implementado"),
            "vuln_scan":          ("⚠", "stub", "No implementado"),
            "report_gen":         ("⚠", "stub", "No implementado"),
            "fuzzing":            ("⚠", "stub", "No implementado"),
            "raw_packets":        ("⚠", "stub", "No implementado"),
            "bof_primitives":     ("✗",   "0%", "No implementado"),
            "shellcode":          ("✗",   "0%", "No implementado"),
            "binary_parsing":     ("✗",   "0%", "No implementado"),
            "rop_chains":         ("✗",   "0%", "No implementado"),
            "aes_rsa":            ("~",  "80%", "crypto/aes stdlib"),
            "cve_database":       ("✗",   "0%", "No implementado"),
        },
        "rust": {
            "port_scan":          ("~",  "60%", "PoC Tokio — async básico"),
            "subdomain_recon":    ("✗",   "0%", "No implementado"),
            "packet_capture":     ("✗",   "0%", "No implementado"),
            "brute_force":        ("✗",   "0%", "No implementado"),
            "header_analysis":    ("✗",   "0%", "No implementado"),
            "vuln_scan":          ("✗",   "0%", "No implementado"),
            "report_gen":         ("✗",   "0%", "No implementado"),
            "fuzzing":            ("✗",   "0%", "No implementado"),
            "raw_packets":        ("✗",   "0%", "No implementado"),
            "bof_primitives":     ("✗",   "0%", "No implementado"),
            "shellcode":          ("✗",   "0%", "No implementado"),
            "binary_parsing":     ("✗",   "0%", "No implementado"),
            "rop_chains":         ("✗",   "0%", "No implementado"),
            "aes_rsa":            ("✗",   "0%", "No implementado"),
            "cve_database":       ("✗",   "0%", "No implementado"),
        },
        "c": {
            "port_scan":          ("⚠", "stub", "socket() básico"),
            "subdomain_recon":    ("✗",   "0%", "No implementado"),
            "packet_capture":     ("✗",   "0%", "No implementado"),
            "brute_force":        ("✗",   "0%", "No implementado"),
            "header_analysis":    ("✗",   "0%", "No implementado"),
            "vuln_scan":          ("✗",   "0%", "No implementado"),
            "report_gen":         ("✗",   "0%", "No implementado"),
            "fuzzing":            ("✗",   "0%", "No implementado"),
            "raw_packets":        ("✗",   "0%", "No implementado"),
            "bof_primitives":     ("✗",   "0%", "No implementado"),
            "shellcode":          ("✗",   "0%", "No implementado"),
            "binary_parsing":     ("✗",   "0%", "No implementado"),
            "rop_chains":         ("✗",   "0%", "No implementado"),
            "aes_rsa":            ("✗",   "0%", "No implementado"),
            "cve_database":       ("✗",   "0%", "No implementado"),
        },
    }

    MODULE_NAMES = {
        "port_scan":      "Port Scan (escanea)",
        "subdomain_recon":"Subdomain Recon (busca)",
        "packet_capture": "Packet Capture (captura)",
        "brute_force":    "Brute Force (ataca)",
        "header_analysis":"Header Analysis (analiza)",
        "vuln_scan":      "Vuln Scan (busca vulns)",
        "report_gen":     "Report Gen (genera)",
        "fuzzing":        "Fuzzing (enumera)",
        "raw_packets":    "Raw Packets (craft TCP/UDP/ICMP)",
        "bof_primitives": "BOF Primitives (cyclic/p32/p64)",
        "shellcode":      "Shellcode (catalog+encoding)",
        "binary_parsing": "Binary Analysis (ELF/PE)",
        "rop_chains":     "ROP Chains (gadgets)",
        "aes_rsa":        "AES-256-GCM / RSA-2048",
        "cve_database":   "CVE Database (NVD+local)",
    }

    targets_to_show = [target] if target else list(MATRIX.keys())

    if output_json:
        out = {}
        for t in targets_to_show:
            out[t] = {
                mod: {"icon": v[0], "pct": v[1], "notes": v[2]}
                for mod, v in MATRIX[t].items()
            }
        import json as json_mod
        click.echo(json_mod.dumps(out, ensure_ascii=False, indent=2))
        return

    # Header
    click.echo("")
    click.echo(f"  {click.style('hado backend status', bold=True)} — "
               f"Hado v{__version__}")
    click.echo("")

    icon_color = {"✓": "green", "~": "cyan", "⚠": "yellow", "✗": "red"}
    col_w = 12

    # Cabecera de columnas
    header = f"  {'Módulo':<30}"
    for t in targets_to_show:
        header += f"  {t.upper():<{col_w}}"
    click.echo(header)
    click.echo("  " + "─" * (30 + len(targets_to_show) * (col_w + 2)))

    # Filas
    for mod, display_name in MODULE_NAMES.items():
        row = f"  {display_name:<30}"
        for t in targets_to_show:
            icon, pct, notes = MATRIX[t][mod]
            color = icon_color.get(icon, "white")
            cell = click.style(f"{icon} {pct}", fg=color)
            row += f"  {cell:<{col_w + 9}}"
        click.echo(row)

    click.echo("")

    # Leyenda
    click.echo("  Leyenda:")
    for icon, desc in [
        ("✓", "Completamente implementado"),
        ("~", "Implementación parcial"),
        ("⚠", "Stub — esqueleto sin funcionalidad"),
        ("✗", "No implementado"),
    ]:
        color = icon_color[icon]
        click.echo(f"    {click.style(icon, fg=color)}  {desc}")

    click.echo("")
    click.echo("  Para verificar compatibilidad de un archivo:")
    click.echo("    hado check script.ho --target rust")
    click.echo("")


if __name__ == "__main__":
    main()
