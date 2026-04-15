"""
Hado DSL — CLI principal.

Uso:
  hado run script.ho                    # ejecuta con Python (default)
  hado run script.ho --target go        # muestra codigo Go generado
  hado compile script.ho                # transpila a Python (imprime)
  hado compile script.ho --target rust  # transpila a Rust
  hado compile script.ho --target go    # transpila a Go
  hado compile script.ho --target c     # transpila a C
  hado repl                                # REPL interactivo (Python)
  hado targets                             # lista backends disponibles
  hado --version                           # version actual
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
    """Transpila un archivo .ho y muestra (o guarda) el codigo generado."""
    from pathlib import Path
    from .errors import HadoError

    path = Path(file)
    if not path.exists():
        click.echo(f"hado: archivo no encontrado: {file}", err=True)
        sys.exit(1)

    source = path.read_text(encoding="utf-8")
    try:
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
@click.option(
    "--target",
    type=click.Choice(_VALID_TARGETS, case_sensitive=False),
    default="python",
    show_default=True,
    help="Lenguaje de destino del REPL",
)
def repl(target: str):
    """Inicia el REPL interactivo de Hado (Python backend)."""
    runtime.repl(target=target)


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
    click.echo("")


if __name__ == "__main__":
    main()
