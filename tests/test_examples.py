"""Tests de integracion: verifica que todos los ejemplos transpilan sin error."""

import pytest
from pathlib import Path
from habla.runtime import compile_to_source
import ast as pyast


EXAMPLES_DIR = Path(__file__).parent.parent / "examples"


def get_example_files():
    return sorted(EXAMPLES_DIR.glob("*.habla"))


@pytest.mark.parametrize("example_path", get_example_files(), ids=lambda p: p.name)
def test_example_compiles_to_python(example_path):
    source = example_path.read_text(encoding="utf-8")
    code = compile_to_source(source, target="python", filename=str(example_path))
    assert code is not None
    assert len(code.strip()) > 0


@pytest.mark.parametrize("example_path", get_example_files(), ids=lambda p: p.name)
def test_example_python_is_valid(example_path):
    source = example_path.read_text(encoding="utf-8")
    code = compile_to_source(source, target="python", filename=str(example_path))
    try:
        pyast.parse(code)
    except SyntaxError as e:
        pytest.fail(f"Python invalido generado de {example_path.name}: {e}\n\nCodigo:\n{code}")


@pytest.mark.parametrize("example_path", get_example_files(), ids=lambda p: p.name)
def test_example_compiles_to_c(example_path):
    source = example_path.read_text(encoding="utf-8")
    code = compile_to_source(source, target="c", filename=str(example_path))
    assert code is not None
    assert len(code.strip()) > 0


@pytest.mark.parametrize("example_path", get_example_files(), ids=lambda p: p.name)
def test_example_compiles_to_rust(example_path):
    source = example_path.read_text(encoding="utf-8")
    code = compile_to_source(source, target="rust", filename=str(example_path))
    assert code is not None
    assert len(code.strip()) > 0


def test_hola_mundo_runs():
    """El programa hola-mundo debe ejecutarse y producir output."""
    example = EXAMPLES_DIR / "01-hola-mundo.habla"
    if not example.exists():
        pytest.skip("Ejemplo no encontrado")

    source = example.read_text(encoding="utf-8")

    import io
    import sys
    captured = io.StringIO()
    sys.stdout = captured
    try:
        from habla.runtime import run_source
        run_source(source, filename="01-hola-mundo.habla")
    finally:
        sys.stdout = sys.__stdout__

    output = captured.getvalue()
    assert "Habla" in output or "Bienvenido" in output or "mundo" in output
