"""
Hado DSL — Clase base abstracta y registry de backends de generacion de codigo.

Cada backend (Python, Go, Rust, C) hereda de BaseTranspiler y se registra aqui.

Para agregar un nuevo target basta con:
  1. Crear backends/mylang_transpiler.py con una clase MyLangTranspiler(BaseTranspiler)
  2. Agregar una entrada en _BACKEND_REGISTRY con su modulo y clase
  3. Listo — get_backend("mylang", ast) funciona automaticamente

La arquitectura multi-target funciona asi:
  .ho -> Lexer -> Parser -> AST (compartido) -> Backend especifico -> codigo target
"""

from __future__ import annotations
import importlib
from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING

from ..ast_nodes import Program

if TYPE_CHECKING:
    from ..transpiler import BaseTranspiler


class HadoBackend(ABC):
    """
    Interfaz abstracta que deben implementar todos los backends de Hado.

    El AST es identico para todos los targets — solo el backend de generacion
    de codigo cambia. Esto permite escribir codigo Hado una vez y compilarlo
    a Python, Go, Rust o C sin modificaciones.
    """

    @abstractmethod
    def generate(self, ast: Program) -> str:
        """
        Recibe el AST de un programa Hado y devuelve codigo fuente
        en el lenguaje target como string.
        """
        ...

    @abstractmethod
    def file_extension(self) -> str:
        """Extension del archivo generado: ".py" | ".go" | ".rs" | ".c" """
        ...

    @abstractmethod
    def compile_command(self, source_path: str) -> Optional[str]:
        """
        Comando para compilar el archivo generado.
        Devuelve None si el lenguaje es interpretado (Python).

        Ejemplos:
            Python  -> None
            Go      -> "go build {source_path}"
            Rust    -> "rustc {source_path}"
            C       -> "gcc -o output {source_path}"
        """
        ...


# ─── Registry central de backends ─────────────────────────────────────────────
#
# Para agregar un nuevo target:
#   1. Crear src/hado/backends/<lang>_transpiler.py con la clase correspondiente
#   2. Agregar una entrada aqui con module, class, extension y compile_cmd
#   No se necesita tocar ningun otro archivo.

_BACKEND_REGISTRY: dict[str, dict] = {
    "python": {
        "version": "0.1",
        "status": "funcional",
        "description": "Scripting, OSINT, automatizacion",
        "module": "hado.backends.python_transpiler",
        "class": "PythonTranspiler",
        "extension": ".py",
        "compile_cmd": None,
    },
    "go": {
        "version": "0.1",
        "status": "stub",
        "description": "Scanners concurrentes, binarios standalone",
        "module": "hado.backends.go_backend",
        "class": "GoBackend",
        "extension": ".go",
        "compile_cmd": "go build {path}",
    },
    "rust": {
        "version": "0.1",
        "status": "stub",
        "description": "Fuzzing, parsers, memory-safe tools",
        "module": "hado.backends.rust_transpiler",
        "class": "RustTranspiler",
        "extension": ".rs",
        "compile_cmd": "rustc {path}",
    },
    "c": {
        "version": "0.1",
        "status": "funcional",
        "description": "Exploits, shellcode, kernel modules",
        "module": "hado.backends.c_transpiler",
        "class": "CTranspiler",
        "extension": ".c",
        "compile_cmd": "gcc -o output {path}",
    },
}


def get_backend(target: str, ast: Program) -> "BaseTranspiler":
    """
    Retorna el transpiler correcto segun el target, usando el registry.

    Agregar un nuevo lenguaje = agregar una entrada en _BACKEND_REGISTRY.
    Esta funcion no necesita modificarse nunca.

    Args:
        target: nombre del target (ej. "python", "go", "rust", "c")
        ast: AST del programa Hado

    Returns:
        Instancia del transpiler para ese target

    Raises:
        ValueError: si el target no existe en el registry
    """
    target = target.lower()
    entry = _BACKEND_REGISTRY.get(target)
    if entry is None:
        valid = ", ".join(_BACKEND_REGISTRY.keys())
        raise ValueError(f"Target desconocido: '{target}'. Opciones: {valid}")
    mod = importlib.import_module(entry["module"])
    cls = getattr(mod, entry["class"])
    return cls(ast)


def list_backends() -> dict[str, dict]:
    """Devuelve el registry de todos los backends disponibles."""
    return {k: {kk: vv for kk, vv in v.items() if kk not in ("module", "class")}
            for k, v in _BACKEND_REGISTRY.items()}


__all__ = ["HadoBackend", "get_backend", "list_backends", "_BACKEND_REGISTRY"]
