"""
Hado DSL — Transpiler base abstracto.
Cada backend (Python, C, Rust) hereda de esta clase.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Set

from .ast_nodes import Program


class ImportTracker:
    """Registra los imports/includes necesarios durante el recorrido del AST."""

    def __init__(self):
        self._modules: Set[str] = set()
        self._helpers: Set[str] = set()

    def need(self, module: str):
        self._modules.add(module)

    def need_helper(self, helper: str):
        self._helpers.add(helper)

    @property
    def modules(self) -> List[str]:
        return sorted(self._modules)

    @property
    def helpers(self) -> List[str]:
        return sorted(self._helpers)


class BaseTranspiler(ABC):
    """Clase base para todos los backends de transpilacion."""

    def __init__(self, ast: Program):
        self.ast = ast
        self.imports = ImportTracker()
        self._indent = 0
        self._pipe_counter = 0

    @abstractmethod
    def emit(self) -> str:
        """Genera el codigo fuente completo para el target."""
        ...

    def _ind(self) -> str:
        return "    " * self._indent

    def _next_pipe_var(self) -> str:
        name = f"_pipe_{self._pipe_counter}"
        self._pipe_counter += 1
        return name
