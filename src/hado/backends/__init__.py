"""
Hado DSL — Factory de backends de transpilacion.

El registry central vive en base.py. Para agregar un nuevo target:
  1. Crear backends/<lang>_transpiler.py con la clase del transpiler
  2. Agregar una entrada en base._BACKEND_REGISTRY
  3. Listo — get_backend("lang", ast) funciona automaticamente

Backends disponibles (ver base._BACKEND_REGISTRY para la lista completa):
  python  Scripting, OSINT, automatizacion
  go      Scanners concurrentes, binarios standalone
  rust    Fuzzing, parsers, memory-safe tools
  c       Exploits, shellcode, kernel modules
"""

from .base import get_backend, list_backends, _BACKEND_REGISTRY

# TARGETS expuesto por compatibilidad con codigo existente
TARGETS = list_backends()

__all__ = ["get_backend", "list_backends", "TARGETS", "_BACKEND_REGISTRY"]
