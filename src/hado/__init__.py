"""
Hado DSL — A cybersecurity DSL designed for AI-native code generation.
Spanish verbs. English nouns. Zero boilerplate.
Transpiles to Python, C, and Rust.
"""

__version__ = "0.1.0"
__author__ = "Christian Toledo"
__license__ = "MIT"

from .runtime import run, run_source, compile_to_source
from .transpiler import BaseTranspiler

__all__ = [
    "__version__",
    "run",
    "run_source",
    "compile_to_source",
    "BaseTranspiler",
]
