"""
Hado DSL — Normalizacion ASCII.

Convierte caracteres especiales del espanol a sus equivalentes ASCII.
La normalizacion se aplica SOLO a codigo (fuera de string literals),
preservando el contenido de strings tal cual.
"""

import re

NORMALIZATIONS = {
    "ñ": "nh",
    "Ñ": "Nh",
    "á": "a",
    "Á": "A",
    "é": "e",
    "É": "E",
    "í": "i",
    "Í": "I",
    "ó": "o",
    "Ó": "O",
    "ú": "u",
    "Ú": "U",
    "ü": "u",
    "Ü": "U",
    "¿": "",
    "¡": "",
}

# Regex para detectar string literals (preservar su contenido)
_STRING_PATTERN = re.compile(
    r'("""[\s\S]*?"""|'       # triple double quote
    r"'''[\s\S]*?'''|"        # triple single quote
    r'"(?:[^"\\]|\\.)*"|'     # double quote
    r"'(?:[^'\\]|\\.)*')",    # single quote
    re.DOTALL,
)


def normalize(source: str) -> str:
    """Normaliza diacriticos en codigo Hado, preservando strings literales."""
    parts = _STRING_PATTERN.split(source)
    result = []
    for i, part in enumerate(parts):
        if i % 2 == 0:
            # Segmento de codigo — aplicar normalizaciones
            for char, replacement in NORMALIZATIONS.items():
                part = part.replace(char, replacement)
        # Segmentos impares son string literals — preservar intactos
        result.append(part)
    return "".join(result)
