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
    """
    Normaliza diacriticos en codigo Hado, preservando strings literales.
    También normaliza variantes de comillas tipográficas a ASCII estándar.
    """
    # 1. Normalizar comillas tipográficas a ASCII (frecuentes al copiar de LLMs/web)
    QUOTE_NORMALIZATIONS = {
        "\u201c": '"',   # " comilla doble izquierda
        "\u201d": '"',   # " comilla doble derecha
        "\u2018": "'",   # ' comilla simple izquierda
        "\u2019": "'",   # ' comilla simple derecha
        "\u00ab": '"',   # « guillemet izquierdo
        "\u00bb": '"',   # » guillemet derecho
        "\u2039": "'",   # ‹ single guillemet izquierdo
        "\u203a": "'",   # › single guillemet derecho
        "\u201e": '"',   # „ comilla baja alemana
        "\u2026": "...", # … puntos suspensivos
    }
    for char, replacement in QUOTE_NORMALIZATIONS.items():
        source = source.replace(char, replacement)

    # 2. Normalizar diacríticos y caracteres especiales del español
    #    Solo fuera de string literals
    parts = _STRING_PATTERN.split(source)
    result = []
    for i, part in enumerate(parts):
        if i % 2 == 0:
            # Segmento de código — aplicar normalizaciones
            for char, replacement in NORMALIZATIONS.items():
                part = part.replace(char, replacement)
        # Segmentos impares son string literals — preservar intactos
        result.append(part)
    return "".join(result)
