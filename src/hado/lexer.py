"""
Hado DSL — Lexer / Tokenizador.

Convierte codigo fuente Hado en una secuencia de tokens.
Maneja INDENT/DEDENT basado en indentacion (estilo Python).

Robustez v0.5:
  - Acepta comillas simples Y dobles para strings (normaliza a doble)
  - Descarte silencioso de artefactos de terminal / clipboard de macOS:
      * Bracketed paste: ESC[200~ / ESC[201~
      * Secuencias ANSI: ESC[...m
      * Caracteres no imprimibles (0x00-0x08, 0x0b-0x0c, 0x0e-0x1f, 0x7f)
      * Retornos de carro \\r (Windows)
      * UTF-8 BOM (\\ufeff), zero-width spaces (\\u200b-\\u200d)
  - En modo estricto=False (default): UNKNOWN emite advertencia sin abortar
  - En modo estricto=True: comportamiento original (raise LexerError)
"""

from __future__ import annotations
import re
import warnings
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional

from .errors import LexerError, fmt


class TokenType(Enum):
    KEYWORD    = auto()
    IDENTIFIER = auto()
    NUMBER     = auto()
    STRING     = auto()
    OPERATOR   = auto()
    PIPE       = auto()   # ->
    NEWLINE    = auto()
    INDENT     = auto()
    DEDENT     = auto()
    LPAREN     = auto()
    RPAREN     = auto()
    LBRACKET   = auto()
    RBRACKET   = auto()
    LBRACE     = auto()
    RBRACE     = auto()
    COMMA      = auto()
    COLON      = auto()
    DOT        = auto()
    COMMENT    = auto()
    EOF        = auto()


KEYWORDS = frozenset({
    # Control de flujo
    "si", "sino", "mientras", "para", "cada", "en",
    "fn", "devuelve", "retorna",
    # Operaciones de display / IO
    "muestra", "guarda", "lee", "abre",
    # Operaciones de datos
    "filtra", "ordena", "agrupa", "cuenta", "suma",
    "crea", "borra", "actualiza", "envia",
    # Ciberseguridad
    "escanea", "busca", "captura", "ataca", "intercepta", "analiza", "genera", "enumera",
    # Logica
    "cuando", "listos", "espera", "lanza", "atrapa",
    "es", "no", "y", "o", "de", "con", "sin", "como", "donde",
    # Literales
    "cierto", "falso", "nulo", "vacio",
    # HTTP / red
    "desde",
    # Calificadores de cyber (estos son sustantivos — se tratan como keywords SOLO en contexto)
    # NO incluir: target, ports, subdomains, alive, packets, interface, headers,
    #             severity, wordlist, vulns, reporte
    # (se parsean via tok.value == "..." en el parser directamente)
    # Modificadores
    "por", "al", "a",
})


@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    col: int

    def __repr__(self):
        return f"Token({self.type.name}, {self.value!r}, {self.line}:{self.col})"


# ─── Pre-proceso: limpiar artefactos de terminal antes de tokenizar ──────────

# Bracketed paste sequences (macOS Terminal, iTerm2, etc.)
_BRACKETED_PASTE_RE = re.compile(r'\x1b\[200~.*?\x1b\[201~', re.DOTALL)
# ANSI escape sequences (colores, movimiento de cursor, etc.)
_ANSI_ESCAPE_RE = re.compile(r'\x1b(\[[\d;]*[A-Za-z]|[0-9A-Za-z])', re.DOTALL)
# UTF-8 BOM + zero-width spaces + non-printable ASCII control chars
# Incluye: \x00-\x08 (control), \x0b (VT), \x0c (FF), \x0e-\x1f (control),
#          \x7f (DEL), \r (carriage return), \ufeff (BOM), \u200b-\u200d (ZWS)
_INVISIBLE_RE = re.compile(
    r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\r\ufeff\u200b\u200c\u200d]'
)


def clean_source(source: str) -> tuple[str, list[str]]:
    """
    Limpia el código fuente de artefactos invisibles antes del lexing.

    Returns:
        (cleaned_source, list_of_warnings)
        Los warnings son descripciones de lo que fue eliminado.
    """
    warns = []

    # 1. Eliminar bracketed paste sequences completas
    cleaned, n = _BRACKETED_PASTE_RE.subn('', source)
    if n:
        warns.append(f"Se descartaron {n} secuencia(s) de bracketed-paste (ESC[200~/ESC[201~)")
        source = cleaned

    # 2. Eliminar secuencias ANSI de escape
    cleaned, n = _ANSI_ESCAPE_RE.subn('', source)
    if n:
        warns.append(f"Se descartaron {n} secuencia(s) ANSI de terminal")
        source = cleaned

    # 3. Eliminar caracteres no imprimibles (pero preservar \t y \n)
    cleaned, n = _INVISIBLE_RE.subn('', source)
    if n:
        warns.append(f"Se descartaron {n} carácter(es) no imprimible(s)/invisible(s)")
        source = cleaned

    return source, warns


# ─── Patrones del lexer ───────────────────────────────────────────────────────

# Orden importa: PIPE antes de OPERATOR, FLOAT antes de INT, etc.
_TOKEN_PATTERNS = [
    ("COMMENT",      r"//[^\n]*"),
    ("HASH_COMMENT", r"#[^\n]*"),
    ("STRING",     r'"""[\s\S]*?"""|'
                   r"'''[\s\S]*?'''|"
                   r'"(?:[^"\\]|\\.)*"|'
                   r"'(?:[^'\\]|\\.)*'"),
    ("FLOAT",      r"\d+\.\d+"),
    ("INT",        r"\d+"),
    ("PIPE",       r"->"),
    ("VERT_PIPE",  r"\|"),
    ("GE",         r">="),
    ("LE",         r"<="),
    ("EQ",         r"=="),
    ("NE",         r"!="),
    ("GT",         r">"),
    ("LT",         r"<"),
    ("PLUS",       r"\+"),
    ("MINUS",      r"-"),
    ("STAR",       r"\*"),
    ("SLASH",      r"/"),
    ("PERCENT",    r"%"),
    ("ASSIGN",     r"="),
    ("LPAREN",     r"\("),
    ("RPAREN",     r"\)"),
    ("LBRACKET",   r"\["),
    ("RBRACKET",   r"\]"),
    ("LBRACE",     r"\{"),
    ("RBRACE",     r"\}"),
    ("COMMA",      r","),
    ("COLON",      r":"),
    ("DOT",        r"\."),
    ("IDENTIFIER", r"[A-Za-z_][A-Za-z0-9_]*"),
    ("WHITESPACE", r"[ \t]+"),
    ("UNKNOWN",    r"."),
]

_MASTER_REGEX = re.compile(
    "|".join(f"(?P<{name}>{pattern})" for name, pattern in _TOKEN_PATTERNS),
    re.DOTALL,
)

# Grupos que se mapean a OPERATOR
_OPERATOR_GROUPS = frozenset({"GE", "LE", "EQ", "NE", "GT", "LT", "PLUS", "MINUS", "STAR", "SLASH", "PERCENT", "ASSIGN"})
# Grupos que se ignoran
_SKIP_GROUPS = frozenset({"WHITESPACE", "COMMENT", "HASH_COMMENT"})


class Lexer:
    def __init__(self, source: str, filename: str = "<input>", strict: bool = False):
        """
        Args:
            source:   código fuente Hado
            filename: nombre del archivo (para mensajes de error)
            strict:   True = abortar en caracteres desconocidos (v0.1 behavior)
                      False = emitir advertencia y continuar (default desde v0.5)
        """
        # Limpiar artefactos invisibles antes de tokenizar
        self.source, self._clean_warnings = clean_source(source)
        self.filename = filename
        self.strict = strict

    def get_warnings(self) -> List[str]:
        """Retorna advertencias acumuladas (artefactos descartados, etc.)."""
        return list(self._clean_warnings)

    def tokenize(self) -> List[Token]:
        lines = self.source.split("\n")
        tokens: List[Token] = []
        indent_stack: List[int] = [0]
        line_num = 0

        for raw_line in lines:
            line_num += 1
            stripped = raw_line.lstrip()

            # Saltar lineas en blanco y comentarios al medir indentacion
            if not stripped or stripped.startswith("//") or stripped.startswith("#"):
                tokens.append(Token(TokenType.NEWLINE, "", line_num, 0))
                continue

            # Medir indentacion (tabs = 4 espacios)
            col = 0
            for ch in raw_line:
                if ch == " ":
                    col += 1
                elif ch == "\t":
                    col += 4
                else:
                    break

            # Emitir INDENT / DEDENT
            if col > indent_stack[-1]:
                tokens.append(Token(TokenType.INDENT, "", line_num, col))
                indent_stack.append(col)
            elif col < indent_stack[-1]:
                while col < indent_stack[-1]:
                    tokens.append(Token(TokenType.DEDENT, "", line_num, col))
                    indent_stack.pop()
                if col != indent_stack[-1]:
                    raise LexerError(
                        fmt("dedent_error", line=line_num),
                        line=line_num, col=col, filename=self.filename,
                    )

            # Tokenizar el contenido de la linea
            tokens.extend(self._tokenize_line(stripped, line_num, col))
            tokens.append(Token(TokenType.NEWLINE, "", line_num, len(raw_line)))

        # Flush del stack al final
        while indent_stack[-1] > 0:
            tokens.append(Token(TokenType.DEDENT, "", line_num, 0))
            indent_stack.pop()

        tokens.append(Token(TokenType.EOF, "", line_num, 0))
        return tokens

    def _tokenize_line(self, line: str, line_num: int, base_col: int) -> List[Token]:
        tokens = []
        for m in _MASTER_REGEX.finditer(line):
            group = m.lastgroup
            value = m.group()
            col = base_col + m.start()

            if group in _SKIP_GROUPS:
                continue
            if group == "UNKNOWN":
                if self.strict:
                    raise LexerError(
                        fmt("invalid_char", char=value, line=line_num),
                        line=line_num, col=col, filename=self.filename,
                    )
                else:
                    # Modo tolerante: descarte silencioso con advertencia
                    char_repr = repr(value)
                    self._clean_warnings.append(
                        f"Línea {line_num}:{col} — carácter desconocido ignorado: {char_repr}"
                    )
                    continue

            token_type = self._classify(group, value)
            # Normalizar strings a double-quote en lex time
            if token_type == TokenType.STRING:
                value = self._normalize_string(value)
            tokens.append(Token(token_type, value, line_num, col))

        return tokens

    @staticmethod
    def _normalize_string(raw: str) -> str:
        """
        Normaliza cualquier literal de string a comillas dobles.
        Soporta: 'x', "x", '''x''', \"\"\"x\"\"\".
        Garantiza que StringLiteral.value siempre sea "..." para output consistente.
        """
        if raw.startswith('"""') or raw.startswith("'''"):
            inner = raw[3:-3]
        elif raw.startswith("'"):
            # Unescape single quotes, escape double quotes
            inner = raw[1:-1].replace("\\'", "'").replace('"', '\\"')
        else:
            return raw  # ya es double-quoted — sin cambios
        return f'"{inner}"'

    def _classify(self, group: str, value: str) -> TokenType:
        if group == "IDENTIFIER":
            return TokenType.KEYWORD if value in KEYWORDS else TokenType.IDENTIFIER
        if group in ("FLOAT", "INT"):
            return TokenType.NUMBER
        if group == "STRING":
            return TokenType.STRING
        if group in ("PIPE", "VERT_PIPE"):
            return TokenType.PIPE
        if group in _OPERATOR_GROUPS:
            return TokenType.OPERATOR
        # Brackets y puntuacion
        mapping = {
            "LPAREN": TokenType.LPAREN,
            "RPAREN": TokenType.RPAREN,
            "LBRACKET": TokenType.LBRACKET,
            "RBRACKET": TokenType.RBRACKET,
            "LBRACE": TokenType.LBRACE,
            "RBRACE": TokenType.RBRACE,
            "COMMA": TokenType.COMMA,
            "COLON": TokenType.COLON,
            "DOT": TokenType.DOT,
        }
        return mapping.get(group, TokenType.IDENTIFIER)
