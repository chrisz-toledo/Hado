"""
Habla DSL — Lexer / Tokenizador.

Convierte codigo fuente Habla en una secuencia de tokens.
Maneja INDENT/DEDENT basado en indentacion (estilo Python).
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import List

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
    "fn", "devuelve",
    # Operaciones de display / IO
    "muestra", "guarda", "lee", "abre",
    # Operaciones de datos
    "filtra", "ordena", "agrupa", "cuenta", "suma",
    "crea", "borra", "actualiza", "envia",
    # Ciberseguridad
    "escanea", "busca", "captura", "ataca", "intercepta", "analiza", "genera",
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
    def __init__(self, source: str, filename: str = "<input>"):
        self.source = source
        self.filename = filename

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
                raise LexerError(
                    fmt("invalid_char", char=value, line=line_num),
                    line=line_num, col=col, filename=self.filename,
                )

            token_type = self._classify(group, value)
            tokens.append(Token(token_type, value, line_num, col))

        return tokens

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
