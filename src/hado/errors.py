"""
Hado DSL — Mensajes de error en espanol.
"""


class HadoError(Exception):
    def __init__(self, message: str, line: int = 0, col: int = 0, filename: str = "<input>"):
        self.message = message
        self.line = line
        self.col = col
        self.filename = filename
        super().__init__(str(self))

    def __str__(self):
        if self.line:
            return f"{self.filename}:{self.line}:{self.col}: {self.message}"
        return self.message


class LexerError(HadoError):
    pass


class ParseError(HadoError):
    pass


class TranspileError(HadoError):
    pass


class HadoRuntimeError(HadoError):
    pass


class IncompleteError(HadoError):
    """Raised when input is incomplete (REPL needs more lines)."""
    pass


ERRORS = {
    "unexpected_token": 'Error: no esperaba "{token}" en linea {line}. Quizas quisiste escribir "{suggestion}"?',
    "undefined_var": "Error: la variable \"{name}\" no existe. Definela primero con: {name} = ...",
    "indent_error": "Error: la indentacion en linea {line} no es correcta. Usa 2 espacios o 1 tab.",
    "dedent_error": "Error: el dedent en linea {line} no corresponde a ningun nivel de indentacion anterior.",
    "pipe_error": 'Error: el pipe "->" necesita algo a la derecha. Ejemplo: datos -> filtra donde x > 0',
    "missing_target": 'Error: "{verb}" necesita un objetivo. Ejemplo: escanea target "192.168.1.1"',
    "unexpected_eof": "Error: fin de archivo inesperado. Falta cerrar un bloque?",
    "invalid_char": 'Error: caracter no reconocido "{char}" en linea {line}.',
    "expected_token": 'Error: se esperaba "{expected}" pero se encontro "{found}" en linea {line}.',
    "missing_indent": "Error: se esperaba un bloque indentado despues de linea {line}.",
}


def fmt(key: str, **kwargs) -> str:
    return ERRORS[key].format(**kwargs)
