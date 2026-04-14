"""
Hado DSL — Nodos del AST.
Todos los nodos son dataclasses inmutables con un campo `line` para tracking de errores.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class Node:
    line: int = 0


# ─── Programa ────────────────────────────────────────────────────────────────

@dataclass
class Program(Node):
    statements: List[Node] = field(default_factory=list)


# ─── Declaraciones ────────────────────────────────────────────────────────────

@dataclass
class Assignment(Node):
    name: str = ""
    value: Optional[Node] = None


@dataclass
class IfStatement(Node):
    condition: Optional[Node] = None
    then_body: List[Node] = field(default_factory=list)
    else_body: List[Node] = field(default_factory=list)


@dataclass
class WhileStatement(Node):
    condition: Optional[Node] = None
    body: List[Node] = field(default_factory=list)


@dataclass
class ForStatement(Node):
    var: str = ""
    iterable: Optional[Node] = None
    body: List[Node] = field(default_factory=list)


@dataclass
class FunctionDef(Node):
    name: str = ""
    params: List[str] = field(default_factory=list)
    body: List[Node] = field(default_factory=list)


@dataclass
class ReturnStatement(Node):
    value: Optional[Node] = None


@dataclass
class ShowStatement(Node):
    """
    muestra X [, Y, Z ...] — imprime uno o varios valores.
    En contexto de pipe: value=None, los valores vienen del step anterior.
    En contexto de statement: values contiene todos los args.
    """
    value: Optional[Node] = None          # compat: pipe context / single arg
    values: List[Node] = field(default_factory=list)  # multi-arg: muestra a, b, c


@dataclass
class SaveStatement(Node):
    """guarda X en "archivo" o como paso de pipe."""
    value: Optional[Node] = None  # None cuando recibe input del pipe
    filename: Optional[Node] = None


@dataclass
class ReadStatement(Node):
    """lee "archivo" """
    filename: Optional[Node] = None


@dataclass
class ExpressionStatement(Node):
    expr: Optional[Node] = None


# ─── Expresiones de pipe ──────────────────────────────────────────────────────

@dataclass
class PipeExpression(Node):
    """X -> Y -> Z"""
    steps: List[Node] = field(default_factory=list)


@dataclass
class FilterExpression(Node):
    """filtra donde cond
    iterable=None significa que recibe input del pipe."""
    iterable: Optional[Node] = None
    condition: Optional[Node] = None
    var: str = "_x"  # variable de iteracion interna


@dataclass
class SortExpression(Node):
    """ordena por campo
    source=None significa que recibe input del pipe."""
    source: Optional[Node] = None
    key: Optional[Node] = None
    reverse: bool = False


@dataclass
class CountExpression(Node):
    """cuenta X"""
    source: Optional[Node] = None


# ─── Ciberseguridad ───────────────────────────────────────────────────────────

@dataclass
class CyberScan(Node):
    """escanea target "ip" en ports [22, 80, 443]"""
    target: Optional[Node] = None
    ports: List[Node] = field(default_factory=list)


@dataclass
class CyberRecon(Node):
    """busca subdomains de "dominio"
    filter_alive=True cuando se agrega -> filtra alive"""
    domain: Optional[Node] = None
    filter_alive: bool = False


@dataclass
class CyberCapture(Node):
    """captura packets en interface "eth0" donde port == 443"""
    interface: Optional[Node] = None
    filter_expr: Optional[Node] = None
    count: Optional[Node] = None


@dataclass
class CyberAttack(Node):
    """ataca ssh en target con wordlist "rockyou.txt" """
    service: Optional[Node] = None
    target: Optional[Node] = None
    username: Optional[Node] = None
    wordlist: Optional[Node] = None


@dataclass
class CyberAnalyze(Node):
    """analiza headers de target"""
    source: Optional[Node] = None
    mode: str = "headers"


@dataclass
class CyberFindVulns(Node):
    """busca vulns en target donde severity >= HIGH"""
    target: Optional[Node] = None
    severity: Optional[Node] = None


@dataclass
class CyberEnumerate(Node):
    """enumera directories en target [usando wordlist]"""
    mode: str = "directories"      # directories | files | endpoints
    target: Optional[Node] = None
    wordlist: Optional[Node] = None
    threads: Optional[Node] = None


@dataclass
class GenerateReport(Node):
    """genera reporte con datos"""
    data: Optional[Node] = None
    options: List[Node] = field(default_factory=list)


# ─── HTTP / red ───────────────────────────────────────────────────────────────

@dataclass
class HttpGet(Node):
    """desde "url" [con headers {...}]"""
    url: Optional[Node] = None
    headers: Optional[Node] = None


@dataclass
class HttpPost(Node):
    """envia a "url" el objeto {...}"""
    url: Optional[Node] = None
    body: Optional[Node] = None
    headers: Optional[Node] = None


# ─── Expresiones ─────────────────────────────────────────────────────────────

@dataclass
class BinaryOp(Node):
    op: str = ""
    left: Optional[Node] = None
    right: Optional[Node] = None


@dataclass
class TernaryExpression(Node):
    """value si condition sino alternative  →  value if condition else alternative"""
    value: Optional[Node] = None
    condition: Optional[Node] = None
    alternative: Optional[Node] = None


@dataclass
class UnaryOp(Node):
    op: str = ""
    operand: Optional[Node] = None


@dataclass
class Identifier(Node):
    name: str = ""


@dataclass
class NumberLiteral(Node):
    value: Any = 0  # int or float


@dataclass
class StringLiteral(Node):
    value: str = ""


@dataclass
class BooleanLiteral(Node):
    value: bool = True


@dataclass
class NullLiteral(Node):
    pass


@dataclass
class ListLiteral(Node):
    elements: List[Node] = field(default_factory=list)


@dataclass
class DictLiteral(Node):
    pairs: List[tuple] = field(default_factory=list)  # List[(key_node, value_node)]


@dataclass
class PropertyAccess(Node):
    obj: Optional[Node] = None
    prop: str = ""


@dataclass
class IndexAccess(Node):
    obj: Optional[Node] = None
    index: Optional[Node] = None


@dataclass
class FunctionCall(Node):
    func: str = ""
    args: List[Node] = field(default_factory=list)
    kwargs: List[tuple] = field(default_factory=list)  # List[(str, Node)]
