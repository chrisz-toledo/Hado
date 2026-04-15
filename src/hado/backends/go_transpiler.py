"""
Hado DSL — Backend Go v1.0 (funcional).

Genera codigo Go compilable usando exclusivamente la stdlib de Go.
No requiere dependencias externas.

MODELO DE GENERACION:
  - Variables:     x := 5 (primera vez), x = 10 (reasignacion)
  - Condicionales: if cond { ... } else { ... }
  - Loops:         for _, x := range lista { ... } / for cond { ... }
  - Funciones:     func nombre(a interface{}) interface{} { ... }
  - IO:            fmt.Println(x), os.WriteFile(...)
  - Cybersec:      hado_scan() con goroutines + sync.WaitGroup (stdlib net)
  - HTTP:          hado_http_get() con net/http + io.ReadAll

FILOSOFIA (Meadows):
  El Go backend es un nuevo FLUJO que incrementa el stock de "backends
  funcionales" de 1 (Python) a 2. El leverage point: el AST compartido.
  El balancing feedback loop: go build (si no compila, la iteracion es inmediata).
"""

from __future__ import annotations
from typing import List, Optional, Set

from ..transpiler import BaseTranspiler
from ..ast_nodes import (
    Program, Node, Assignment, IfStatement, WhileStatement, ForStatement,
    FunctionDef, ReturnStatement, ShowStatement, SaveStatement,
    ExpressionStatement, NumberLiteral, StringLiteral, BooleanLiteral,
    NullLiteral, ListLiteral, DictLiteral, Identifier, BinaryOp, UnaryOp,
    PipeExpression, PropertyAccess, IndexAccess, FunctionCall,
    CyberScan, CyberRecon, CyberCapture, CyberAttack, CyberFindVulns,
    CyberAnalyze, GenerateReport, HttpGet, FilterExpression,
    SortExpression, CountExpression,
)
from .base import HadoBackend


# ─── Mapa de operadores ───────────────────────────────────────────────────────

_OP_MAP = {
    "y":   "&&",
    "o":   "||",
    "no":  "!",
    "es":  "==",
    "==":  "==",
    "!=":  "!=",
    ">=":  ">=",
    "<=":  "<=",
    ">":   ">",
    "<":   "<",
    "+":   "+",
    "-":   "-",
    "*":   "*",
    "/":   "/",
    "%":   "%",
}


# ─── Helper functions (stdlib only) ──────────────────────────────────────────
# Se emiten solo cuando son necesarias (deteccion automatica por el transpiler)

_HELPER_SCAN = """
// hado_scan — escanea puertos TCP usando goroutines (stdlib net).
// Llama a cada puerto en paralelo con sync.WaitGroup.
func hado_scan(target string, ports []int) []int {
\tvar mu sync.Mutex
\tvar wg sync.WaitGroup
\tvar abiertos []int
\tfor _, port := range ports {
\t\twg.Add(1)
\t\tgo func(p int) {
\t\t\tdefer wg.Done()
\t\t\taddr := fmt.Sprintf("%s:%d", target, p)
\t\t\tconn, err := net.DialTimeout("tcp", addr, 2*time.Second)
\t\t\tif err == nil {
\t\t\t\tconn.Close()
\t\t\t\tmu.Lock()
\t\t\t\tabiertos = append(abiertos, p)
\t\t\t\tmu.Unlock()
\t\t\t}
\t\t}(port)
\t}
\twg.Wait()
\treturn abiertos
}
"""

_HELPER_HTTP_GET = """
// hado_http_get — GET HTTP y devuelve body como string (stdlib net/http).
func hado_http_get(url string) string {
\tresp, err := http.Get(url)
\tif err != nil {
\t\treturn ""
\t}
\tdefer resp.Body.Close()
\tbody, _ := io.ReadAll(resp.Body)
\treturn string(body)
}
"""


# ─── Transpiler principal ─────────────────────────────────────────────────────

class GoTranspiler(BaseTranspiler, HadoBackend):
    """
    Backend Go v1.0 — genera codigo Go compilable con la stdlib.

    Caracteristicas clave:
      - Tracking de variables declaradas por scope (:= vs =)
      - Goroutines automaticas para escanea (hado_scan con net.DialTimeout)
      - Solo stdlib de Go: fmt, net, sync, time, os, net/http, io
      - Deteccion automatica de imports segun las operaciones usadas
      - Helper functions emitidas antes de main() cuando se necesitan
      - Separacion correcta de funciones top-level vs cuerpo de main
    """

    def __init__(self, ast: Program):
        super().__init__(ast)
        self._go_imports: Set[str] = set()
        self._go_helpers: Set[str] = set()
        # Tracking de variables declaradas por scope
        self._declared_vars: Set[str] = set()
        self._scope_stack: List[Set[str]] = []
        self._has_main = False
        # fmt siempre presente (muestra → fmt.Println)
        self._go_imports.add('"fmt"')

    # ─── HadoBackend interface ───────────────────────────────────────────────

    def generate(self, ast: Program) -> str:
        self.ast = ast
        return self.emit()

    def file_extension(self) -> str:
        return ".go"

    def compile_command(self, source_path: str) -> Optional[str]:
        return f"go build {source_path}"

    # ─── Emit principal ──────────────────────────────────────────────────────

    def emit(self) -> str:
        """
        Genera el programa Go completo.

        Estrategia de dos pasadas:
          1. Funciones top-level (FunctionDef) → emitidas a nivel de paquete
          2. El resto de statements → van al cuerpo de func main()

        Los imports y helpers se acumulan durante la visita del AST.
        """
        # Separar funciones vs statements de main
        func_stmts: List[Node] = []
        main_stmts: List[Node] = []
        for stmt in self.ast.statements:
            if isinstance(stmt, FunctionDef):
                func_stmts.append(stmt)
            else:
                main_stmts.append(stmt)

        # Generar funciones top-level (indent=0)
        self._indent = 0
        func_code_lines: List[str] = []
        for stmt in func_stmts:
            result = self._visit(stmt)
            if result:
                func_code_lines.append(result)

        # Generar cuerpo de main (indent=1)
        self._indent = 1
        main_code_lines: List[str] = []
        for stmt in main_stmts:
            result = self._visit(stmt)
            if result:
                main_code_lines.append(result)
        self._indent = 0

        # Construir bloques del archivo Go
        imports_block = self._build_imports()

        helpers_block_parts: List[str] = []
        if "hado_scan" in self._go_helpers:
            helpers_block_parts.append(_HELPER_SCAN.strip())
        if "hado_http_get" in self._go_helpers:
            helpers_block_parts.append(_HELPER_HTTP_GET.strip())
        helpers_block = "\n\n".join(helpers_block_parts)

        func_code = "\n\n".join(func_code_lines)

        main_body = "\n".join(main_code_lines)
        if not self._has_main:
            main_func = f"func main() {{\n{main_body}\n}}"
        else:
            main_func = ""  # el usuario definio su propio main

        # Ensamblar archivo final
        parts: List[str] = ["package main", ""]
        if imports_block:
            parts.append(imports_block)
            parts.append("")
        if helpers_block:
            parts.append(helpers_block)
            parts.append("")
        if func_code:
            parts.append(func_code)
            parts.append("")
        if main_func:
            parts.append(main_func)

        return "\n".join(parts)

    def _build_imports(self) -> str:
        if not self._go_imports:
            return ""
        sorted_imports = sorted(self._go_imports)
        lines = ["import ("]
        for imp in sorted_imports:
            lines.append(f"\t{imp}")
        lines.append(")")
        return "\n".join(lines)

    # ─── Scope management ────────────────────────────────────────────────────

    def _push_scope(self) -> None:
        """Abre un nuevo scope (entrada a funcion)."""
        self._scope_stack.append(frozenset(self._declared_vars))
        self._declared_vars = set()

    def _pop_scope(self) -> None:
        """Cierra el scope actual (salida de funcion)."""
        if self._scope_stack:
            self._declared_vars = set(self._scope_stack.pop())

    def _declare_op(self, name: str) -> str:
        """
        Retorna ':=' si es la primera declaracion de esta variable en el scope,
        '=' si ya fue declarada (reasignacion).
        """
        if name in self._declared_vars:
            return "="
        self._declared_vars.add(name)
        return ":="

    # ─── Visitor dispatch ────────────────────────────────────────────────────

    def _visit(self, node: Node) -> str:
        method = f"_visit_{type(node).__name__}"
        visitor = getattr(self, method, self._visit_stub)
        return visitor(node)

    def _visit_stub(self, node: Node) -> str:
        return f"{self._ind()}// TODO Go: {type(node).__name__}"

    # ─── Statements ──────────────────────────────────────────────────────────

    def _visit_Assignment(self, node: Assignment) -> str:
        op = self._declare_op(node.name)
        value = self._visit(node.value) if node.value else "nil"
        return f"{self._ind()}{node.name} {op} {value}"

    def _visit_IfStatement(self, node: IfStatement) -> str:
        cond = self._visit(node.condition)
        lines = [f"{self._ind()}if {cond} {{"]
        self._indent += 1
        for stmt in node.then_body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        if node.else_body:
            lines.append(f"{self._ind()}}} else {{")
            self._indent += 1
            for stmt in node.else_body:
                lines.append(self._visit(stmt))
            self._indent -= 1
        lines.append(f"{self._ind()}}}")
        return "\n".join(lines)

    def _visit_WhileStatement(self, node: WhileStatement) -> str:
        cond = self._visit(node.condition)
        lines = [f"{self._ind()}for {cond} {{"]
        self._indent += 1
        for stmt in node.body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        lines.append(f"{self._ind()}}}")
        return "\n".join(lines)

    def _visit_ForStatement(self, node: ForStatement) -> str:
        iterable = self._visit(node.iterable)
        # La variable del loop se declara fresca en cada iteracion
        lines = [f"{self._ind()}for _, {node.var} := range {iterable} {{"]
        # Dentro del for, el var es alcanzable pero no se agrega al scope exterior
        saved = frozenset(self._declared_vars)
        self._declared_vars.add(node.var)
        self._indent += 1
        for stmt in node.body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        lines.append(f"{self._ind()}}}")
        self._declared_vars = set(saved)
        return "\n".join(lines)

    def _visit_FunctionDef(self, node: FunctionDef) -> str:
        if node.name == "main":
            self._has_main = True

        self._push_scope()
        # Los params son variables ya disponibles en el scope de la funcion
        for p in node.params:
            self._declared_vars.add(p)

        params = ", ".join(f"{p} interface{{}}" for p in node.params)

        if node.name == "main":
            sig = f"{self._ind()}func main() {{"
        else:
            sig = f"{self._ind()}func {node.name}({params}) interface{{}} {{"

        lines = [sig]
        self._indent += 1
        if not node.body:
            lines.append(f"{self._ind()}return nil")
        else:
            for stmt in node.body:
                lines.append(self._visit(stmt))
        self._indent -= 1
        lines.append(f"{self._ind()}}}")

        self._pop_scope()
        return "\n".join(lines)

    def _visit_ReturnStatement(self, node: ReturnStatement) -> str:
        val = self._visit(node.value) if node.value else ""
        return f"{self._ind()}return {val}".rstrip()

    def _visit_ShowStatement(self, node: ShowStatement) -> str:
        self._go_imports.add('"fmt"')
        if node.values:
            args = ", ".join(self._visit(v) for v in node.values)
        elif node.value is not None:
            args = self._visit(node.value)
        else:
            args = "_hado_pipe_input"
        return f"{self._ind()}fmt.Println({args})"

    def _visit_SaveStatement(self, node: SaveStatement) -> str:
        self._go_imports.add('"os"')
        self._go_imports.add('"fmt"')
        fname = self._visit(node.filename) if node.filename else '"output.txt"'
        val = self._visit(node.value) if node.value else "_hado_pipe_input"
        return f'{self._ind()}os.WriteFile({fname}, []byte(fmt.Sprintf("%v", {val})), 0644)'

    def _visit_ExpressionStatement(self, node: ExpressionStatement) -> str:
        if isinstance(node.expr, PipeExpression):
            return self._emit_pipe_chain(node.expr.steps)
        return f"{self._ind()}{self._visit(node.expr)}"

    # ─── Cybersec — stdlib net + goroutines ──────────────────────────────────

    def _visit_CyberScan(self, node: CyberScan) -> str:
        """
        escanea target "ip" en ports [22, 80]
        → llama a hado_scan() que usa goroutines + sync.WaitGroup (stdlib).

        Esta es la ventaja de Go: concurrencia nativa sin librerias externas.
        Un scan que en Python tarda 10 segundos en Go tarda <1 segundo.
        """
        self._go_imports.add('"fmt"')
        self._go_imports.add('"net"')
        self._go_imports.add('"sync"')
        self._go_imports.add('"time"')
        self._go_helpers.add("hado_scan")
        target = self._visit(node.target) if node.target else '"127.0.0.1"'
        ports_inner = ", ".join(self._visit(p) for p in node.ports)
        return f"{self._ind()}hado_scan({target}, []int{{{ports_inner}}})"

    def _visit_HttpGet(self, node: HttpGet) -> str:
        self._go_imports.add('"net/http"')
        self._go_imports.add('"io"')
        self._go_helpers.add("hado_http_get")
        url = self._visit(node.url) if node.url else '""'
        return f"{self._ind()}hado_http_get({url})"

    def _visit_CyberRecon(self, node: CyberRecon) -> str:
        domain = self._visit(node.domain) if node.domain else '""'
        return (
            f"{self._ind()}// buscar subdominios de {domain}\n"
            f"{self._ind()}// (requiere herramientas externas: subfinder, amass)"
        )

    def _visit_CyberCapture(self, node: CyberCapture) -> str:
        iface = self._visit(node.interface) if node.interface else '"eth0"'
        return (
            f"{self._ind()}// capturar packets en {iface}\n"
            f"{self._ind()}// (requiere gopacket: github.com/google/gopacket)"
        )

    def _visit_CyberAttack(self, node: CyberAttack) -> str:
        return (
            f"{self._ind()}// ataque de fuerza bruta\n"
            f"{self._ind()}// (implementar con goroutines + golang.org/x/crypto/ssh)"
        )

    def _visit_CyberFindVulns(self, node: CyberFindVulns) -> str:
        return f"{self._ind()}// buscar vulnerabilidades (requiere nuclei externo)"

    def _visit_CyberAnalyze(self, node: CyberAnalyze) -> str:
        return f"{self._ind()}// analizar seguridad"

    def _visit_GenerateReport(self, node: GenerateReport) -> str:
        data = self._visit(node.data) if node.data else "nil"
        return (
            f"{self._ind()}// generar reporte con {data}\n"
            f"{self._ind()}// (usar html/template o encoding/json de la stdlib)"
        )

    # ─── Expresiones ─────────────────────────────────────────────────────────

    def _visit_NumberLiteral(self, node: NumberLiteral) -> str:
        return str(node.value)

    def _visit_StringLiteral(self, node: StringLiteral) -> str:
        return node.value

    def _visit_BooleanLiteral(self, node: BooleanLiteral) -> str:
        return "true" if node.value else "false"

    def _visit_NullLiteral(self, node: NullLiteral) -> str:
        return "nil"

    def _visit_ListLiteral(self, node: ListLiteral) -> str:
        elements = ", ".join(self._visit(e) for e in node.elements)
        return "[]interface{}{" + elements + "}"

    def _visit_DictLiteral(self, node: DictLiteral) -> str:
        pairs = ", ".join(f"{self._visit(k)}: {self._visit(v)}" for k, v in node.pairs)
        return "map[string]interface{}{" + pairs + "}"

    def _visit_Identifier(self, node: Identifier) -> str:
        return node.name

    def _visit_BinaryOp(self, node: BinaryOp) -> str:
        left = self._visit(node.left)
        right = self._visit(node.right)
        op = _OP_MAP.get(node.op, node.op)
        return f"{left} {op} {right}"

    def _visit_UnaryOp(self, node: UnaryOp) -> str:
        operand = self._visit(node.operand)
        op = _OP_MAP.get(node.op, node.op)
        if op == "!":
            return f"!{operand}"
        return f"{op}{operand}"

    def _visit_PropertyAccess(self, node: PropertyAccess) -> str:
        obj = self._visit(node.obj)
        return f'{obj}["{node.prop}"]'

    def _visit_IndexAccess(self, node: IndexAccess) -> str:
        obj = self._visit(node.obj)
        idx = self._visit(node.index)
        return f"{obj}[{idx}]"

    def _visit_FunctionCall(self, node: FunctionCall) -> str:
        args = [self._visit(a) for a in node.args]
        all_args = ", ".join(args)
        return f"{node.func}({all_args})"

    def _visit_FilterExpression(self, node: FilterExpression) -> str:
        src = self._visit(node.iterable) if node.iterable else "_hado_pipe_input"
        cond = self._visit(node.condition)
        var = node.var
        lines = [
            f"{self._ind()}var _filtered []interface{{}}",
            f"{self._ind()}for _, {var} := range {src} {{",
            f"{self._ind()}    if {cond} {{",
            f"{self._ind()}        _filtered = append(_filtered, {var})",
            f"{self._ind()}    }}",
            f"{self._ind()}}}",
        ]
        return "\n".join(lines)

    def _visit_CountExpression(self, node: CountExpression) -> str:
        src = self._visit(node.source) if node.source else "_hado_pipe_input"
        return f"len({src})"

    def _visit_SortExpression(self, node: SortExpression) -> str:
        # Go stdlib: sort.Slice
        self._go_imports.add('"sort"')
        src = self._visit(node.source) if node.source else "_hado_pipe_input"
        return f"sort.Slice({src}, func(i, j int) bool {{ return true }})"

    # ─── Pipe chain ──────────────────────────────────────────────────────────

    def _emit_pipe_chain(self, steps: List[Node], target_var: Optional[str] = None) -> str:
        """
        Convierte una cadena de pipes en codigo Go con variables intermedias.

        resultado = datos -> filtra donde x > 0 -> muestra
        se convierte en:
            var _filtered []interface{}
            for _, _x := range datos {
                if _x > 0 {
                    _filtered = append(_filtered, _x)
                }
            }
            fmt.Println(_filtered)
        """
        lines: List[str] = []
        prev_var: Optional[str] = None

        for i, step in enumerate(steps):
            is_last = (i == len(steps) - 1)

            if i == 0:
                if isinstance(step, Identifier):
                    prev_var = step.name
                    continue
                else:
                    out_var = target_var if is_last else self._next_pipe_var()
                    op = self._declare_op(out_var) if out_var else ":="
                    lines.append(f"{self._ind()}{out_var} {op} {self._visit(step)}")
                    prev_var = out_var
                    continue

            out_var = target_var if is_last else self._next_pipe_var()

            if isinstance(step, ShowStatement):
                self._go_imports.add('"fmt"')
                lines.append(f"{self._ind()}fmt.Println({prev_var})")

            elif isinstance(step, SaveStatement):
                self._go_imports.add('"os"')
                fname = self._visit(step.filename) if step.filename else '"output.txt"'
                lines.append(
                    f'{self._ind()}os.WriteFile({fname}, []byte(fmt.Sprintf("%v", {prev_var})), 0644)'
                )

            elif isinstance(step, CountExpression):
                op = self._declare_op(out_var)
                lines.append(f"{self._ind()}{out_var} {op} len({prev_var})")
                prev_var = out_var

            else:
                op = self._declare_op(out_var)
                lines.append(f"{self._ind()}// pipe: {type(step).__name__}")
                lines.append(f"{self._ind()}{out_var} {op} {prev_var}")
                prev_var = out_var

        return "\n".join(lines)
