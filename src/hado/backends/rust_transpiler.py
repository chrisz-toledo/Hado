"""
Hado DSL — Backend Rust.
Genera codigo Rust 2021 edition a partir del AST de Hado.

Cargo.toml requerido para codigo generado que usa HTTP:
  [dependencies]
  reqwest = { version = "0.11", features = ["blocking", "json"] }
"""

from __future__ import annotations
from typing import List, Optional, Set

from ..transpiler import BaseTranspiler
from ..ast_nodes import *


class RustTranspiler(BaseTranspiler):
    """
    Genera codigo Rust 2021 edition.

    El codigo generado se envuelve en fn main() si no hay una fn main definida.
    Variables son let (inmutables) por defecto; el transpiler usa let mut
    cuando detecta reasignacion (simplificacion: siempre usa let mut para
    variables que podrian reasignarse).
    """

    def __init__(self, ast: Program):
        super().__init__(ast)
        self._has_main = False
        self._uses: Set[str] = set()
        self._uses_result = False  # si main debe retornar Result

    def emit(self) -> str:
        body_lines = self._visit_program(self.ast)
        body = "\n".join(body_lines)

        # Construir use statements
        use_lines = sorted(f"use {u};" for u in self._uses)
        uses = "\n".join(use_lines)

        # Cargo.toml hint como comentario
        cargo_hint = self._emit_cargo_hint()

        if self._has_main:
            return f"{cargo_hint}{uses}\n\n{body}" if uses else f"{cargo_hint}{body}"

        # Envolver en main
        indent = "    "
        indented_body = "\n".join(indent + line if line else "" for line in body.splitlines())

        if self._uses_result:
            main_sig = "fn main() -> Result<(), Box<dyn std::error::Error>>"
            main_end = "    Ok(())\n}"
        else:
            main_sig = "fn main()"
            main_end = "}"

        header = f"{cargo_hint}{uses}\n\n" if uses else f"{cargo_hint}"
        return f"{header}{main_sig} {{\n{indented_body}\n{main_end}"

    def _emit_cargo_hint(self) -> str:
        if "reqwest::blocking" not in self._uses and "reqwest" not in str(self._uses):
            return ""
        return """\
// Cargo.toml requerido:
// [dependencies]
// reqwest = { version = "0.11", features = ["blocking", "json"] }
// serde_json = "1"

"""

    # ─── Visitors ────────────────────────────────────────────────────────────

    def _visit(self, node: Node) -> str:
        method = f"_visit_{type(node).__name__}"
        visitor = getattr(self, method, self._visit_unknown)
        return visitor(node)

    def _visit_unknown(self, node: Node) -> str:
        return f"// TODO: {type(node).__name__}"

    def _visit_program(self, node: Program) -> List[str]:
        lines = []
        for stmt in node.statements:
            result = self._visit(stmt)
            if result:
                lines.append(result)
        return lines

    def _ind(self) -> str:
        base = "" if self._has_main else "    "
        return base + "    " * self._indent

    # ─── Statements ──────────────────────────────────────────────────────────

    def _visit_Assignment(self, node: Assignment) -> str:
        value = self._visit(node.value) if node.value else "None"
        return f"{self._ind()}let mut {node.name} = {value};"

    def _visit_ShowStatement(self, node: ShowStatement) -> str:
        if node.values:
            fmt_str = " ".join("{}" for _ in node.values)
            args = ", ".join(self._visit(v) for v in node.values)
            return f'{self._ind()}println!("{fmt_str}", {args});'
        val = self._visit(node.value) if node.value is not None else "_pipe_input"
        return f'{self._ind()}println!("{{}}", {val});'

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
        lines = [f"{self._ind()}while {cond} {{"]
        self._indent += 1
        for stmt in node.body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        lines.append(f"{self._ind()}}}")
        return "\n".join(lines)

    def _visit_ForStatement(self, node: ForStatement) -> str:
        iterable = self._visit(node.iterable)
        lines = [f"{self._ind()}for {node.var} in {iterable}.iter() {{"]
        self._indent += 1
        for stmt in node.body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        lines.append(f"{self._ind()}}}")
        return "\n".join(lines)

    def _visit_FunctionDef(self, node: FunctionDef) -> str:
        if node.name == "main":
            self._has_main = True
            lines = ["fn main() {"]
        else:
            params = ", ".join(f"{p}: &str" for p in node.params)
            lines = [f"{self._ind()}fn {node.name}({params}) {{"]
        self._indent += 1
        for stmt in node.body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        lines.append(f"{self._ind()}}}")
        return "\n".join(lines)

    def _visit_ReturnStatement(self, node: ReturnStatement) -> str:
        val = self._visit(node.value) if node.value else ""
        return f"{self._ind()}return {val};".rstrip() + ";"

    def _visit_ExpressionStatement(self, node: ExpressionStatement) -> str:
        if isinstance(node.expr, PipeExpression):
            return self._emit_pipe_chain(node.expr.steps)
        return f"{self._ind()}{self._visit(node.expr)};"

    # ─── Cyber ────────────────────────────────────────────────────────────────

    def _visit_CyberScan(self, node: CyberScan) -> str:
        self._uses.add("std::net::TcpStream")
        self._uses.add("std::time::Duration")
        target = self._visit(node.target) if node.target else '"127.0.0.1"'
        ports = [self._visit(p) for p in node.ports]
        lines = [
            f"{self._ind()}// escanea target {target}",
            f"{self._ind()}let _ports = vec![{', '.join(ports)}u16];",
            f"{self._ind()}for _port in &_ports {{",
            f"{self._ind()}    let _addr = format!(\"{{}}:{{}}\", {target}, _port);",
            f"{self._ind()}    let _timeout = Duration::from_secs(1);",
            f"{self._ind()}    match TcpStream::connect_timeout(&_addr.parse().unwrap(), _timeout) {{",
            f'{self._ind()}        Ok(_) => println!("Port {{}}: open", _port),',
            f'{self._ind()}        Err(_) => println!("Port {{}}: closed", _port),',
            f"{self._ind()}    }}",
            f"{self._ind()}}}",
        ]
        return "\n".join(lines)

    def _visit_HttpGet(self, node: HttpGet) -> str:
        self._uses.add("reqwest::blocking")
        self._uses_result = True
        url = self._visit(node.url) if node.url else '""'
        return f"{self._ind()}let _response = reqwest::blocking::get({url})?.text()?;"

    def _visit_CyberRecon(self, node: CyberRecon) -> str:
        self._uses.add("std::net::ToSocketAddrs")
        domain = self._visit(node.domain) if node.domain else '""'
        prefixes = ["www", "mail", "api", "dev", "admin", "test"]
        lines = [
            f"{self._ind()}// busca subdomains de {domain}",
            f'{self._ind()}let _prefixes = vec![{", ".join(repr(p) for p in prefixes)}];',
            f"{self._ind()}let mut _subdomains: Vec<String> = Vec::new();",
            f"{self._ind()}for _prefix in &_prefixes {{",
            f"{self._ind()}    let _fqdn = format!(\"{{}}.{{}}\", _prefix, {domain});",
            f'{self._ind()}    if (_fqdn.clone() + ":80").to_socket_addrs().is_ok() {{',
            f"{self._ind()}        _subdomains.push(_fqdn);",
            f"{self._ind()}    }}",
            f"{self._ind()}}}",
        ]
        return "\n".join(lines)

    def _visit_GenerateReport(self, node: GenerateReport) -> str:
        data = self._visit(node.data) if node.data else "_data"
        return f'{self._ind()}println!("=== Reporte ===\\n{{:#?}}", {data});'

    # ─── Expresiones ─────────────────────────────────────────────────────────

    def _visit_BinaryOp(self, node: BinaryOp) -> str:
        left = self._visit(node.left)
        right = self._visit(node.right)
        op_map = {"y": "&&", "o": "||", "no": "!", "es": "==", "==": "==",
                  "!=": "!=", ">=": ">=", "<=": "<=", ">": ">", "<": "<",
                  "+": "+", "-": "-", "*": "*", "/": "/", "%": "%"}
        op = op_map.get(node.op, node.op)
        return f"({left} {op} {right})"

    def _visit_UnaryOp(self, node: UnaryOp) -> str:
        operand = self._visit(node.operand)
        op_map = {"no": "!", "-": "-"}
        op = op_map.get(node.op, node.op)
        return f"({op}{operand})"

    def _visit_NumberLiteral(self, node: NumberLiteral) -> str:
        return str(node.value)

    def _visit_StringLiteral(self, node: StringLiteral) -> str:
        return node.value

    def _visit_BooleanLiteral(self, node: BooleanLiteral) -> str:
        return "true" if node.value else "false"

    def _visit_NullLiteral(self, node: NullLiteral) -> str:
        return "None"

    def _visit_ListLiteral(self, node: ListLiteral) -> str:
        elements = ", ".join(self._visit(e) for e in node.elements)
        return f"vec![{elements}]"

    def _visit_Identifier(self, node: Identifier) -> str:
        return node.name

    def _visit_PropertyAccess(self, node: PropertyAccess) -> str:
        obj = self._visit(node.obj)
        return f'{obj}["{node.prop}"]'

    def _visit_FilterExpression(self, node: FilterExpression) -> str:
        cond = self._visit(node.condition)
        src = self._visit(node.iterable) if node.iterable else "_pipe_input"
        return f"{src}.iter().filter(|{node.var}| {cond}).cloned().collect::<Vec<_>>()"

    def _visit_CountExpression(self, node: CountExpression) -> str:
        src = self._visit(node.source) if node.source else "_pipe_input"
        return f"{src}.len()"

    # ─── Pipe chain ──────────────────────────────────────────────────────────

    def _emit_pipe_chain(self, steps: List[Node], target_var: Optional[str] = None) -> str:
        lines = []
        prev_var: Optional[str] = None

        for i, step in enumerate(steps):
            is_last = (i == len(steps) - 1)

            if i == 0:
                if isinstance(step, Identifier):
                    prev_var = step.name
                    continue
                else:
                    out_var = target_var if is_last else self._next_pipe_var()
                    lines.append(f"{self._ind()}let mut {out_var} = {self._visit(step)};")
                    prev_var = out_var
                    continue

            out_var = target_var if is_last else self._next_pipe_var()
            line = self._emit_pipe_step(step, prev_var, out_var)
            if line:
                lines.append(line)
            prev_var = out_var

        return "\n".join(lines)

    def _emit_pipe_step(self, step: Node, prev_var: str, out_var: str) -> str:
        ind = self._ind()
        if isinstance(step, FilterExpression):
            cond = self._visit(step.condition)
            v = step.var
            return f"{ind}let mut {out_var} = {prev_var}.iter().filter(|{v}| {cond}).cloned().collect::<Vec<_>>();"
        elif isinstance(step, ShowStatement):
            return f'{ind}println!("{{}}", {prev_var});'
        elif isinstance(step, SaveStatement):
            fname = self._visit(step.filename) if step.filename else '"output.txt"'
            self._uses.add("std::fs")
            return f"{ind}std::fs::write({fname}, format!(\"{{}}\", {prev_var}))?;"
        elif isinstance(step, CountExpression):
            return f"{ind}let mut {out_var} = {prev_var}.len();"
        elif isinstance(step, GenerateReport):
            return f'{ind}println!("=== Reporte ===\\n{{:#?}}", {prev_var});'
        else:
            return f"{ind}let mut {out_var} = {self._visit(step)};"
