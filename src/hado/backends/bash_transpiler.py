"""
Hado DSL — Backend Bash.
Genera codigo Bash para ataques "Living off the Land" en Unix.
"""

from __future__ import annotations
from typing import List

from ..transpiler import BaseTranspiler
from ..ast_nodes import *

class BashTranspiler(BaseTranspiler):
    def emit(self) -> str:
        lines = ["#!/usr/bin/env bash", "set -e", ""]
        for stmt in self.ast.statements:
            result = self._visit(stmt)
            if result:
                lines.append(result)
        return "\n".join(lines) + "\n"

    def _ind(self) -> str:
        return "    " * self._indent

    def _visit(self, node: Node) -> str:
        method = f"_visit_{type(node).__name__}"
        visitor = getattr(self, method, self._visit_unknown)
        return visitor(node)

    def _visit_unknown(self, node: Node) -> str:
        raise NotImplementedError(f"Node not implemented in Bash backend: {type(node).__name__}")

    def _visit_Assignment(self, node: Assignment) -> str:
        val = self._visit(node.value) if node.value else '""'
        if isinstance(node.value, (ListLiteral, DictLiteral)):
            return f"{self._ind()}{node.name}=({val})"
        return f"{self._ind()}{node.name}={val}"

    def _visit_ShowStatement(self, node: ShowStatement) -> str:
        if not node.values and node.value is None:
            return f"{self._ind()}cat"
        vals = node.values if node.values else [node.value]
        rendered = " ".join(self._visit(v) for v in vals)
        return f"{self._ind()}echo -e {rendered}"

    def _visit_IfStatement(self, node: IfStatement) -> str:
        cond = self._visit(node.condition)
        lines = [f"{self._ind()}if [[ {cond} ]]; then"]
        self._indent += 1
        for stmt in node.then_body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        if node.else_body:
            lines.append(f"{self._ind()}else")
            self._indent += 1
            for stmt in node.else_body:
                lines.append(self._visit(stmt))
            self._indent -= 1
        lines.append(f"{self._ind()}fi")
        return "\n".join(lines)

    def _visit_WhileStatement(self, node: WhileStatement) -> str:
        cond = self._visit(node.condition)
        lines = [f"{self._ind()}while [[ {cond} ]]; do"]
        self._indent += 1
        for stmt in node.body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        lines.append(f"{self._ind()}done")
        return "\n".join(lines)

    def _visit_ForStatement(self, node: ForStatement) -> str:
        iterable = self._visit(node.iterable)
        # Convertir array de bash a items
        if iterable.startswith("${") and iterable.endswith("}"):
            iterable = f"\"${{{iterable[2:-1]}[@]}}\""
        lines = [f"{self._ind()}for {node.var} in {iterable}; do"]
        self._indent += 1
        for stmt in node.body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        lines.append(f"{self._ind()}done")
        return "\n".join(lines)

    def _visit_FunctionDef(self, node: FunctionDef) -> str:
        lines = [f"{self._ind()}{node.name}() {{"]
        self._indent += 1
        if node.params:
            for i, p in enumerate(node.params):
                lines.append(f"{self._ind()}local {p}=${i+1}")
        for stmt in node.body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        lines.append(f"{self._ind()}}}")
        if node.name == "main":
            lines.append(f"{self._ind()}main \"$@\"")
        return "\n".join(lines)

    def _visit_ReturnStatement(self, node: ReturnStatement) -> str:
        if node.value:
            val = self._visit(node.value)
            return f"{self._ind()}echo {val}; return 0"
        return f"{self._ind()}return 0"

    def _visit_SaveStatement(self, node: SaveStatement) -> str:
        fname = self._visit(node.filename) if node.filename else "out.txt"
        val = self._visit(node.value) if node.value else '"$_pipe"'
        return f"{self._ind()}echo {val} > {fname}"

    # ─── Cyber ────────────────────────────────────────────────────────────────

    def _visit_CyberScan(self, node: CyberScan) -> str:
        target = self._visit(node.target) if node.target else "127.0.0.1"
        ports = " ".join(self._visit(p) for p in node.ports)
        lines = [
            f"{self._ind()}for port in {ports}; do",
            f"{self._ind()}    if nc -z -w 1 {target} $port 2>/dev/null; then",
            f'{self._ind()}        echo "Port $port: open"',
            f"{self._ind()}    else",
            f'{self._ind()}        echo "Port $port: closed"',
            f"{self._ind()}    fi",
            f"{self._ind()}done"
        ]
        return "\n".join(lines)

    def _visit_CyberRecon(self, node: CyberRecon) -> str:
        domain = self._visit(node.domain) if node.domain else "example.com"
        return f'{self._ind()}echo "[hado] DNS Recon on {domain}:"; dig +short {domain}'

    def _visit_CyberAttack(self, node: CyberAttack) -> str:
        target = self._visit(node.target) if node.target else "127.0.0.1"
        username = self._visit(node.username) if node.username else "admin"
        wordlist = self._visit(node.wordlist) if node.wordlist else '"admin" "password" "123456"'
        lines = [
            f"{self._ind()}for pass in {wordlist}; do",
            f"{self._ind()}    res=$(curl -s -o /dev/null -w \"%{{http_code}}\" -u \"{username}:$pass\" {target} || true)",
            f"{self._ind()}    if [[ \"$res\" == \"200\" ]]; then",
            f'{self._ind()}        echo "[hado] Brute success: {username}:$pass"',
            f"{self._ind()}        break",
            f"{self._ind()}    fi",
            f"{self._ind()}done"
        ]
        return "\n".join(lines)

    def _visit_CyberCapture(self, node: CyberCapture) -> str:
        iface = self._visit(node.interface) if node.interface else "eth0"
        return f'{self._ind()}echo "[hado] Starting capture on {iface}"; tcpdump -i {iface} -nn -c 10 2>/dev/null || echo "Requiere root"'

    def _visit_CyberEnumerate(self, node: CyberEnumerate) -> str:
        target = self._visit(node.target) if node.target else "http://127.0.0.1"
        wordlist = self._visit(node.wordlist) if node.wordlist else '"admin" "login"'
        lines = [
            f"{self._ind()}for dir in {wordlist}; do",
            f"{self._ind()}    res=$(curl -s -o /dev/null -w \"%{{http_code}}\" {target}/$dir || true)",
            f"{self._ind()}    if [[ \"$res\" != \"404\" && \"$res\" != \"000\" ]]; then",
            f'{self._ind()}        echo "[hado] Found: {target}/$dir [$res]"',
            f"{self._ind()}    fi",
            f"{self._ind()}done"
        ]
        return "\n".join(lines)

    def _visit_CyberAnalyze(self, node: CyberAnalyze) -> str:
        target = self._visit(node.source) if node.source else "http://127.0.0.1"
        return f'{self._ind()}echo "[hado] Headers for {target}"; curl -I -s {target}'

    def _visit_CyberFindVulns(self, node: CyberFindVulns) -> str:
        target = self._visit(node.target) if node.target else "target"
        return f'{self._ind()}echo "[hado] Scanning vulns on {target} (integrate nmap/nuclei)"'

    def _visit_GenerateReport(self, node: GenerateReport) -> str:
        data = self._visit(node.data) if node.data else "{}"
        fname = node.output_file if hasattr(node, 'output_file') and node.output_file else "report.json"
        return f'{self._ind()}echo "{{\\"data\\": \\"{data}\\"}}" > "{fname}"; echo "[hado] Report saved to {fname}"'

    def _visit_HttpGet(self, node: HttpGet) -> str:
        url = self._visit(node.url) if node.url else '""'
        return f"$(curl -s {url})"

    def _visit_HttpPost(self, node: HttpPost) -> str:
        url = self._visit(node.url) if node.url else '""'
        body = self._visit(node.body) if node.body else '""'
        return f"$(curl -s -X POST -d {body} {url})"

    def _visit_ExpressionStatement(self, node: ExpressionStatement) -> str:
        return f"{self._ind()}{self._visit(node.expr)}"

    # ─── Expresiones ─────────────────────────────────────────────────────────

    def _visit_BinaryOp(self, node: BinaryOp) -> str:
        left = self._visit(node.left)
        right = self._visit(node.right)
        op_map = {"y": "&&", "o": "||", "no": "!", "es": "==", "==": "==", "!=": "!=", ">=": ">=", "<=": "<=", ">": ">", "<": "<"}
        op = op_map.get(node.op, node.op)
        return f'{left} {op} {right}'

    def _visit_UnaryOp(self, node: UnaryOp) -> str:
        op = "!" if node.op == "no" else "-"
        return f"{op}{self._visit(node.operand)}"

    def _visit_NumberLiteral(self, node: NumberLiteral) -> str:
        return str(node.value)

    def _visit_StringLiteral(self, node: StringLiteral) -> str:
        return node.value

    def _visit_BooleanLiteral(self, node: BooleanLiteral) -> str:
        return '"true"' if node.value else '"false"'

    def _visit_NullLiteral(self, node: NullLiteral) -> str:
        return '""'

    def _visit_Identifier(self, node: Identifier) -> str:
        return f"${node.name}"

    def _visit_ListLiteral(self, node: ListLiteral) -> str:
        return " ".join(self._visit(e) for e in node.elements)

    def _visit_DictLiteral(self, node: DictLiteral) -> str:
        pairs = []
        for k, v in node.pairs:
            pairs.append(f"{self._visit(k)}:{self._visit(v)}")
        return '"' + ", ".join(pairs) + '"'

    def _visit_PropertyAccess(self, node: PropertyAccess) -> str:
        return f"{self._visit(node.obj)}_{node.prop}"

    def _visit_IndexAccess(self, node: IndexAccess) -> str:
        obj = self._visit(node.obj).lstrip('$')
        idx = self._visit(node.index)
        return f"${{{obj}[{idx}]}}"

    def _visit_FunctionCall(self, node: FunctionCall) -> str:
        args = " ".join(self._visit(a) for a in node.args)
        return f"$({node.func} {args})"

    def _visit_PipeExpression(self, node: PipeExpression) -> str:
        steps = [self._visit(s) for s in node.steps]
        pipe_str = " | ".join(steps)
        if isinstance(node.steps[-1], (ShowStatement, SaveStatement)):
            return pipe_str
        return f"$(echo \"${{{self._visit(node.steps[0]).lstrip('$')}}}\" | " + " | ".join(steps[1:]) + ")"

    def _visit_FilterExpression(self, node: FilterExpression) -> str:
        cond = self._visit(node.condition).replace('"', '\\"')
        return f"awk '{{if({cond}) print $0}}'"

    def _visit_SortExpression(self, node: SortExpression) -> str:
        return "sort"

    def _visit_CountExpression(self, node: CountExpression) -> str:
        return "wc -l"
