"""
Habla DSL — Backend Python.
Convierte el AST a codigo Python ejecutable.
"""

from __future__ import annotations
from typing import List, Optional

from ..transpiler import BaseTranspiler, ImportTracker
from ..ast_nodes import *
from ..errors import TranspileError


# Mapa de imports de modulos estandar
_MODULE_IMPORTS = {
    "requests": "import requests",
    "socket":   "import socket",
    "json":     "import json",
    "os":       "import os",
    "re":       "import re",
    "sys":      "import sys",
    "hashlib":  "import hashlib",
    "base64":   "import base64",
    "time":     "import time",
    "subprocess": "import subprocess",
}

# Mapa de imports de helpers de cybersec
_HELPER_IMPORTS = {
    "scan":             "from habla.cybersec.scanner import scan as _habla_scan",
    "find_subdomains":  "from habla.cybersec.recon import find_subdomains as _habla_find_subdomains",
    "capture":          "from habla.cybersec.capture import capture as _habla_capture",
    "attack":           "from habla.cybersec.attack import attack as _habla_attack",
    "analyze":          "from habla.cybersec.analysis import analyze as _habla_analyze",
    "analyze_headers":  "from habla.cybersec.analysis import analyze_headers as _habla_analyze_headers",
    "report":           "from habla.cybersec.report import report as _habla_report",
    "hash_md5":         "from habla.cybersec.crypto import hash_md5 as _habla_hash_md5",
    "hash_sha1":        "from habla.cybersec.crypto import hash_sha1 as _habla_hash_sha1",
    "hash_sha256":      "from habla.cybersec.crypto import hash_sha256 as _habla_hash_sha256",
    "hash_sha512":      "from habla.cybersec.crypto import hash_sha512 as _habla_hash_sha512",
    "b64_encode":       "from habla.cybersec.crypto import b64_encode as _habla_b64_encode",
    "b64_decode":       "from habla.cybersec.crypto import b64_decode as _habla_b64_decode",
    "generate_token":   "from habla.cybersec.crypto import generate_token as _habla_generate_token",
}

# Traduccion de operadores
_OP_MAP = {
    "y": "and",
    "o": "or",
    "no": "not",
    "es": "==",
    "==": "==",
    "!=": "!=",
    ">=": ">=",
    "<=": "<=",
    ">":  ">",
    "<":  "<",
    "+":  "+",
    "-":  "-",
    "*":  "*",
    "/":  "/",
    "%":  "%",
}


class PythonTranspiler(BaseTranspiler):

    def emit(self) -> str:
        body_lines = self._visit_program(self.ast)
        body = "\n".join(body_lines)

        # Construir cabecera de imports
        import_lines = []
        for mod in self.imports.modules:
            if mod in _MODULE_IMPORTS:
                import_lines.append(_MODULE_IMPORTS[mod])
        for helper in self.imports.helpers:
            if helper in _HELPER_IMPORTS:
                import_lines.append(_HELPER_IMPORTS[helper])

        if import_lines:
            return "\n".join(import_lines) + "\n\n" + body
        return body

    # ─── Visitors ────────────────────────────────────────────────────────────

    def _visit(self, node: Node) -> str:
        method = f"_visit_{type(node).__name__}"
        visitor = getattr(self, method, self._visit_unknown)
        return visitor(node)

    def _visit_unknown(self, node: Node) -> str:
        return f"# TODO: {type(node).__name__}"

    def _visit_program(self, node: Program) -> List[str]:
        lines = []
        for stmt in node.statements:
            result = self._visit(stmt)
            if result:
                lines.append(result)
        return lines

    # ─── Statements ──────────────────────────────────────────────────────────

    def _visit_Assignment(self, node: Assignment) -> str:
        if isinstance(node.value, PipeExpression):
            return self._emit_pipe_chain(node.value.steps, target_var=node.name)
        value = self._visit(node.value) if node.value else "None"
        return f"{self._ind()}{node.name} = {value}"

    def _visit_IfStatement(self, node: IfStatement) -> str:
        cond = self._visit(node.condition)
        lines = [f"{self._ind()}if {cond}:"]
        self._indent += 1
        for stmt in node.then_body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        if node.else_body:
            lines.append(f"{self._ind()}else:")
            self._indent += 1
            for stmt in node.else_body:
                lines.append(self._visit(stmt))
            self._indent -= 1
        return "\n".join(lines)

    def _visit_WhileStatement(self, node: WhileStatement) -> str:
        cond = self._visit(node.condition)
        lines = [f"{self._ind()}while {cond}:"]
        self._indent += 1
        for stmt in node.body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        return "\n".join(lines)

    def _visit_ForStatement(self, node: ForStatement) -> str:
        iterable = self._visit(node.iterable)
        lines = [f"{self._ind()}for {node.var} in {iterable}:"]
        self._indent += 1
        for stmt in node.body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        return "\n".join(lines)

    def _visit_FunctionDef(self, node: FunctionDef) -> str:
        params = ", ".join(node.params)
        lines = [f"{self._ind()}def {node.name}({params}):"]
        self._indent += 1
        if not node.body:
            lines.append(f"{self._ind()}pass")
        else:
            for stmt in node.body:
                lines.append(self._visit(stmt))
        self._indent -= 1
        return "\n".join(lines)

    def _visit_ReturnStatement(self, node: ReturnStatement) -> str:
        val = self._visit(node.value) if node.value else ""
        return f"{self._ind()}return {val}".rstrip()

    def _visit_ShowStatement(self, node: ShowStatement) -> str:
        val = self._visit(node.value) if node.value else "_pipe_input"
        return f"{self._ind()}print({val})"

    def _visit_SaveStatement(self, node: SaveStatement) -> str:
        fname = self._visit(node.filename) if node.filename else '"output.txt"'
        val = self._visit(node.value) if node.value else "_pipe_input"
        return f'{self._ind()}open({fname}, "w").write(str({val}))'

    def _visit_ReadStatement(self, node: ReadStatement) -> str:
        fname = self._visit(node.filename) if node.filename else '"input.txt"'
        return f'{self._ind()}open({fname}).read()'

    def _visit_ExpressionStatement(self, node: ExpressionStatement) -> str:
        if isinstance(node.expr, PipeExpression):
            return self._emit_pipe_chain(node.expr.steps)
        return f"{self._ind()}{self._visit(node.expr)}"

    # ─── Expresiones cyber ───────────────────────────────────────────────────

    def _visit_CyberScan(self, node: CyberScan) -> str:
        self.imports.need("socket")
        self.imports.need_helper("scan")
        target = self._visit(node.target) if node.target else '"127.0.0.1"'
        ports = "[" + ", ".join(self._visit(p) for p in node.ports) + "]"
        return f"_habla_scan({target}, {ports})"

    def _visit_CyberRecon(self, node: CyberRecon) -> str:
        self.imports.need("socket")
        self.imports.need_helper("find_subdomains")
        domain = self._visit(node.domain) if node.domain else '""'
        return f"_habla_find_subdomains({domain})"

    def _visit_CyberCapture(self, node: CyberCapture) -> str:
        self.imports.need_helper("capture")
        iface = self._visit(node.interface) if node.interface else '"eth0"'
        flt = self._visit(node.filter_expr) if node.filter_expr else '""'
        return f"_habla_capture({iface}, {flt})"

    def _visit_CyberAttack(self, node: CyberAttack) -> str:
        self.imports.need_helper("attack")
        service = self._visit(node.service) if node.service else '"http"'
        target = self._visit(node.target) if node.target else '""'
        wordlist = self._visit(node.wordlist) if node.wordlist else '[]'
        username = self._visit(node.username) if node.username else '"admin"'
        return f"_habla_attack({service}, {target}, {wordlist}, {username})"

    def _visit_CyberAnalyze(self, node: CyberAnalyze) -> str:
        source = self._visit(node.source) if node.source else 'None'
        # Si el modo es headers, usar analyze_headers directamente (A-F grade + lista)
        if getattr(node, 'mode', 'auto') == 'headers':
            self.imports.need_helper("analyze_headers")
            return f"_habla_analyze_headers({source})"
        self.imports.need_helper("analyze")
        return f"_habla_analyze({source})"

    def _visit_CyberFindVulns(self, node: CyberFindVulns) -> str:
        self.imports.need_helper("analyze")
        target = self._visit(node.target) if node.target else 'None'
        return f"_habla_analyze({target}, mode='vulns')"

    def _visit_GenerateReport(self, node: GenerateReport) -> str:
        self.imports.need_helper("report")
        data = self._visit(node.data) if node.data else 'None'
        return f"_habla_report({data})"

    # ─── HTTP ────────────────────────────────────────────────────────────────

    def _visit_HttpGet(self, node: HttpGet) -> str:
        self.imports.need("requests")
        url = self._visit(node.url) if node.url else '""'
        if node.headers:
            hdrs = self._visit(node.headers)
            return f"requests.get({url}, headers={hdrs}).json()"
        return f"requests.get({url}).json()"

    def _visit_HttpPost(self, node: HttpPost) -> str:
        self.imports.need("requests")
        url = self._visit(node.url) if node.url else '""'
        body = self._visit(node.body) if node.body else '{{}}'
        return f"requests.post({url}, json={body}).json()"

    # ─── Expresiones de datos ─────────────────────────────────────────────────

    def _visit_FilterExpression(self, node: FilterExpression) -> str:
        cond = self._visit(node.condition)
        var = node.var
        src = self._visit(node.iterable) if node.iterable else "_habla_pipe_input"
        return f"[{var} for {var} in {src} if {cond}]"

    def _visit_SortExpression(self, node: SortExpression) -> str:
        src = self._visit(node.source) if node.source else "_habla_pipe_input"
        if node.key:
            key_expr = self._visit(node.key)
            return f"sorted({src}, key=lambda _x: _x[{key_expr}])"
        return f"sorted({src})"

    def _visit_CountExpression(self, node: CountExpression) -> str:
        src = self._visit(node.source) if node.source else "_habla_pipe_input"
        return f"len({src})"

    # ─── Literales ───────────────────────────────────────────────────────────

    def _visit_NumberLiteral(self, node: NumberLiteral) -> str:
        return str(node.value)

    def _visit_StringLiteral(self, node: StringLiteral) -> str:
        # Preservar el string tal como fue escrito (con comillas)
        return node.value

    def _visit_BooleanLiteral(self, node: BooleanLiteral) -> str:
        return "True" if node.value else "False"

    def _visit_NullLiteral(self, node: NullLiteral) -> str:
        return "None"

    def _visit_ListLiteral(self, node: ListLiteral) -> str:
        elements = ", ".join(self._visit(e) for e in node.elements)
        return f"[{elements}]"

    def _visit_DictLiteral(self, node: DictLiteral) -> str:
        pairs = ", ".join(f"{self._visit(k)}: {self._visit(v)}" for k, v in node.pairs)
        return "{" + pairs + "}"

    def _visit_Identifier(self, node: Identifier) -> str:
        return node.name

    def _visit_BinaryOp(self, node: BinaryOp) -> str:
        left = self._visit(node.left)
        right = self._visit(node.right)
        op = _OP_MAP.get(node.op, node.op)

        # Auto-coercion de string + no-string: "texto" + numero -> str(numero)
        if op == "+" and isinstance(node.left, StringLiteral) and not isinstance(node.right, StringLiteral):
            right = f"str({right})"
        elif op == "+" and isinstance(node.right, StringLiteral) and not isinstance(node.left, StringLiteral):
            left = f"str({left})"

        return f"{left} {op} {right}"

    def _visit_UnaryOp(self, node: UnaryOp) -> str:
        operand = self._visit(node.operand)
        op = _OP_MAP.get(node.op, node.op)
        return f"{op} {operand}"

    def _visit_PropertyAccess(self, node: PropertyAccess) -> str:
        obj = self._visit(node.obj)
        return f'{obj}["{node.prop}"]'

    def _visit_IndexAccess(self, node: IndexAccess) -> str:
        obj = self._visit(node.obj)
        idx = self._visit(node.index)
        return f"{obj}[{idx}]"

    def _visit_FunctionCall(self, node: FunctionCall) -> str:
        args = [self._visit(a) for a in node.args]
        kwargs = [f"{k}={self._visit(v)}" for k, v in node.kwargs]
        all_args = ", ".join(args + kwargs)
        return f"{node.func}({all_args})"

    # ─── Pipe chain ──────────────────────────────────────────────────────────

    def _emit_pipe_chain(self, steps: List[Node], target_var: Optional[str] = None) -> str:
        """
        Convierte una cadena de pipes en codigo Python con variables intermedias.

        X -> filtra donde cond -> guarda "out.txt"
        se convierte en:
            _pipe_0 = [_x for _x in X if cond]
            open("out.txt", "w").write(str(_pipe_0))
        """
        lines = []
        prev_var: Optional[str] = None

        for i, step in enumerate(steps):
            is_last = (i == len(steps) - 1)

            # Primer paso: si es un identificador, usarlo directamente
            if i == 0:
                if isinstance(step, Identifier):
                    prev_var = step.name
                    continue
                elif isinstance(step, (NumberLiteral, StringLiteral, ListLiteral, DictLiteral)):
                    out_var = target_var if is_last else self._next_pipe_var()
                    lines.append(f"{self._ind()}{out_var} = {self._visit(step)}")
                    prev_var = out_var
                    continue
                else:
                    out_var = target_var if is_last else self._next_pipe_var()
                    lines.append(f"{self._ind()}{out_var} = {self._visit(step)}")
                    prev_var = out_var
                    continue

            # Pasos siguientes reciben prev_var como input
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
            var = step.var
            result = f"[{var} for {var} in {prev_var} if {cond}]"
            return f"{ind}{out_var} = {result}" if out_var else f"{ind}{result}"

        elif isinstance(step, SortExpression):
            if step.key:
                key_expr = self._visit(step.key)
                result = f"sorted({prev_var}, key=lambda _x: _x[{key_expr}])"
            else:
                result = f"sorted({prev_var})"
            return f"{ind}{out_var} = {result}" if out_var else f"{ind}{result}"

        elif isinstance(step, ShowStatement):
            return f"{ind}print({prev_var})"

        elif isinstance(step, SaveStatement):
            fname = self._visit(step.filename) if step.filename else '"output.txt"'
            return f'{ind}open({fname}, "w").write(str({prev_var}))'

        elif isinstance(step, CountExpression):
            if out_var:
                return f"{ind}{out_var} = len({prev_var})"
            return f"{ind}len({prev_var})"

        elif isinstance(step, CyberRecon):
            # filtra alive como paso de pipe
            if step.filter_alive:
                if out_var:
                    return f"{ind}{out_var} = [s for s in {prev_var} if s]"
                return f"{ind}[s for s in {prev_var} if s]"
            self.imports.need_helper("find_subdomains")
            domain = self._visit(step.domain) if step.domain else '""'
            if out_var:
                return f"{ind}{out_var} = _habla_find_subdomains({domain})"
            return f"{ind}_habla_find_subdomains({domain})"

        elif isinstance(step, GenerateReport):
            self.imports.need_helper("report")
            # Si out_var es None (ultimo paso sin asignacion), emitir como statement
            if out_var:
                return f"{ind}{out_var} = _habla_report({prev_var})"
            return f"{ind}_habla_report({prev_var})"

        elif isinstance(step, FunctionCall):
            args = [prev_var] + [self._visit(a) for a in step.args]
            all_args = ", ".join(args)
            if out_var:
                return f"{ind}{out_var} = {step.func}({all_args})"
            return f"{ind}{step.func}({all_args})"

        else:
            # Caso generico
            val = self._visit(step)
            return f"{ind}{out_var} = {val}" if out_var else f"{ind}{val}"
