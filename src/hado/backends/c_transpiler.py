"""
Hado DSL — Backend C.
Genera codigo C ANSI a partir del AST de Hado.
Los archivos generados requieren gcc/clang para compilar.
"""

from __future__ import annotations
from typing import List, Optional

from ..transpiler import BaseTranspiler
from ..ast_nodes import *


class CTranspiler(BaseTranspiler):
    """
    Genera codigo C a partir del AST de Hado.

    Limitaciones de v0.1:
    - Todos los strings son char* (literales estaticos)
    - Listas de enteros se manejan como arrays con variable de longitud
    - El codigo se envuelve en int main() si no hay fn main definida
    - Cybersec: scan usa sockets POSIX; HTTP usa comentario con instrucciones libcurl
    """

    def __init__(self, ast: Program):
        super().__init__(ast)
        self._has_main = False
        self._includes: set = set()

    def emit(self) -> str:
        # Primera pasada: detectar que includes se necesitan
        self._scan_includes(self.ast)

        body_lines = self._visit_program(self.ast)
        body = "\n".join(body_lines)

        # Construir includes
        include_lines = sorted(f"#include {inc}" for inc in self._includes)
        preamble = "\n".join(include_lines)

        # Helpers de Hado en C
        helpers = self._emit_helpers()

        if self._has_main:
            return f"{preamble}\n\n{helpers}\n{body}"
        else:
            return f"{preamble}\n\n{helpers}\nint main(int argc, char *argv[]) {{\n{body}\n    return 0;\n}}"

    def _scan_includes(self, node: Program):
        self._includes.add("<stdio.h>")
        self._includes.add("<stdlib.h>")
        self._includes.add("<string.h>")
        # Siempre agregar estas para el uso general
        for stmt in node.statements:
            self._check_includes(stmt)

    def _check_includes(self, node):
        # Desenvuelve ExpressionStatement
        if isinstance(node, ExpressionStatement):
            node = node.expr
        if isinstance(node, CyberScan):
            self._includes.add("<sys/socket.h>")
            self._includes.add("<netinet/in.h>")
            self._includes.add("<arpa/inet.h>")
            self._includes.add("<unistd.h>")
        elif isinstance(node, HttpGet):
            self._includes.add("<stdio.h>")  # Nota: libcurl se agrega como comentario
        elif isinstance(node, (ForStatement, WhileStatement)):
            for s in getattr(node, "body", []):
                self._check_includes(s)
        elif isinstance(node, IfStatement):
            for s in node.then_body + node.else_body:
                self._check_includes(s)

    def _emit_helpers(self) -> str:
        if "<sys/socket.h>" not in self._includes:
            return ""
        return """\
/* Hado helper: escanea puertos */
int hado_scan_port(const char *host, int port) {
    struct sockaddr_in addr;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    struct timeval tv = {1, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);
    return result == 0;
}
"""

    # ─── Visitors ────────────────────────────────────────────────────────────

    def _visit(self, node: Node) -> str:
        method = f"_visit_{type(node).__name__}"
        visitor = getattr(self, method, self._visit_unknown)
        return visitor(node)

    def _visit_unknown(self, node: Node) -> str:
        return f"/* TODO: {type(node).__name__} */"

    def _visit_program(self, node: Program) -> List[str]:
        lines = []
        for stmt in node.statements:
            result = self._visit(stmt)
            if result:
                lines.append(result)
        return lines

    def _ind(self) -> str:
        base = "    " if not self._has_main else ""
        return "    " * self._indent + ("    " if not self._has_main else "")

    # ─── Statements ──────────────────────────────────────────────────────────

    def _visit_Assignment(self, node: Assignment) -> str:
        value = self._visit(node.value) if node.value else "NULL"
        # Inferencia de tipo simplificada
        if isinstance(node.value, NumberLiteral):
            if isinstance(node.value.value, float):
                return f"{self._ind()}double {node.name} = {value};"
            return f"{self._ind()}int {node.name} = {value};"
        elif isinstance(node.value, StringLiteral):
            return f"{self._ind()}const char *{node.name} = {value};"
        elif isinstance(node.value, BooleanLiteral):
            return f"{self._ind()}int {node.name} = {value};"
        return f"{self._ind()}void *{node.name} = (void*)(uintptr_t){value}; /* auto */"

    def _visit_ShowStatement(self, node: ShowStatement) -> str:
        targets = node.values if node.values else ([node.value] if node.value is not None else [])
        if not targets:
            return f'{self._ind()}printf("%s\\n", "(pipe input)");'
        parts_fmt, parts_args = [], []
        for v in targets:
            rendered = self._visit(v)
            if isinstance(v, NumberLiteral):
                parts_fmt.append("%d" if isinstance(v.value, int) else "%f")
            else:
                parts_fmt.append("%s")
            parts_args.append(rendered)
        fmt = " ".join(parts_fmt)
        args = ", ".join(parts_args)
        return f'{self._ind()}printf("{fmt}\\n", {args});'

    def _visit_IfStatement(self, node: IfStatement) -> str:
        cond = self._visit(node.condition)
        lines = [f"{self._ind()}if ({cond}) {{"]
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

    def _visit_ForStatement(self, node: ForStatement) -> str:
        iterable = self._visit(node.iterable)
        var = node.var
        lines = [
            f"{self._ind()}/* para {var} en {iterable} */",
            f"{self._ind()}for (int _i_{var} = 0; _i_{var} < _len_{var}; _i_{var}++) {{",
            f"{self._ind()}    int {var} = {iterable}[_i_{var}];",
        ]
        self._indent += 1
        for stmt in node.body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        lines.append(f"{self._ind()}}}")
        return "\n".join(lines)

    def _visit_FunctionDef(self, node: FunctionDef) -> str:
        if node.name == "main":
            self._has_main = True
            params = "int argc, char *argv[]"
            lines = [f"int main({params}) {{"]
        else:
            params = ", ".join(f"void *{p}" for p in node.params)
            lines = [f"void {node.name}({params}) {{"]
        self._indent += 1
        for stmt in node.body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        lines.append("}")
        if node.name == "main":
            lines.insert(-1, "    return 0;")
        return "\n".join(lines)

    def _visit_ReturnStatement(self, node: ReturnStatement) -> str:
        val = self._visit(node.value) if node.value else ""
        return f"{self._ind()}return {val};".rstrip() + ";"

    # ─── Cyber ────────────────────────────────────────────────────────────────

    def _visit_CyberScan(self, node: CyberScan) -> str:
        target = self._visit(node.target) if node.target else '"127.0.0.1"'
        ports = [self._visit(p) for p in node.ports]
        lines = [
            f"{self._ind()}/* escanea target {target} en ports [{', '.join(ports)}] */",
            f"{self._ind()}{{",
            f"{self._ind()}    int _ports[] = {{{', '.join(ports)}}};",
            f"{self._ind()}    int _nports = {len(ports)};",
            f"{self._ind()}    for (int _pi = 0; _pi < _nports; _pi++) {{",
            f"{self._ind()}        int _open = hado_scan_port({target}, _ports[_pi]);",
            f'{self._ind()}        printf("Port %d: %s\\n", _ports[_pi], _open ? "open" : "closed");',
            f"{self._ind()}    }}",
            f"{self._ind()}}}",
        ]
        return "\n".join(lines)

    def _visit_HttpGet(self, node: HttpGet) -> str:
        url = self._visit(node.url) if node.url else '""'
        return (
            f"{self._ind()}/* HTTP GET {url} */\n"
            f"{self._ind()}/* Nota: requiere libcurl. Compila con: gcc -lcurl */\n"
            f"{self._ind()}/* CURL *curl = curl_easy_init(); */\n"
            f'{self._ind()}/* curl_easy_setopt(curl, CURLOPT_URL, {url}); */\n'
            f"{self._ind()}/* curl_easy_perform(curl); */"
        )

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
        return node.value  # ya incluye comillas

    def _visit_BooleanLiteral(self, node: BooleanLiteral) -> str:
        return "1" if node.value else "0"

    def _visit_NullLiteral(self, node: NullLiteral) -> str:
        return "NULL"

    def _visit_Identifier(self, node: Identifier) -> str:
        return node.name

    def _visit_ListLiteral(self, node: ListLiteral) -> str:
        elements = ", ".join(self._visit(e) for e in node.elements)
        return "{" + elements + "}"

    def _visit_PropertyAccess(self, node: PropertyAccess) -> str:
        obj = self._visit(node.obj)
        return f"{obj}.{node.prop}"

    def _visit_ExpressionStatement(self, node: ExpressionStatement) -> str:
        return f"{self._ind()}{self._visit(node.expr)};"
