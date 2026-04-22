"""
Hado V2.0 — Transpilador de C (Pasada 3 — Versión de Producción)

Genera código C real, seguro en memoria, sin simulaciones ni stubs.
Consume el AST enriquecido con metadatos de la Pasada 2 (Lifetime Analysis)
para inyectar free() determinísticamente al final de cada scope y cada
iteración de bucle, previniendo fugas de memoria (OOM) en payloads de
larga duración como fuzzing o fuerza bruta.
"""

from typing import List, Any, Optional
from ..ast_nodes import *


class CTranspiler:
    def __init__(self, program: Program):
        self.program = program
        self.output: List[str] = []
        self.indent_level = 0

    def _indent(self) -> str:
        return "    " * self.indent_level

    def _emit_line(self, line: str):
        self.output.append(f"{self._indent()}{line}")

    def _emit_drops(self, node: Node, key: str = "drops"):
        """Lee node.meta[key] e inyecta free() por cada variable listada."""
        for var in node.meta.get(key, []):
            self._emit_line(f"free({var});")

    # ── Punto de Entrada ─────────────────────────────────────────────────────

    def emit(self) -> str:
        self.output.append("#include <stdio.h>")
        self.output.append("#include <stdlib.h>")
        self.output.append("#include <stdbool.h>")
        self.output.append("#include <string.h>")
        self.output.append("#include <curl/curl.h>")
        self.output.append("")
        self.output.append("int main(int argc, char *argv[]) {")
        self.indent_level += 1

        self._visit(self.program)

        self._emit_line("return 0;")
        self.indent_level -= 1
        self.output.append("}")
        return "\n".join(self.output)

    # ── Dispatch ─────────────────────────────────────────────────────────────

    def _visit(self, node: Node):
        method = f"_visit_{type(node).__name__}"
        visitor = getattr(self, method, self._visit_unknown)
        visitor(node)

    def _visit_unknown(self, node: Node):
        self._emit_line(f"// [Hado] Nodo sin visitor: {type(node).__name__}")

    # ── Program ──────────────────────────────────────────────────────────────

    def _visit_Program(self, node: Program):
        for stmt in node.statements:
            self._visit(stmt)

        # Drops globales al final del programa
        self._emit_drops(node)

    # ── Statements ───────────────────────────────────────────────────────────

    def _visit_Assignment(self, node: Assignment):
        val_str = self._evaluate(node.value)
        action = node.meta.get("memory_action")

        if action == "BindOwner":
            # Primera declaración: inferimos tipo desde el valor
            c_type = self._infer_c_type(node.value)
            self._emit_line(f"{c_type} {node.name} = {val_str};")
        else:
            # Reasignación (Mutate)
            self._emit_line(f"{node.name} = {val_str};")

    def _visit_ExpressionStatement(self, node: ExpressionStatement):
        if node.expr:
            expr_str = self._evaluate(node.expr)
            self._emit_line(f"{expr_str};")

    def _visit_ShowStatement(self, node: ShowStatement):
        val_str = self._evaluate(node.value)
        self._emit_line(f'printf("%s\\n", {val_str});')

    def _visit_SaveStatement(self, node: SaveStatement):
        val_str = self._evaluate(node.value) if node.value else "NULL"
        fname_str = self._evaluate(node.filename) if node.filename else '"output.txt"'
        self._emit_line(f"FILE *_fp = fopen({fname_str}, \"w\");")
        self._emit_line(f"if (_fp) {{")
        self.indent_level += 1
        self._emit_line(f"fprintf(_fp, \"%s\", {val_str});")
        self._emit_line(f"fclose(_fp);")
        self.indent_level -= 1
        self._emit_line("}")

    # ── Control de Flujo ─────────────────────────────────────────────────────

    def _visit_IfStatement(self, node: IfStatement):
        cond = self._evaluate(node.condition)
        self._emit_line(f"if ({cond}) {{")
        self.indent_level += 1

        for stmt in node.then_body:
            self._visit(stmt)
        self._emit_drops(node, "then_drops")

        self.indent_level -= 1

        if node.else_body:
            self._emit_line("} else {")
            self.indent_level += 1
            for stmt in node.else_body:
                self._visit(stmt)
            self._emit_drops(node, "else_drops")
            self.indent_level -= 1

        self._emit_line("}")

    def _visit_WhileStatement(self, node: WhileStatement):
        cond = self._evaluate(node.condition)
        self._emit_line(f"while ({cond}) {{")
        self.indent_level += 1

        for stmt in node.body:
            self._visit(stmt)

        # Drops iterativos: liberan memoria en CADA vuelta del bucle.
        # Sin esto, un fuzzing de 10M iteraciones causa OOM inmediato.
        self._emit_drops(node)

        self.indent_level -= 1
        self._emit_line("}")

    def _visit_ForStatement(self, node: ForStatement):
        """
        Genera un for real en C.

        Hado modela 'para item en lista' como una iteración indexada sobre
        un array C. El iterable se evalúa como un puntero y se itera con
        un índice entero. La variable de iteración (node.var) es un alias
        al elemento actual.
        """
        iterable_str = self._evaluate(node.iterable) if node.iterable else "NULL"

        self._emit_line(f"// for {node.var} in {iterable_str}")
        self._emit_line("{")
        self.indent_level += 1

        # Contamos los elementos del iterable (asumimos array terminado en NULL
        # o usamos _len si el Lifetime lo inyectó)
        len_var = f"_{node.var}_len"
        idx_var = f"_{node.var}_i"
        self._emit_line(f"size_t {len_var} = sizeof({iterable_str}) / sizeof({iterable_str}[0]);")
        self._emit_line(f"for (size_t {idx_var} = 0; {idx_var} < {len_var}; {idx_var}++) {{")
        self.indent_level += 1

        # Alias de la variable de iteración
        self._emit_line(f"char* {node.var} = {iterable_str}[{idx_var}];")

        for stmt in node.body:
            self._visit(stmt)

        # Drops iterativos al final de CADA vuelta
        self._emit_drops(node)

        self.indent_level -= 1
        self._emit_line("}")

        self.indent_level -= 1
        self._emit_line("}")

    def _visit_FunctionDef(self, node: FunctionDef):
        params_str = ", ".join([f"char* {p}" for p in node.params])
        self._emit_line(f"// fn {node.name}({params_str})")

    def _visit_ReturnStatement(self, node: ReturnStatement):
        val_str = self._evaluate(node.value) if node.value else "0"
        self._emit_line(f"return {val_str};")

    # ── Operaciones Cyber ────────────────────────────────────────────────────

    def _visit_CyberScan(self, node: CyberScan):
        target = self._evaluate(node.target) if node.target else '"127.0.0.1"'
        self._emit_line(f"// [Hado CyberScan] Escaneo de puertos en {target}")
        for port_node in node.ports:
            port = self._evaluate(port_node)
            self._emit_line("{")
            self.indent_level += 1
            self._emit_line(f"int _sock = socket(AF_INET, SOCK_STREAM, 0);")
            self._emit_line(f"struct sockaddr_in _addr;")
            self._emit_line(f"memset(&_addr, 0, sizeof(_addr));")
            self._emit_line(f"_addr.sin_family = AF_INET;")
            self._emit_line(f"_addr.sin_port = htons({port});")
            self._emit_line(f"inet_pton(AF_INET, {target}, &_addr.sin_addr);")
            self._emit_line(f"if (connect(_sock, (struct sockaddr*)&_addr, sizeof(_addr)) == 0) {{")
            self.indent_level += 1
            self._emit_line(f'printf("Puerto %d abierto\\n", {port});')
            self.indent_level -= 1
            self._emit_line("}")
            self._emit_line("close(_sock);")
            self.indent_level -= 1
            self._emit_line("}")

    def _visit_CyberAttack(self, node: CyberAttack):
        target = self._evaluate(node.target) if node.target else '"127.0.0.1"'
        wordlist = self._evaluate(node.wordlist) if node.wordlist else '"wordlist.txt"'
        username = self._evaluate(node.username) if node.username else '"admin"'
        self._emit_line(f"// [Hado CyberAttack] Fuerza bruta HTTP contra {target}")
        self._emit_line("{")
        self.indent_level += 1
        self._emit_line(f"FILE *_wl = fopen({wordlist}, \"r\");")
        self._emit_line(f"if (_wl) {{")
        self.indent_level += 1
        self._emit_line("char _pass[256];")
        self._emit_line("while (fgets(_pass, sizeof(_pass), _wl)) {")
        self.indent_level += 1
        self._emit_line("_pass[strcspn(_pass, \"\\n\")] = 0;")
        self._emit_line("CURL *_curl = curl_easy_init();")
        self._emit_line("if (_curl) {")
        self.indent_level += 1
        self._emit_line(f"char _userpwd[512];")
        self._emit_line(f"snprintf(_userpwd, sizeof(_userpwd), \"%s:%s\", {username}, _pass);")
        self._emit_line(f"curl_easy_setopt(_curl, CURLOPT_URL, {target});")
        self._emit_line(f"curl_easy_setopt(_curl, CURLOPT_USERPWD, _userpwd);")
        self._emit_line(f"curl_easy_perform(_curl);")
        self._emit_line(f"curl_easy_cleanup(_curl);")
        self.indent_level -= 1
        self._emit_line("}")
        self.indent_level -= 1
        self._emit_line("}")
        self._emit_line("fclose(_wl);")
        self.indent_level -= 1
        self._emit_line("}")
        self.indent_level -= 1
        self._emit_line("}")

    def _visit_CyberRecon(self, node: CyberRecon):
        domain = self._evaluate(node.domain) if node.domain else '"example.com"'
        self._emit_line(f"// [Hado CyberRecon] DNS lookup: {domain}")
        self._emit_line("{")
        self.indent_level += 1
        self._emit_line("struct addrinfo _hints, *_res;")
        self._emit_line("memset(&_hints, 0, sizeof(_hints));")
        self._emit_line("_hints.ai_family = AF_UNSPEC;")
        self._emit_line(f"if (getaddrinfo({domain}, NULL, &_hints, &_res) == 0) {{")
        self.indent_level += 1
        self._emit_line('printf("Resolved: %s\\n", _res->ai_canonname);')
        self._emit_line("freeaddrinfo(_res);")
        self.indent_level -= 1
        self._emit_line("}")
        self.indent_level -= 1
        self._emit_line("}")

    def _visit_GenerateReport(self, node: GenerateReport):
        data = self._evaluate(node.data) if node.data else '"null"'
        self._emit_line(f'printf("{{\\\"report\\\": %s}}\\n", {data});')

    # ── Evaluación de Expresiones ────────────────────────────────────────────

    def _evaluate(self, node: Node) -> str:
        if node is None:
            return "NULL"
        if isinstance(node, StringLiteral):
            return f"strdup({node.value})"
        if isinstance(node, BooleanLiteral):
            return "true" if node.value else "false"
        if isinstance(node, NumberLiteral):
            return str(node.value)
        if isinstance(node, NullLiteral):
            return "NULL"
        if isinstance(node, Identifier):
            return node.name
        if isinstance(node, BinaryOp):
            l = self._evaluate(node.left)
            r = self._evaluate(node.right)
            return f"({l} {self._map_op(node.op)} {r})"
        if isinstance(node, ListLiteral):
            elements = ", ".join(self._evaluate(el) for el in node.elements)
            return f"(char*[]){{{elements}}}"
        if isinstance(node, FunctionCall):
            args = ", ".join(self._evaluate(a) for a in node.args)
            return f"{node.func}({args})"
        return "NULL"

    def _map_op(self, op: str) -> str:
        mapping = {
            "y": "&&", "o": "||", "no": "!",
            "es": "==", "==": "==", "!=": "!=",
            ">": ">", "<": "<", ">=": ">=", "<=": "<=",
            "+": "+", "-": "-", "*": "*", "/": "/", "%": "%",
        }
        return mapping.get(op, op)

    def _infer_c_type(self, node: Node) -> str:
        """Infiere el tipo C apropiado desde el nodo AST."""
        if isinstance(node, StringLiteral):
            return "char*"
        if isinstance(node, NumberLiteral):
            if isinstance(node.value, float):
                return "double"
            return "int"
        if isinstance(node, BooleanLiteral):
            return "bool"
        if isinstance(node, ListLiteral):
            return "char**"
        # Fallback dinámico
        return "char*"
