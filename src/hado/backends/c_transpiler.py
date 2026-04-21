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
    - Literal strings are char*
    - Numbers are interos se manejan como arrays con variable de longitud
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
        elif isinstance(node, CyberRecon):
            self._includes.add("<netdb.h>")
            self._includes.add("<sys/socket.h>")
            self._includes.add("<arpa/inet.h>")
            self._includes.add("<string.h>")
        elif isinstance(node, CyberAttack):
            self._includes.add("<curl/curl.h>")
            self._includes.add("<stdio.h>")
            self._includes.add("<stdlib.h>")
            self._includes.add("<string.h>")
        elif isinstance(node, (CyberEnumerate, CyberAnalyze)):
            self._includes.add("<curl/curl.h>")
            self._includes.add("<stdio.h>")
            self._includes.add("<stdlib.h>")
        elif isinstance(node, CyberCapture):
            self._includes.add("<pcap.h>")
            self._includes.add("<stdio.h>")
        elif isinstance(node, GenerateReport):
            self._includes.add("<stdio.h>")
        elif isinstance(node, (HttpGet, HttpPost)):
            self._includes.add("<curl/curl.h>")
            self._includes.add("<stdio.h>")
            self._includes.add("<stdlib.h>")
        elif isinstance(node, SaveStatement):
            self._includes.add("<stdio.h>")
        elif isinstance(node, (ForStatement, WhileStatement)):
            for s in getattr(node, "body", []):
                self._check_includes(s)
        elif isinstance(node, IfStatement):
            for s in node.then_body + node.else_body:
                self._check_includes(s)

    def _emit_helpers(self) -> str:
        scan_helper = """\
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
        curl_helper = """\
/* Hado helper: HTTP req con libcurl */
struct hado_mem_str { char *memory; size_t size; };
static size_t _hado_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  struct hado_mem_str *mem = (struct hado_mem_str *)userp;
  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(!ptr) return 0;
  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
  return realsize;
}
char* hado_http_req(const char* url, const char* method, const char* body, const char* auth) {
  CURL *curl; CURLcode res;
  struct hado_mem_str chunk; chunk.memory = malloc(1); chunk.size = 0;
  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _hado_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    if(body) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    if(auth) curl_easy_setopt(curl, CURLOPT_USERPWD, auth);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
  return chunk.memory;
}
"""
        recon_helper = """\
/* Hado helper: DNS recon */
char* hado_recon_dns(const char* domain) {
    struct addrinfo hints, *res, *p;
    char ipstr[INET6_ADDRSTRLEN];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char* result = calloc(4096, 1);
    if (getaddrinfo(domain, NULL, &hints, &res) != 0) return result;
    for(p = res; p != NULL; p = p->ai_next) {
        void *addr;
        if (p->ai_family == AF_INET) {
            addr = &((struct sockaddr_in *)p->ai_addr)->sin_addr;
            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
            if (strlen(result) + strlen(ipstr) + 3 < 4096) {
                strcat(result, ipstr); strcat(result, ", ");
            }
        }
    }
    freeaddrinfo(res);
    return result;
}
"""
        helpers = []
        if "<sys/socket.h>" in self._includes:
            if "<netdb.h>" in self._includes:
                helpers.append(recon_helper)
            if "hado_scan_port" in scan_helper: # Condicion dummy para usar scan_helper si es necesario, pero _check_includes de CyberScan no se usa solo
                helpers.append(scan_helper)
        if "<curl/curl.h>" in self._includes:
            helpers.append(curl_helper)
        return "\n\n".join(helpers)

    # ─── Visitors ────────────────────────────────────────────────────────────

    def _visit(self, node: Node) -> str:
        method = f"_visit_{type(node).__name__}"
        visitor = getattr(self, method, self._visit_unknown)
        return visitor(node)

    def _visit_unknown(self, node: Node) -> str:
        raise NotImplementedError(f"Node not implemented in C backend: {type(node).__name__}")

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

    def _visit_WhileStatement(self, node: WhileStatement) -> str:
        cond = self._visit(node.condition)
        lines = [f"{self._ind()}while ({cond}) {{"]
        self._indent += 1
        for stmt in node.body:
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

    def _visit_SaveStatement(self, node: SaveStatement) -> str:
        fname = self._visit(node.filename) if node.filename else '"output.txt"'
        val = self._visit(node.value) if node.value else "_pipe_val"
        lines = [
            f"{self._ind()}{{",
            f"{self._ind()}    FILE *_f = fopen({fname}, \"w\");",
            f"{self._ind()}    if (_f) {{",
            f'{self._ind()}        fprintf(_f, "%s", (char*){val});',
            f"{self._ind()}        fclose(_f);",
            f"{self._ind()}    }}",
            f"{self._ind()}}}"
        ]
        return "\n".join(lines)

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

    def _visit_CyberRecon(self, node: CyberRecon) -> str:
        domain = self._visit(node.domain) if node.domain else '"example.com"'
        return f'printf("[hado] Recon DNS on %s: %s\\n", {domain}, hado_recon_dns({domain}));'

    def _visit_CyberAttack(self, node: CyberAttack) -> str:
        target = self._visit(node.target) if node.target else '"127.0.0.1"'
        username = self._visit(node.username) if node.username else '"admin"'
        wordlist = self._visit(node.wordlist) if node.wordlist else '{"admin", "password", "123456"}'
        lines = [
            f"{self._ind()}{{ /* HTTP basic-auth brute force (simulating iter) */",
            f"{self._ind()}    const char* _wl[] = {wordlist};",
            f"{self._ind()}    int _nwl = sizeof(_wl)/sizeof(_wl[0]);",
            f"{self._ind()}    for(int _i=0; _i<_nwl; _i++) {{",
            f"{self._ind()}        char _auth[256];",
            f"{self._ind()}        snprintf(_auth, sizeof(_auth), \"%s:%s\", {username}, _wl[_i]);",
            f"{self._ind()}        char* _res = hado_http_req({target}, \"GET\", NULL, _auth);",
            f"{self._ind()}        if (_res && strlen(_res) > 0) {{",
            f'{self._ind()}            printf("[hado] Brute success: %s\\n", _auth);',
            f"{self._ind()}            free(_res);",
            f"{self._ind()}            break;",
            f"{self._ind()}        }}",
            f"{self._ind()}        if(_res) free(_res);",
            f"{self._ind()}    }}",
            f"{self._ind()}}}"
        ]
        return "\n".join(lines)

    def _visit_CyberAnalyze(self, node: CyberAnalyze) -> str:
        target = self._visit(node.source) if node.source else '"http://127.0.0.1"'
        return f'printf("[hado] Analizando headers (usar libcurl CURLOPT_HEADERDATA) en: %s\\n", {target});'

    def _visit_CyberCapture(self, node: CyberCapture) -> str:
        iface = self._visit(node.interface) if node.interface else '"eth0"'
        lines = [
            f"{self._ind()}{{ /* Captura de paquetes usando libpcap */",
            f"{self._ind()}    char errbuf[PCAP_ERRBUF_SIZE];",
            f"{self._ind()}    pcap_t *handle = pcap_open_live({iface}, BUFSIZ, 1, 1000, errbuf);",
            f"{self._ind()}    if (handle == NULL) {{",
            f'{self._ind()}        fprintf(stderr, "No se pudo abrir el dispositivo %s: %s\\n", {iface}, errbuf);',
            f"{self._ind()}    }} else {{",
            f'{self._ind()}        printf("[hado] Capturando en interfaz: %s (Compilar con -lpcap)\\n", {iface});',
            f"{self._ind()}        pcap_close(handle);",
            f"{self._ind()}    }}",
            f"{self._ind()}}}"
        ]
        return "\n".join(lines)

    def _visit_CyberEnumerate(self, node: CyberEnumerate) -> str:
        target = self._visit(node.target) if node.target else '"127.0.0.1"'
        wordlist = self._visit(node.wordlist) if node.wordlist else '{"admin", "login"}'
        lines = [
            f"{self._ind()}{{ /* Dir fuzzing secuencial */",
            f"{self._ind()}    const char* _wl[] = {wordlist};",
            f"{self._ind()}    int _nwl = sizeof(_wl)/sizeof(_wl[0]);",
            f"{self._ind()}    for(int _i=0; _i<_nwl; _i++) {{",
            f"{self._ind()}        char _url[512];",
            f"{self._ind()}        snprintf(_url, sizeof(_url), \"%s/%s\", {target}, _wl[_i]);",
            f"{self._ind()}        char* _res = hado_http_req(_url, \"GET\", NULL, NULL);",
            f"{self._ind()}        if (_res) {{",
            f'{self._ind()}            printf("[hado] Encontrado: %s\\n", _url);',
            f"{self._ind()}            free(_res);",
            f"{self._ind()}        }}",
            f"{self._ind()}    }}",
            f"{self._ind()}}}"
        ]
        return "\n".join(lines)

    def _visit_CyberFindVulns(self, node: CyberFindVulns) -> str:
        target = self._visit(node.target) if node.target else '"target"'
        return f'printf("[hado] Escaneando vulnerabilidades en: %s\\n", {target});'

    def _visit_GenerateReport(self, node: GenerateReport) -> str:
        data = self._visit(node.data) if node.data else '"{}"'
        fname = f'"{node.output_file}"' if hasattr(node, 'output_file') and node.output_file else '"report.json"'
        lines = [
            f"{self._ind()}{{",
            f"{self._ind()}    FILE *_f = fopen({fname}, \"w\");",
            f"{self._ind()}    if (_f) {{",
            f'{self._ind()}        fprintf(_f, "{{\\"data\\": \\"%s\\"}}", (char*){data});',
            f"{self._ind()}        fclose(_f);",
            f'{self._ind()}        printf("[hado] Reporte guardado en %s\\n", {fname});',
            f"{self._ind()}    }}",
            f"{self._ind()}}}"
        ]
        return "\n".join(lines)

    def _visit_HttpGet(self, node: HttpGet) -> str:
        url = self._visit(node.url) if node.url else '""'
        return f"hado_http_req({url}, \"GET\", NULL, NULL)"

    def _visit_HttpPost(self, node: HttpPost) -> str:
        url = self._visit(node.url) if node.url else '""'
        body = self._visit(node.body) if node.body else '""'
        return f"hado_http_req({url}, \"POST\", {body}, NULL)"

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

    def _visit_IndexAccess(self, node: IndexAccess) -> str:
        obj = self._visit(node.obj)
        idx = self._visit(node.index)
        return f"((void**){obj})[(int)({idx})]"

    def _visit_DictLiteral(self, node: DictLiteral) -> str:
        # En C nativo sin dependencias, serializamos dicts pequeños como JSON string literal
        pairs = []
        for k, v in node.pairs:
            key = self._visit(k).strip('"')
            val = self._visit(v).strip('"')
            pairs.append(f'\\"{key}\\": \\"{val}\\"')
        json_str = ", ".join(pairs)
        return f'"{{{json_str}}}"'

    def _visit_FunctionCall(self, node: FunctionCall) -> str:
        args = ", ".join(self._visit(a) for a in node.args)
        return f"{node.func}({args})"

    def _visit_PipeExpression(self, node: PipeExpression) -> str:
        lines = [f"{self._ind()}void *_pipe_val = NULL;"]
        for i, step in enumerate(node.steps):
            if i == 0:
                val = self._visit(step)
                lines.append(f"{self._ind()}_pipe_val = (void*)(uintptr_t){val};")
            else:
                if isinstance(step, (ShowStatement, SaveStatement)):
                    lines.append(self._visit(step))
                else:
                    val = self._visit(step)
                    lines.append(f"{self._ind()}_pipe_val = (void*)(uintptr_t){val};")
        return "\n".join(lines)

    def _visit_FilterExpression(self, node: FilterExpression) -> str:
        src = self._visit(node.iterable) if node.iterable else "_pipe_val"
        cond = self._visit(node.condition)
        var = node.var
        # Aproximación genérica C array sin conocer longitud
        lines = [
            f"0; /* Filter requiere length info en C. Implementacion pendiente. */",
            f"/* src: {src}, cond: {cond} */",
            f"{self._ind()}for(int _i=0; _i<10; _i++) {{",
            f"{self._ind()}    void* {var} = ((void**){src})[_i];",
            f"{self._ind()}    if({cond}) {{ /* append logic */ }}",
            f"{self._ind()}}}"
        ]
        return "\n".join(lines)

    def _visit_CountExpression(self, node: CountExpression) -> str:
        src = self._visit(node.source) if node.source else "_pipe_val"
        return f"0 /* Count() req struct array en C, valor simulado 0 para {src} */"

    def _visit_SortExpression(self, node: SortExpression) -> str:
        src = self._visit(node.source) if node.source else "_pipe_val"
        return f"{src} /* Sort() req struct array en C, bypass para {src} */"

    def _visit_ExpressionStatement(self, node: ExpressionStatement) -> str:
        return f"{self._ind()}{self._visit(node.expr)};"
