"""
Hado DSL — Backend Rust (Tokio async edition).

Genera código Rust 2021 edition con async/await y tokio runtime.
Cada módulo de ciberseguridad emite código idiomático real.

Uso desde CLI:
    hado compile script.ho --target rust          # imprime main.rs en stdout
    hado compile script.ho --target rust --out dir # genera src/main.rs + Cargo.toml

Cargo.toml generado automáticamente con las dependencias que usa el código.
"""

from __future__ import annotations
from typing import List, Optional, Set, Dict, Tuple

from ..transpiler import BaseTranspiler
from ..ast_nodes import *


# ─── Dependencias conocidas ──────────────────────────────────────────────────

_CARGO_DEPS: Dict[str, str] = {
    "tokio":        'tokio = { version = "1", features = ["full"] }',
    "reqwest":      'reqwest = { version = "0.12", features = ["json"] }',
    "serde":        'serde = { version = "1", features = ["derive"] }',
    "serde_json":   'serde_json = "1"',
    "anyhow":       'anyhow = "1"',
    "futures":      'futures = "0.3"',
    "clap":         'clap = { version = "4", features = ["derive"] }',
    "tokio-stream": 'tokio-stream = "0.1"',
}


class RustTranspiler(BaseTranspiler):
    """
    Genera código Rust 2021 edition con async/await y tokio runtime.

    Características:
    - main() es siempre async con #[tokio::main]
    - CyberScan usa tokio::net::TcpStream para escaneo concurrente
    - CyberRecon usa tokio::net::lookup_host para DNS async
    - HttpGet usa reqwest async client
    - Cargo.toml generado automáticamente con las deps reales
    - emit()         → main.rs listo para pegar
    - emit_project() → (main_rs, cargo_toml) para proyecto Cargo completo
    """

    def __init__(self, ast: Program, crate_name: str = "hado_generated"):
        super().__init__(ast)
        self._crate_name = crate_name
        self._has_async = False
        self._cargo_deps: Set[str] = set()
        self._top_level: List[str] = []  # funciones helper al top-level

    # ─── Entry points ─────────────────────────────────────────────────────────

    def emit(self) -> str:
        """Retorna el contenido de main.rs completo."""
        main_rs, _ = self.emit_project()
        return main_rs

    def emit_project(self) -> Tuple[str, str]:
        """
        Retorna (main_rs, cargo_toml).
        main_rs  → contenido de src/main.rs
        cargo_toml → contenido de Cargo.toml
        """
        body_lines = self._visit_program(self.ast)

        # Construir función main
        main_body = "\n".join(body_lines)
        if not main_body.strip():
            main_body = "    // programa vacío"

        self._cargo_deps.add("anyhow")

        if self._has_async:
            self._cargo_deps.add("tokio")
            main_fn = (
                "#[tokio::main]\n"
                "async fn main() -> anyhow::Result<()> {\n"
                f"{main_body}\n"
                "    Ok(())\n"
                "}"
            )
        else:
            main_fn = (
                "fn main() -> anyhow::Result<()> {\n"
                f"{main_body}\n"
                "    Ok(())\n"
                "}"
            )

        # Ensamblar main.rs
        parts = [
            "// Generado por Hado DSL — https://github.com/hado-lang/hado",
            "// Compilar: cargo build --release",
            "// Ejecutar: cargo run",
            "",
        ]
        if self._top_level:
            parts.extend(self._top_level)
            parts.append("")
        parts.append(main_fn)

        main_rs = "\n".join(parts)
        cargo_toml = self._build_cargo_toml()
        return main_rs, cargo_toml

    # ─── Cargo.toml ──────────────────────────────────────────────────────────

    def _build_cargo_toml(self) -> str:
        dep_lines = []
        for dep_name in sorted(self._cargo_deps):
            if dep_name in _CARGO_DEPS:
                dep_lines.append(_CARGO_DEPS[dep_name])
            else:
                dep_lines.append(f'{dep_name} = "*"')
        deps_section = "\n".join(dep_lines)
        return (
            f"[package]\n"
            f'name = "{self._crate_name}"\n'
            f'version = "0.1.0"\n'
            f'edition = "2021"\n'
            f"\n"
            f"[dependencies]\n"
            f"{deps_section}\n"
        )

    # ─── Visitor dispatch ────────────────────────────────────────────────────

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
            if isinstance(result, list):
                lines.extend(result)
            elif result:
                lines.append(result)
        return lines

    # ─── Statements ──────────────────────────────────────────────────────────

    def _visit_Assignment(self, node: Assignment) -> str:
        val = self._visit(node.value)
        return f"{self._ind()}let mut {node.name} = {val};"

    def _visit_ShowStatement(self, node: ShowStatement) -> str:
        val = self._visit(node.value)
        if isinstance(node.value, StringLiteral):
            inner = node.value.value[1:-1]
            return f'{self._ind()}println!("{inner}");'
        return f"{self._ind()}println!(\"{{:?}}\", {val});"

    def _visit_IfStatement(self, node: IfStatement) -> str:
        lines = []
        cond = self._visit(node.condition)
        lines.append(f"{self._ind()}if {cond} {{")
        self._indent += 1
        for stmt in node.then_body:
            r = self._visit(stmt)
            if isinstance(r, list):
                lines.extend(r)
            elif r:
                lines.append(r)
        self._indent -= 1
        if node.else_body:
            lines.append(f"{self._ind()}}} else {{")
            self._indent += 1
            for stmt in node.else_body:
                r = self._visit(stmt)
                if isinstance(r, list):
                    lines.extend(r)
                elif r:
                    lines.append(r)
            self._indent -= 1
        lines.append(f"{self._ind()}}}")
        return "\n".join(lines)

    def _visit_WhileStatement(self, node: WhileStatement) -> str:
        lines = []
        cond = self._visit(node.condition)
        lines.append(f"{self._ind()}while {cond} {{")
        self._indent += 1
        for stmt in node.body:
            r = self._visit(stmt)
            if isinstance(r, list):
                lines.extend(r)
            elif r:
                lines.append(r)
        self._indent -= 1
        lines.append(f"{self._ind()}}}")
        return "\n".join(lines)

    def _visit_ForStatement(self, node: ForStatement) -> List[str]:
        lines = []
        iterable = self._visit(node.iterable)
        lines.append(f"{self._ind()}for {node.var} in {iterable} {{")
        self._indent += 1
        for stmt in node.body:
            r = self._visit(stmt)
            if isinstance(r, list):
                lines.extend(r)
            elif r:
                lines.append(r)
        self._indent -= 1
        lines.append(f"{self._ind()}}}")
        return lines

    def _visit_FunctionDef(self, node: FunctionDef) -> List[str]:
        params = ", ".join(f"{p}: &str" for p in node.params)
        lines = [f"{self._ind()}fn {node.name}({params}) {{"]
        self._indent += 1
        for stmt in node.body:
            r = self._visit(stmt)
            if isinstance(r, list):
                lines.extend(r)
            elif r:
                lines.append(r)
        self._indent -= 1
        lines.append(f"{self._ind()}}}")
        return lines

    def _visit_ReturnStatement(self, node: ReturnStatement) -> str:
        val = self._visit(node.value) if node.value else ""
        return (f"{self._ind()}return {val};").rstrip() + ";"

    def _visit_ExpressionStatement(self, node: ExpressionStatement) -> str:
        if isinstance(node.expr, PipeExpression):
            return self._emit_pipe_chain(node.expr.steps)
        return f"{self._ind()}{self._visit(node.expr)};"

    def _visit_SaveStatement(self, node: SaveStatement) -> str:
        val = self._visit(node.value) if node.value else "_data"
        fname = self._visit(node.filename) if node.filename else '"output.txt"'
        return f"{self._ind()}std::fs::write({fname}, format!(\"{{:?}}\", {val}))?;"

    # ─── Cyber — Port Scanner (async Tokio) ──────────────────────────────────

    def _visit_CyberScan(self, node: CyberScan) -> str:
        """
        Port scanner async con tokio::net::TcpStream y futures::join_all.
        Lanza todas las conexiones concurrentemente, timeout de 1 segundo.
        """
        self._has_async = True
        self._cargo_deps.update({"tokio", "futures", "anyhow"})

        target = self._visit(node.target) if node.target else '"127.0.0.1"'
        ports = [self._visit(p) for p in node.ports] if node.ports else ["80", "443", "22"]

        # Registrar scan_ports() como helper top-level (solo una vez)
        if not getattr(self, "_scan_ports_registered", False):
            self._scan_ports_registered = True
            self._top_level.append(_SCAN_PORTS_FN)

        ports_vec = ", ".join(f"{p}u16" for p in ports)
        lines = [
            f"{self._ind()}// escanea {target}",
            f"{self._ind()}let _ports: Vec<u16> = vec![{ports_vec}];",
            f"{self._ind()}let scan_results = scan_ports({target}, &_ports).await;",
            f"{self._ind()}for (port, open) in &scan_results {{",
            f'{self._ind()}    let status = if *open {{ "open" }} else {{ "closed" }};',
            f'{self._ind()}    println!("  {{}}:{{}}: {{}}", {target}, port, status);',
            f"{self._ind()}}}",
        ]
        return "\n".join(lines)

    # ─── Cyber — Recon (async DNS) ────────────────────────────────────────────

    def _visit_CyberRecon(self, node: CyberRecon) -> str:
        self._has_async = True
        self._cargo_deps.update({"tokio", "futures", "anyhow"})

        domain = self._visit(node.domain) if node.domain else '"example.com"'

        if not getattr(self, "_recon_registered", False):
            self._recon_registered = True
            self._top_level.append(_FIND_SUBDOMAINS_FN)

        lines = [
            f"{self._ind()}// busca subdomains de {domain}",
            f"{self._ind()}let subdomains = find_subdomains({domain}).await;",
            f'{self._ind()}println!("Subdominios encontrados: {{}}", subdomains.len());',
            f"{self._ind()}for sub in &subdomains {{",
            f'{self._ind()}    println!("  + {{}}", sub);',
            f"{self._ind()}}}",
        ]
        return "\n".join(lines)

    # ─── Cyber — HTTP ─────────────────────────────────────────────────────────

    def _visit_HttpGet(self, node: HttpGet) -> str:
        self._has_async = True
        self._cargo_deps.update({"tokio", "reqwest", "anyhow"})
        url = self._visit(node.url) if node.url else '""'
        return (
            f"{self._ind()}let _response = reqwest::get({url}).await?;\n"
            f"{self._ind()}let _body = _response.text().await?;"
        )

    # ─── Cyber — Report ───────────────────────────────────────────────────────

    def _visit_GenerateReport(self, node: GenerateReport) -> str:
        data = self._visit(node.data) if node.data else "_data"
        return f'{self._ind()}println!("=== Reporte Hado ===\\n{{:#?}}", {data});'

    # ─── Expresiones ─────────────────────────────────────────────────────────

    def _visit_BinaryOp(self, node: BinaryOp) -> str:
        left = self._visit(node.left)
        right = self._visit(node.right)
        op_map = {
            "y": "&&", "o": "||", "no": "!", "es": "==",
            "==": "==", "!=": "!=", ">=": ">=", "<=": "<=",
            ">": ">", "<": "<",
            "+": "+", "-": "-", "*": "*", "/": "/", "%": "%",
        }
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

    def _visit_FunctionCall(self, node: FunctionCall) -> str:
        args = ", ".join(self._visit(a) for a in node.args)
        return f"{node.func}({args})"

    def _visit_FilterExpression(self, node: FilterExpression) -> str:
        cond = self._visit(node.condition)
        src = self._visit(node.iterable) if node.iterable else "_pipe_input"
        return (
            f"{src}.iter().filter(|{node.var}| {cond})"
            ".cloned().collect::<Vec<_>>()"
        )

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
                    r = self._visit(step)
                    if isinstance(r, list):
                        lines.extend(r)
                    else:
                        lines.append(f"{self._ind()}let mut {out_var} = {r};")
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
            return (
                f"{ind}let mut {out_var} = "
                f"{prev_var}.iter().filter(|{v}| {cond}).cloned().collect::<Vec<_>>();"
            )
        elif isinstance(step, ShowStatement):
            return f'{ind}println!("{{:?}}", {prev_var});'
        elif isinstance(step, SaveStatement):
            fname = self._visit(step.filename) if step.filename else '"output.txt"'
            return f"{ind}std::fs::write({fname}, format!(\"{{:?}}\", {prev_var}))?;"
        elif isinstance(step, CountExpression):
            return f"{ind}let mut {out_var} = {prev_var}.len();"
        elif isinstance(step, GenerateReport):
            return f'{ind}println!("=== Reporte ===\\n{{:#?}}", {prev_var});'
        else:
            r = self._visit(step)
            return f"{ind}let mut {out_var} = {r};"


# ─── Funciones helper generadas (top-level en main.rs) ──────────────────────

_SCAN_PORTS_FN = '''\
/// Escanea una lista de puertos de forma concurrente usando tokio.
/// Retorna Vec<(u16, bool)> donde bool = true si el puerto está abierto.
async fn scan_ports(host: &str, ports: &[u16]) -> Vec<(u16, bool)> {
    use futures::future::join_all;
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    let tasks: Vec<_> = ports
        .iter()
        .map(|&port| {
            let addr = format!("{}:{}", host, port);
            async move {
                let is_open = timeout(
                    Duration::from_secs(1),
                    TcpStream::connect(&addr),
                )
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
                (port, is_open)
            }
        })
        .collect();

    join_all(tasks).await
}'''

_FIND_SUBDOMAINS_FN = '''\
/// Enumera subdominios del dominio dado mediante resolución DNS async.
async fn find_subdomains(domain: &str) -> Vec<String> {
    use futures::future::join_all;
    use tokio::net::lookup_host;

    let prefixes = [
        "www", "mail", "api", "dev", "admin",
        "test", "staging", "vpn", "ftp", "git",
    ];

    let tasks: Vec<_> = prefixes
        .iter()
        .map(|prefix| {
            let fqdn = format!("{}.{}", prefix, domain);
            async move {
                let query = format!("{}:80", fqdn);
                if lookup_host(&query).await.is_ok() {
                    Some(fqdn)
                } else {
                    None
                }
            }
        })
        .collect();

    join_all(tasks)
        .await
        .into_iter()
        .flatten()
        .collect()
}'''
