"""
Hado cybersec — Generacion de reportes de seguridad.
Formatos: markdown, html, texto plano.
"""

import json
from datetime import datetime
from typing import Any, Optional


_DEFAULT_JSON_PATH = "hado_report.json"


def report(
    data: Any,
    output_file: Optional[str] = None,
    format: str = "markdown",
    title: str = "Reporte de Seguridad",
    author: str = "Hado Security Scanner",
    persist: bool = True,
) -> str:
    """
    Genera un reporte de seguridad y lo persiste en disco.

    Siempre escribe hado_report.json en el directorio de ejecucion actual
    (comportamiento opcionalmente desactivable con persist=False).
    Adicionalmente, si output_file está especificado, escribe el formato
    solicitado en esa ruta.

    Args:
        data: datos del reporte (dict, list, o cualquier estructura)
        output_file: path adicional para el reporte formateado
        format: "markdown", "html", "text", "json"
        title: titulo del reporte
        author: autor del reporte
        persist: si True (default), guarda hado_report.json automaticamente

    Returns:
        Contenido del reporte como string
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if format == "markdown":
        content = _render_markdown(data, title, author, timestamp)
    elif format == "html":
        content = _render_html(data, title, author, timestamp)
    elif format == "json":
        content = json.dumps(
            {"title": title, "author": author, "timestamp": timestamp, "data": data},
            indent=2, default=str,
        )
    else:
        content = _render_text(data, title, author, timestamp)

    # ── Persistencia automatica a JSON (siempre, a menos que persist=False) ──
    if persist:
        json_payload = {
            "title": title,
            "author": author,
            "timestamp": timestamp,
            "format": format,
            "data": data,
        }
        with open(_DEFAULT_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(json_payload, f, indent=2, default=str)

    # ── Output file adicional (formato solicitado) ────────────────────────────
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(content)

    return content


def _render_markdown(data: Any, title: str, author: str, timestamp: str) -> str:
    lines = [
        f"# {title}",
        f"",
        f"**Autor:** {author}  ",
        f"**Fecha:** {timestamp}  ",
        f"",
        f"---",
        f"",
    ]

    if isinstance(data, list):
        for i, item in enumerate(data, 1):
            lines.append(f"## Target {i}")
            lines.append("")
            lines.extend(_dict_to_md(item))
            lines.append("")
    elif isinstance(data, dict):
        lines.extend(_dict_to_md(data))
    else:
        lines.append(f"```\n{data}\n```")

    lines.append("---")
    lines.append(f"*Generado con [Hado DSL](https://github.com/chrisz-toledo/hado)*")
    return "\n".join(lines)


def _dict_to_md(d: dict, indent: int = 0) -> list:
    lines = []
    prefix = "  " * indent
    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{prefix}- **{k}:**")
            lines.extend(_dict_to_md(v, indent + 1))
        elif isinstance(v, list):
            lines.append(f"{prefix}- **{k}:** {', '.join(str(x) for x in v) if v else '(ninguno)'}")
        else:
            lines.append(f"{prefix}- **{k}:** {v}")
    return lines


def _render_html(data: Any, title: str, author: str, timestamp: str) -> str:
    body = json.dumps(data, indent=2, default=str)
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>{title}</title>
  <style>
    body {{ font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 2rem; }}
    h1 {{ color: #00ff88; }}
    pre {{ background: #16213e; padding: 1rem; border-radius: 4px; overflow-x: auto; }}
    .meta {{ color: #888; margin-bottom: 1rem; }}
  </style>
</head>
<body>
  <h1>{title}</h1>
  <p class="meta">Autor: {author} | Fecha: {timestamp}</p>
  <pre>{body}</pre>
  <hr>
  <p><em>Generado con <a href="https://github.com/chrisz-toledo/hado">Hado DSL</a></em></p>
</body>
</html>"""


def _render_text(data: Any, title: str, author: str, timestamp: str) -> str:
    separator = "=" * 60
    lines = [
        separator,
        f"  {title.upper()}",
        separator,
        f"Autor: {author}",
        f"Fecha: {timestamp}",
        separator,
        "",
        str(data),
        "",
        separator,
        "Generado con Hado DSL",
    ]
    return "\n".join(lines)


def consolidate(*datasets, output_file: Optional[str] = None, title: str = "Reporte Consolidado") -> str:
    """
    Consolida multiples estructuras de datos en un unico reporte JSON.

    Acepta dicts, listas, strings — cualquier resultado de operaciones cyber.
    Util para combinar resultados de scan + recon + analisis en un solo output.

    Args:
        *datasets: cualquier numero de resultados a consolidar
        output_file: path opcional para guardar el JSON
        title: titulo del reporte consolidado

    Returns:
        String JSON con todos los datasets indexados
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    consolidated = {
        "title": title,
        "timestamp": timestamp,
        "generator": "Hado DSL",
        "datasets": [],
    }

    for i, ds in enumerate(datasets, 1):
        entry: dict = {"index": i}
        if isinstance(ds, dict):
            entry["type"] = "scan_result" if "open_ports" in ds else "dict"
            entry["data"] = ds
        elif isinstance(ds, list):
            entry["type"] = "list"
            entry["count"] = len(ds)
            entry["data"] = ds
        elif isinstance(ds, str):
            entry["type"] = "text"
            entry["data"] = ds
        else:
            entry["type"] = type(ds).__name__
            entry["data"] = str(ds)
        consolidated["datasets"].append(entry)

    content = json.dumps(consolidated, indent=2, default=str)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(content)

    return content
