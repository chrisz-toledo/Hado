"""
Hado cybersec — Analisis de seguridad.
Analisis de headers HTTP, banners, y resultados de escaneo.
"""

from typing import Any, Dict, List, Optional


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
]


def analyze(data: Any, mode: str = "auto") -> dict:
    """
    Analiza datos de seguridad.

    Args:
        data: datos a analizar (URL, dict de headers, resultado de scan, etc.)
        mode: "headers", "scan", "auto"

    Returns:
        dict con resultados del analisis
    """
    if mode == "auto":
        mode = _detect_mode(data)

    if mode == "headers":
        return analyze_headers(data)
    elif mode == "scan":
        return analyze_scan(data)
    else:
        return {"raw": data, "mode": mode}


def _detect_mode(data: Any) -> str:
    if isinstance(data, str) and (data.startswith("http://") or data.startswith("https://")):
        return "headers"
    if isinstance(data, dict) and "open_ports" in data:
        return "scan"
    return "raw"


def analyze_headers(target) -> dict:
    """
    Analiza los headers de seguridad de una URL o dict de headers.

    Args:
        target: URL (str) o dict de headers

    Returns:
        dict con headers presentes, faltantes y puntuacion de seguridad
    """
    if isinstance(target, str):
        headers = _fetch_headers(target)
        url = target
    elif isinstance(target, dict):
        headers = target
        url = headers.get("url", "unknown")
    else:
        return {"error": "target debe ser una URL o un dict de headers"}

    present = []
    missing = []
    details = {}

    for h in SECURITY_HEADERS:
        # Busqueda case-insensitive
        found_key = next((k for k in headers if k.lower() == h.lower()), None)
        if found_key:
            present.append(h)
            details[h] = {"present": True, "value": headers[found_key]}
        else:
            missing.append(h)
            details[h] = {"present": False, "value": None}

    score = int((len(present) / len(SECURITY_HEADERS)) * 100)

    return {
        "url": url,
        "present_headers": present,
        "missing_headers": missing,
        "security_score": score,
        "details": details,
        "grade": _grade(score),
    }


def analyze_scan(scan_result: dict) -> dict:
    """Analiza el resultado de un escaneo de puertos."""
    open_ports = scan_result.get("open_ports", [])
    target = scan_result.get("target", "unknown")

    risky = []
    for port in open_ports:
        risk = _port_risk(port)
        if risk:
            risky.append({"port": port, "service": risk["service"], "risk": risk["level"]})

    return {
        "target": target,
        "open_ports": open_ports,
        "risky_ports": risky,
        "risk_count": len(risky),
        "summary": f"{len(open_ports)} puertos abiertos, {len(risky)} con riesgo potencial",
    }


def _fetch_headers(url: str) -> dict:
    try:
        import requests
        resp = requests.head(url, timeout=10, allow_redirects=True)
        return dict(resp.headers)
    except Exception as e:
        return {"error": str(e)}


def _grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


def _port_risk(port: int) -> Optional[dict]:
    RISKY_PORTS = {
        21: {"service": "FTP", "level": "HIGH"},
        22: {"service": "SSH", "level": "MEDIUM"},
        23: {"service": "Telnet", "level": "CRITICAL"},
        25: {"service": "SMTP", "level": "MEDIUM"},
        3306: {"service": "MySQL", "level": "HIGH"},
        5432: {"service": "PostgreSQL", "level": "HIGH"},
        27017: {"service": "MongoDB", "level": "HIGH"},
        6379: {"service": "Redis", "level": "HIGH"},
        9200: {"service": "Elasticsearch", "level": "HIGH"},
        445: {"service": "SMB", "level": "CRITICAL"},
        3389: {"service": "RDP", "level": "HIGH"},
        5900: {"service": "VNC", "level": "HIGH"},
    }
    return RISKY_PORTS.get(port)
