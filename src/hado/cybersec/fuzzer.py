"""
Hado cybersec — Fuzzer de directorios y endpoints web.
Descubre paths ocultos con requests concurrentes.
ADVERTENCIA: Solo usar en sistemas propios o con permiso explícito.
"""

import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional
from urllib.parse import urlparse


# Wordlist por defecto si no se provee una
_DEFAULT_WORDLIST = [
    "admin", "api", "login", "logout", "dashboard", "config", "backup",
    "uploads", "images", "assets", "static", "media", "files", "docs",
    "test", "dev", "staging", "prod", "internal", "private", "secret",
    "robots.txt", "sitemap.xml", ".env", ".git", "wp-admin", "wp-login.php",
    "phpinfo.php", "info.php", "console", "panel", "manage", "manager",
    "administrator", "user", "users", "account", "accounts", "register",
    "signup", "signin", "auth", "oauth", "token", "health", "status",
    "metrics", "debug", "trace", "log", "logs", "error", "errors",
]

# Códigos que indican que el path existe (no 404)
_INTERESTING_CODES = {200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405}


def fuzz(
    target: str,
    wordlist: Optional[List[str]] = None,
    mode: str = "directories",
    method: str = "GET",
    threads: int = 10,
    timeout: int = 5,
    extensions: Optional[List[str]] = None,
) -> dict:
    """
    Fuzzing de directorios y endpoints web.

    Args:
        target:     URL base (ej: "https://example.com" o "example.com")
        wordlist:   lista de paths a probar. Si None, usa wordlist por defecto.
        method:     método HTTP ("GET" o "HEAD"). HEAD es más rápido y sigiloso.
        threads:    hilos concurrentes (default: 10)
        timeout:    timeout por request en segundos (default: 5)
        extensions: extensiones adicionales a probar (ej: [".php", ".bak"])

    Returns:
        dict con:
          - target:          URL base escaneada
          - found_paths:     list de paths con código interesante
          - status_codes:    dict {path: status_code}
          - total_requests:  número total de requests enviados
          - method:          "requests" o "error"
    """
    try:
        import requests as _req
        _req.packages.urllib3.disable_warnings()  # type: ignore
    except ImportError:
        warnings.warn(
            "requests no instalado. Ejecuta: pip install requests",
            RuntimeWarning,
            stacklevel=2,
        )
        return {
            "target": target,
            "found_paths": [],
            "status_codes": {},
            "total_requests": 0,
            "method": "error",
            "error": "requests no disponible",
        }

    # Normalizar URL base
    base_url = _normalize_url(target)

    # Construir lista de paths a probar
    paths = list(wordlist) if wordlist else list(_DEFAULT_WORDLIST)

    # Agregar variantes con extensiones
    if extensions:
        base_paths = list(paths)
        for path in base_paths:
            if "." not in path:
                for ext in extensions:
                    paths.append(f"{path}{ext}")

    found_paths: List[str] = []
    status_codes: dict = {}

    def probe(path: str):
        url = f"{base_url}/{path.lstrip('/')}"
        try:
            resp = _req.request(
                method,
                url,
                timeout=timeout,
                allow_redirects=False,
                verify=False,
                headers={"User-Agent": "Hado-Scanner/0.2"},
            )
            if resp.status_code in _INTERESTING_CODES:
                return path, resp.status_code
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(probe, p): p for p in paths}
        for future in as_completed(futures):
            result = future.result()
            if result:
                path, code = result
                found_paths.append(path)
                status_codes[path] = code

    # Ordenar por código de respuesta
    found_paths.sort(key=lambda p: status_codes.get(p, 999))

    return {
        "target":          base_url,
        "found_paths":     found_paths,
        "status_codes":    status_codes,
        "total_requests":  len(paths),
        "mode":            mode,
        "method":          "requests",
    }


def _normalize_url(target: str) -> str:
    """Asegura que la URL tenga esquema http/https."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    return target.rstrip("/")
