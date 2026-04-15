"""
Hado cybersec — Reconocimiento y OSINT.
Subdominios, DNS records, whois, email harvesting basico.
"""

import socket
import subprocess
import re
from typing import List, Optional, Dict


DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "api", "dev", "staging", "admin", "test",
    "smtp", "pop", "imap", "vpn", "ssh", "git", "cdn", "static",
    "assets", "beta", "alpha", "demo", "app", "portal", "secure",
    "login", "auth", "blog", "shop", "store", "media", "images",
]


def find_subdomains(domain: str, wordlist: Optional[List[str]] = None) -> List[str]:
    """
    Enumera subdominios de un dominio via DNS resolution.

    Args:
        domain: dominio objetivo (ej: "ejemplo.com")
        wordlist: lista de prefijos a probar; usa DEFAULT_WORDLIST si es None

    Returns:
        Lista de FQDNs que resuelven (estan vivos)
    """
    prefixes = wordlist if wordlist is not None else DEFAULT_WORDLIST
    alive = []

    for prefix in prefixes:
        fqdn = f"{prefix}.{domain}"
        if _resolves(fqdn):
            alive.append(fqdn)

    return alive


def _resolves(fqdn: str) -> bool:
    try:
        socket.gethostbyname(fqdn)
        return True
    except (socket.gaierror, socket.herror, OSError):
        return False


def dns_lookup(domain: str) -> dict:
    """Resolucion DNS basica de un dominio."""
    result = {"domain": domain, "ips": [], "error": None}
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = list({info[4][0] for info in infos})
        result["ips"] = ips
    except socket.gaierror as e:
        result["error"] = str(e)
    return result


def reverse_lookup(ip: str) -> Optional[str]:
    """Lookup DNS inverso."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def dns_records(domain: str) -> Dict[str, list]:
    """
    Consulta registros DNS (A, MX, TXT, NS, CNAME) via dig o nslookup.

    Args:
        domain: dominio objetivo

    Returns:
        dict con tipos de registro como claves y listas de valores
    """
    records: Dict[str, list] = {"A": [], "MX": [], "TXT": [], "NS": [], "CNAME": []}

    # Intentar con dig primero
    for rtype in records:
        try:
            result = subprocess.run(
                ["dig", "+short", rtype, domain],
                capture_output=True, text=True, timeout=10,
            )
            lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
            if lines:
                records[rtype] = lines
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # dig no disponible — usar socket para A records al menos
            if rtype == "A":
                try:
                    infos = socket.getaddrinfo(domain, None)
                    records["A"] = list({info[4][0] for info in infos})
                except Exception:
                    pass

    return {k: v for k, v in records.items() if v}


def whois_lookup(domain: str) -> Dict[str, str]:
    """
    Consulta WHOIS de un dominio.

    Args:
        domain: dominio a consultar

    Returns:
        dict con campos WHOIS relevantes (registrar, creation_date, expiry, etc.)
    """
    result: Dict[str, str] = {"domain": domain}

    # Intentar python-whois primero
    try:
        import whois  # type: ignore
        w = whois.whois(domain)
        result["registrar"]     = str(w.registrar or "")
        result["creation_date"] = str(w.creation_date or "")
        result["expiry_date"]   = str(w.expiration_date or "")
        result["name_servers"]  = ", ".join(w.name_servers or [])
        result["status"]        = str(w.status or "")
        return result
    except ImportError:
        pass
    except Exception:
        pass

    # Fallback: whois via subprocess
    try:
        proc = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=15,
        )
        raw = proc.stdout
        # Extraer campos comunes
        patterns = {
            "registrar":     r"Registrar:\s*(.+)",
            "creation_date": r"Creation Date:\s*(.+)",
            "expiry_date":   r"Registry Expiry Date:\s*(.+)",
            "name_servers":  r"Name Server:\s*(.+)",
            "status":        r"Domain Status:\s*(.+)",
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, raw, re.IGNORECASE)
            if match:
                result[key] = match.group(1).strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        result["error"] = "whois no disponible. Instala python-whois: pip install python-whois"

    return result


def email_harvest(domain: str) -> List[str]:
    """
    Cosecha básica de emails asociados a un dominio via búsquedas DNS/web.
    Busca en registros TXT (SPF, DMARC) y retorna emails encontrados.

    Args:
        domain: dominio objetivo

    Returns:
        Lista de emails encontrados (puede estar vacía si no hay acceso)
    """
    emails = set()
    email_pattern = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

    # Buscar en registros TXT del dominio
    try:
        result = subprocess.run(
            ["dig", "+short", "TXT", domain],
            capture_output=True, text=True, timeout=10,
        )
        matches = email_pattern.findall(result.stdout)
        emails.update(matches)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Buscar en DMARC
    try:
        result = subprocess.run(
            ["dig", "+short", "TXT", f"_dmarc.{domain}"],
            capture_output=True, text=True, timeout=10,
        )
        matches = email_pattern.findall(result.stdout)
        emails.update(matches)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return sorted(emails)
