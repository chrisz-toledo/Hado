"""
Hado cybersec — Scanner de puertos.
Wrapper sobre nmap (si disponible) y socket como fallback.
"""

import socket
import subprocess
from typing import Dict, List


def scan(target: str, ports: List[int]) -> Dict[str, any]:
    """
    Escanea puertos en un target.
    Intenta usar nmap primero; si no esta disponible usa socket.connect_ex.

    Returns:
        dict con claves:
          - target: str
          - open_ports: List[int]
          - closed_ports: List[int]
          - results: Dict[int, bool]
          - method: "nmap" | "socket"
    """
    results = {}

    # Intentar nmap primero
    nmap_result = _try_nmap(target, ports)
    if nmap_result is not None:
        return nmap_result

    # Fallback a socket
    for port in ports:
        results[port] = _check_port_socket(target, port)

    open_ports = [p for p, is_open in results.items() if is_open]
    closed_ports = [p for p, is_open in results.items() if not is_open]

    return {
        "target": target,
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "results": results,
        "method": "socket",
    }


def _check_port_socket(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except (socket.error, OSError):
        return False


def _try_nmap(target: str, ports: List[int]) -> dict | None:
    try:
        port_str = ",".join(str(p) for p in ports)
        proc = subprocess.run(
            ["nmap", "-p", port_str, "--open", "-T4", target],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0:
            return None

        open_ports = _parse_nmap_output(proc.stdout)
        results = {p: (p in open_ports) for p in ports}
        closed_ports = [p for p in ports if p not in open_ports]

        return {
            "target": target,
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "results": results,
            "method": "nmap",
        }
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _parse_nmap_output(output: str) -> List[int]:
    open_ports = []
    for line in output.splitlines():
        line = line.strip()
        if "/tcp" in line and "open" in line:
            try:
                port = int(line.split("/")[0])
                open_ports.append(port)
            except ValueError:
                pass
    return open_ports
