"""
Hado cybersec — Captura de trafico de red.
Usa tcpdump via subprocess; stub para scapy cuando este disponible.
"""

import subprocess
import warnings
from typing import List, Optional


def capture(interface: str, filter_expr: str = "", count: int = 100) -> List[dict]:
    """
    Captura paquetes en una interfaz de red.

    Args:
        interface: nombre de la interfaz (ej: "eth0", "en0")
        filter_expr: filtro BPF (ej: "tcp port 80")
        count: numero maximo de paquetes a capturar

    Returns:
        Lista de dicts con info de cada paquete; [] si tcpdump no disponible.
    """
    # Intentar scapy primero
    try:
        return _capture_scapy(interface, filter_expr, count)
    except ImportError:
        pass

    # Fallback a tcpdump
    try:
        return _capture_tcpdump(interface, filter_expr, count)
    except FileNotFoundError:
        warnings.warn(
            "tcpdump no encontrado. Instala tcpdump o scapy para captura de paquetes.",
            RuntimeWarning,
            stacklevel=2,
        )
        return []


def _capture_scapy(interface: str, filter_expr: str, count: int) -> List[dict]:
    from scapy.all import sniff  # type: ignore

    packets = sniff(iface=interface, filter=filter_expr, count=count, timeout=10)
    result = []
    for pkt in packets:
        result.append({
            "summary": pkt.summary(),
            "len": len(pkt),
            "time": float(pkt.time),
        })
    return result


def _capture_tcpdump(interface: str, filter_expr: str, count: int) -> List[dict]:
    cmd = ["tcpdump", "-i", interface, "-c", str(count), "-l", "-nn"]
    if filter_expr:
        cmd.extend(filter_expr.split())

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    packets = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line:
            packets.append({"summary": line, "len": 0, "time": 0.0})
    return packets
