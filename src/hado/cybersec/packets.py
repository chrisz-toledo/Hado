"""
hado.cybersec.packets — Raw packet crafting: SYN scan, UDP scan, ICMP ping.

Requiere privilegios root para raw sockets.
Fallback automático a TCP connect si no hay privilegios.

Uso directo (Python):
    from hado.cybersec.packets import syn_scan, udp_scan, icmp_ping, craft_tcp_packet
"""
from __future__ import annotations

import socket
import struct
import os
import time
import random
from typing import List, Dict, Optional


# ─── Checksum ────────────────────────────────────────────────────────────────

def _checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _local_ip() -> str:
    """Detecta la IP local de salida."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ─── Packet builders ─────────────────────────────────────────────────────────

def _build_ip_header(src_ip: str, dst_ip: str, protocol: int, total_len: int) -> bytes:
    """Construye IP header (20 bytes)."""
    ver_ihl = (4 << 4) | 5
    tos = 0
    ident = random.randint(1000, 65535)
    flags_frag = 0
    ttl = 64
    checksum = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    hdr = struct.pack('!BBHHHBBH4s4s',
        ver_ihl, tos, total_len, ident, flags_frag,
        ttl, protocol, checksum, src, dst)
    checksum = _checksum(hdr)
    return struct.pack('!BBHHHBBH4s4s',
        ver_ihl, tos, total_len, ident, flags_frag,
        ttl, protocol, checksum, src, dst)


def _build_tcp_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      seq: int, ack: int, flags: int, payload: bytes = b'') -> bytes:
    """Construye TCP header con pseudo-header checksum."""
    data_offset = (5 << 4)  # 5 * 4 = 20 bytes, no options
    window = socket.htons(65535)
    checksum = 0
    urg_ptr = 0

    tcp_hdr = struct.pack('!HHIIHHHH',
        src_port, dst_port, seq, ack,
        data_offset, flags, window, checksum) + struct.pack('!H', urg_ptr)

    # Pseudo-header para checksum
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    pseudo = struct.pack('!4s4sBBH',
        src_addr, dst_addr, 0, socket.IPPROTO_TCP,
        len(tcp_hdr) + len(payload))
    checksum = _checksum(pseudo + tcp_hdr + payload)

    return struct.pack('!HHIIHHHH',
        src_port, dst_port, seq, ack,
        data_offset, flags, window, checksum) + struct.pack('!H', urg_ptr)


def _build_udp_header(src_ip: str, dst_ip: str,
                      src_port: int, dst_port: int, payload: bytes = b'') -> bytes:
    """Construye UDP header con pseudo-header checksum."""
    length = 8 + len(payload)
    checksum = 0
    udp_hdr = struct.pack('!HHHH', src_port, dst_port, length, checksum)

    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    pseudo = struct.pack('!4s4sBBH',
        src_addr, dst_addr, 0, socket.IPPROTO_UDP, length)
    checksum = _checksum(pseudo + udp_hdr + payload)

    return struct.pack('!HHHH', src_port, dst_port, length, checksum)


def _build_icmp_echo(identifier: int = 1, sequence: int = 1, payload: bytes = b'HADO') -> bytes:
    """Construye ICMP echo request."""
    type_ = 8   # Echo request
    code = 0
    checksum = 0
    hdr = struct.pack('!BBHHH', type_, code, checksum, identifier, sequence)
    checksum = _checksum(hdr + payload)
    return struct.pack('!BBHHH', type_, code, checksum, identifier, sequence) + payload


# ─── Public API ──────────────────────────────────────────────────────────────

def craft_tcp_packet(dst_ip: str, dst_port: int, flags: str = "S",
                     src_ip: Optional[str] = None, src_port: int = 0,
                     payload: bytes = b'') -> bytes:
    """
    Construye un paquete TCP raw completo (IP + TCP).

    Args:
        dst_ip:    IP destino
        dst_port:  Puerto destino
        flags:     Flags TCP: "S"=SYN, "A"=ACK, "R"=RST, "F"=FIN, "SA"=SYN-ACK, "PA"=PSH-ACK
        src_ip:    IP origen (detecta automáticamente si None)
        src_port:  Puerto origen (aleatorio si 0)
        payload:   Payload TCP

    Returns:
        bytes del paquete completo (IP header + TCP header + payload)
    """
    if src_ip is None:
        src_ip = _local_ip()
    if src_port == 0:
        src_port = random.randint(1024, 65535)

    flag_map = {'F': 0x01, 'S': 0x02, 'R': 0x04, 'P': 0x08,
                'A': 0x10, 'U': 0x20, 'E': 0x40, 'C': 0x80}
    tcp_flags = 0
    for f in flags.upper():
        tcp_flags |= flag_map.get(f, 0)

    seq = random.randint(0, 2**32 - 1)
    ack = 0

    tcp_hdr = _build_tcp_header(src_ip, dst_ip, src_port, dst_port, seq, ack, tcp_flags, payload)
    total_len = 20 + len(tcp_hdr) + len(payload)
    ip_hdr = _build_ip_header(src_ip, dst_ip, socket.IPPROTO_TCP, total_len)
    return ip_hdr + tcp_hdr + payload


def craft_udp_packet(dst_ip: str, dst_port: int,
                     src_ip: Optional[str] = None, src_port: int = 0,
                     payload: bytes = b'') -> bytes:
    """
    Construye un paquete UDP raw completo (IP + UDP).

    Returns:
        bytes del paquete completo
    """
    if src_ip is None:
        src_ip = _local_ip()
    if src_port == 0:
        src_port = random.randint(1024, 65535)

    udp_hdr = _build_udp_header(src_ip, dst_ip, src_port, dst_port, payload)
    total_len = 20 + 8 + len(payload)
    ip_hdr = _build_ip_header(src_ip, dst_ip, socket.IPPROTO_UDP, total_len)
    return ip_hdr + udp_hdr + payload


def craft_icmp_packet(dst_ip: str, src_ip: Optional[str] = None,
                      payload: bytes = b'HADO-PING') -> bytes:
    """
    Construye un paquete ICMP echo request raw.

    Returns:
        bytes del paquete completo (IP + ICMP)
    """
    if src_ip is None:
        src_ip = _local_ip()

    icmp_data = _build_icmp_echo(identifier=os.getpid() & 0xFFFF, payload=payload)
    total_len = 20 + len(icmp_data)
    ip_hdr = _build_ip_header(src_ip, dst_ip, socket.IPPROTO_ICMP, total_len)
    return ip_hdr + icmp_data


def syn_scan(target: str, ports: List[int], timeout: float = 2.0) -> Dict:
    """
    SYN scan (half-open) en los puertos especificados.

    Requiere root para raw sockets.
    Fallback automático a TCP connect si no hay privilegios.

    Args:
        target:  IP o hostname objetivo
        ports:   Lista de puertos a escanear
        timeout: Timeout por puerto en segundos

    Returns:
        {
          "target": str,
          "method": "syn_raw" | "tcp_connect_fallback",
          "open_ports": [int, ...],
          "closed_ports": [int, ...],
          "filtered_ports": [int, ...],
          "total_scanned": int,
        }
    """
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        return {"target": target, "error": str(e), "open_ports": [], "method": "error"}

    open_ports: List[int] = []
    closed_ports: List[int] = []
    filtered_ports: List[int] = []

    # Intentar raw socket (requiere root)
    can_raw = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False

    if can_raw:
        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            recv_sock.settimeout(timeout)
            src_ip = _local_ip()
            src_port = random.randint(1024, 65535)

            for port in ports:
                pkt = craft_tcp_packet(target_ip, port, flags="S",
                                       src_ip=src_ip, src_port=src_port)
                try:
                    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    send_sock.sendto(pkt, (target_ip, 0))
                    send_sock.close()

                    # Esperar respuesta
                    deadline = time.time() + timeout
                    got_response = False
                    while time.time() < deadline:
                        try:
                            data = recv_sock.recv(4096)
                            # Parse IP header (20 bytes) + TCP header
                            if len(data) < 40:
                                continue
                            # TCP flags en offset 33 del IP+TCP
                            tcp_flags_byte = data[33]
                            tcp_src_port = struct.unpack('!H', data[20:22])[0]
                            if tcp_src_port == port:
                                got_response = True
                                # SYN-ACK = 0x12 → open
                                if tcp_flags_byte & 0x12 == 0x12:
                                    open_ports.append(port)
                                # RST = 0x04 → closed
                                elif tcp_flags_byte & 0x04:
                                    closed_ports.append(port)
                                break
                        except socket.timeout:
                            break
                    if not got_response:
                        filtered_ports.append(port)
                except Exception:
                    filtered_ports.append(port)

            recv_sock.close()
            return {
                "target": target,
                "method": "syn_raw",
                "open_ports": open_ports,
                "closed_ports": closed_ports,
                "filtered_ports": filtered_ports,
                "total_scanned": len(ports),
            }
        except PermissionError:
            can_raw = False

    # Fallback: TCP connect scan
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((target_ip, port))
            s.close()
            if result == 0:
                open_ports.append(port)
            else:
                closed_ports.append(port)
        except Exception:
            filtered_ports.append(port)

    return {
        "target": target,
        "method": "tcp_connect_fallback",
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "filtered_ports": filtered_ports,
        "total_scanned": len(ports),
    }


def udp_scan(target: str, ports: List[int], timeout: float = 2.0) -> Dict:
    """
    UDP scan: envía paquetes UDP vacíos, detecta ICMP port unreachable.

    Puertos cerrados responden con ICMP unreachable.
    Puertos abiertos/filtrados no responden (no hay RST en UDP).

    Args:
        target:  IP o hostname objetivo
        ports:   Lista de puertos UDP a probar
        timeout: Timeout por puerto

    Returns:
        dict con open_or_filtered, closed, total_scanned
    """
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        return {"target": target, "error": str(e), "open_or_filtered": [], "method": "error"}

    open_or_filtered: List[int] = []
    closed: List[int] = []

    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(b'', (target_ip, port))
            try:
                s.recv(1024)
                open_or_filtered.append(port)  # recibió respuesta → servicio UDP activo
            except socket.timeout:
                open_or_filtered.append(port)  # no reply → open or filtered (típico en UDP)
            except ConnectionRefusedError:
                closed.append(port)  # ICMP port unreachable → cerrado
            s.close()
        except Exception:
            open_or_filtered.append(port)

    return {
        "target": target,
        "method": "udp_scan",
        "open_or_filtered": open_or_filtered,
        "closed": closed,
        "total_scanned": len(ports),
        "note": "UDP: sin respuesta = open/filtered; ConnectionRefused = ICMP unreachable = closed",
    }


def icmp_ping(target: str, count: int = 3, timeout: float = 2.0) -> Dict:
    """
    ICMP echo request (ping).

    Requiere root para raw sockets.
    Usa subprocess ping como fallback.

    Args:
        target:  IP o hostname objetivo
        count:   Número de pings
        timeout: Timeout por ping

    Returns:
        {
          "target": str,
          "alive": bool,
          "method": "icmp_raw" | "subprocess_ping" | "tcp_probe",
          "rtt_ms": float | None,
          "sent": int,
          "received": int,
        }
    """
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        return {"target": target, "alive": False, "error": str(e), "method": "error"}

    can_raw = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False

    # Intentar ICMP raw
    if can_raw:
        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_sock.settimeout(timeout)
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

            received = 0
            rtts = []
            pid = os.getpid() & 0xFFFF

            for seq in range(count):
                icmp_pkt = _build_icmp_echo(identifier=pid, sequence=seq)
                t_send = time.time()
                send_sock.sendto(icmp_pkt, (target_ip, 1))
                try:
                    data = recv_sock.recv(1024)
                    t_recv = time.time()
                    # Parse: 20 bytes IP + 8 bytes ICMP → check type=0 (echo reply)
                    if len(data) >= 28 and data[20] == 0:
                        received += 1
                        rtts.append((t_recv - t_send) * 1000)
                except socket.timeout:
                    pass

            send_sock.close()
            recv_sock.close()

            return {
                "target": target,
                "alive": received > 0,
                "method": "icmp_raw",
                "rtt_ms": round(sum(rtts) / len(rtts), 2) if rtts else None,
                "sent": count,
                "received": received,
            }
        except PermissionError:
            pass

    # Fallback: subprocess ping
    try:
        import subprocess
        result = subprocess.run(
            ['ping', '-c', str(count), '-W', str(int(timeout)), target],
            capture_output=True, text=True, timeout=timeout * count + 2
        )
        alive = result.returncode == 0
        rtt = None
        for line in result.stdout.splitlines():
            if 'rtt' in line or 'round-trip' in line:
                parts = line.split('=')
                if len(parts) > 1:
                    rtt = float(parts[-1].split('/')[1])
        return {
            "target": target,
            "alive": alive,
            "method": "subprocess_ping",
            "rtt_ms": rtt,
            "sent": count,
            "received": count if alive else 0,
        }
    except Exception:
        pass

    # Last resort: TCP probe en puerto 80
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        s.connect_ex((target_ip, 80))
        rtt = (time.time() - t0) * 1000
        s.close()
        return {"target": target, "alive": True, "method": "tcp_probe",
                "rtt_ms": round(rtt, 2), "sent": 1, "received": 1}
    except Exception:
        return {"target": target, "alive": False, "method": "tcp_probe",
                "rtt_ms": None, "sent": 1, "received": 0}


def parse_tcp_flags(flags_byte: int) -> List[str]:
    """Convierte el byte de flags TCP en lista de nombres."""
    names = []
    if flags_byte & 0x01: names.append('FIN')
    if flags_byte & 0x02: names.append('SYN')
    if flags_byte & 0x04: names.append('RST')
    if flags_byte & 0x08: names.append('PSH')
    if flags_byte & 0x10: names.append('ACK')
    if flags_byte & 0x20: names.append('URG')
    return names
