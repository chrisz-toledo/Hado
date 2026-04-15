"""
hado.cybersec.binary — ELF, PE y Mach-O binary parser.

Parsea headers de ejecutables sin dependencias externas (solo struct + stdlib).
Útil para análisis de exploits, detección de protecciones (NX, PIE, RELRO, stack canary),
y extracción de metadatos de binarios.

Uso:
    from hado.cybersec.binary import parse_elf, parse_pe, parse_macho, detect_protections
"""
from __future__ import annotations

import struct
import os
from typing import Dict, List, Optional, Tuple, Any


# ─── ELF Parser ──────────────────────────────────────────────────────────────

ELF_MAGIC = b'\x7fELF'

ELF_CLASS = {1: '32-bit', 2: '64-bit'}
ELF_DATA  = {1: 'Little-Endian', 2: 'Big-Endian'}
ELF_TYPE  = {0: 'ET_NONE', 1: 'ET_REL', 2: 'ET_EXEC', 3: 'ET_DYN', 4: 'ET_CORE'}
ELF_MACHINE = {
    0x00: 'No machine', 0x02: 'SPARC', 0x03: 'x86',
    0x08: 'MIPS', 0x14: 'PowerPC', 0x16: 'S390',
    0x28: 'ARM', 0x2a: 'SuperH', 0x32: 'IA-64',
    0x3e: 'x86-64', 0xb7: 'AArch64', 0xf3: 'RISC-V',
}

SHT_NAMES = {
    0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB',
    4: 'RELA', 5: 'HASH', 6: 'DYNAMIC', 7: 'NOTE',
    8: 'NOBITS', 9: 'REL', 11: 'DYNSYM',
}

PT_NAMES = {
    0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP',
    4: 'NOTE', 5: 'SHLIB', 6: 'PHDR', 7: 'TLS',
    0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK',
    0x6474e552: 'GNU_RELRO',
}

PF_FLAGS = {1: 'X', 2: 'W', 4: 'R'}


def _elf_endian(data: bytes) -> str:
    return '<' if data[5] == 1 else '>'


def parse_elf(path: str) -> Dict:
    """
    Parsea un binario ELF (Linux/Unix executable).

    Extrae:
    - Arquitectura, tipo, entry point
    - Secciones (.text, .data, .bss, .plt, .got, etc.)
    - Segmentos (LOAD, DYNAMIC, STACK, etc.)
    - Detección de protecciones (NX, PIE, RELRO, stack canary)
    - Strings interesantes en el binario

    Args:
        path: ruta al binario ELF

    Returns:
        dict con toda la información parseada

    Ejemplo:
        >>> info = parse_elf('/bin/ls')
        >>> info['arch']
        'x86-64'
        >>> info['protections']['pie']
        True
    """
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except (FileNotFoundError, PermissionError) as e:
        return {"error": str(e), "path": path}

    if len(data) < 4 or data[:4] != ELF_MAGIC:
        return {"error": "No es un ELF válido (magic bytes incorrectos)", "path": path}

    endian = _elf_endian(data)
    bits = 64 if data[4] == 2 else 32

    # ELF Header
    if bits == 64:
        hdr_fmt = f'{endian}HHIQQQIHHHHHH'
        hdr_size = struct.calcsize(hdr_fmt)
        (e_type, e_machine, e_version, e_entry,
         e_phoff, e_shoff, e_flags, e_ehsize,
         e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(hdr_fmt, data, 16)
    else:
        hdr_fmt = f'{endian}HHIIIIIHHHHHH'
        hdr_size = struct.calcsize(hdr_fmt)
        (e_type, e_machine, e_version, e_entry,
         e_phoff, e_shoff, e_flags, e_ehsize,
         e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(hdr_fmt, data, 16)

    # Secciones
    sections = []
    shstrtab_offset = None
    if e_shoff and e_shnum and e_shoff + e_shnum * e_shentsize <= len(data):
        if e_shstrndx < e_shnum:
            sh_off = e_shoff + e_shstrndx * e_shentsize
            if bits == 64:
                _, _, _, _, sh_name_offset, sh_size = struct.unpack_from(f'{endian}IIQQqq', data, sh_off)[:6]
            else:
                _, _, _, _, sh_name_offset, sh_size = struct.unpack_from(f'{endian}IIIIII', data, sh_off)[:6]
            shstrtab_offset = sh_name_offset

        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if bits == 64:
                sh_fmt = f'{endian}IIQQQQIIQQ'
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                 sh_size, sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack_from(sh_fmt, data, off)
            else:
                sh_fmt = f'{endian}IIIIIIIIII'
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                 sh_size, sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack_from(sh_fmt, data, off)

            # Leer nombre de sección
            name = ''
            if shstrtab_offset and sh_name:
                name_off = shstrtab_offset + sh_name
                end = data.find(b'\x00', name_off)
                if end > name_off:
                    name = data[name_off:end].decode('utf-8', errors='replace')

            sections.append({
                'name': name,
                'type': SHT_NAMES.get(sh_type, f'0x{sh_type:x}'),
                'address': hex(sh_addr) if sh_addr else '0x0',
                'offset': hex(sh_offset),
                'size': sh_size,
                'flags': _parse_section_flags(sh_flags),
            })

    # Segmentos (Program Headers)
    segments = []
    if e_phoff and e_phnum and e_phoff + e_phnum * e_phentsize <= len(data):
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if bits == 64:
                ph_fmt = f'{endian}IIQQQQQQ'
                (p_type, p_flags, p_offset, p_vaddr, p_paddr,
                 p_filesz, p_memsz, p_align) = struct.unpack_from(ph_fmt, data, off)
            else:
                ph_fmt = f'{endian}IIIIIIII'
                (p_type, p_offset, p_vaddr, p_paddr,
                 p_filesz, p_memsz, p_flags, p_align) = struct.unpack_from(ph_fmt, data, off)

            flags_str = ''.join(PF_FLAGS.get(f, '') for f in [4, 2, 1] if p_flags & f)
            segments.append({
                'type': PT_NAMES.get(p_type, f'0x{p_type:x}'),
                'flags': flags_str,
                'vaddr': hex(p_vaddr),
                'filesz': p_filesz,
                'memsz': p_memsz,
            })

    # Protecciones
    protections = _detect_elf_protections(data, segments, sections, bits, e_type)

    # Strings interesantes
    interesting = _find_interesting_strings(data)

    return {
        'path': path,
        'format': 'ELF',
        'arch': ELF_MACHINE.get(e_machine, f'0x{e_machine:x}'),
        'bits': bits,
        'endian': ELF_DATA.get(data[5], 'Unknown'),
        'type': ELF_TYPE.get(e_type, f'ET_{e_type}'),
        'entry_point': hex(e_entry),
        'sections_count': len(sections),
        'sections': sections,
        'segments_count': len(segments),
        'segments': segments,
        'protections': protections,
        'file_size': len(data),
        'interesting_strings': interesting[:20],
    }


def _parse_section_flags(flags: int) -> str:
    result = ''
    if flags & 0x1: result += 'W'  # Writable
    if flags & 0x2: result += 'A'  # Alloc
    if flags & 0x4: result += 'X'  # Executable
    return result or '-'


def _detect_elf_protections(data: bytes, segments: List, sections: List, bits: int, e_type: int) -> Dict:
    """Detecta protecciones de seguridad en un ELF."""
    # PIE: ET_DYN = 3
    pie = (e_type == 3)

    # NX (No-Execute): segmento GNU_STACK sin flag X
    nx = False
    for seg in segments:
        if seg['type'] == 'GNU_STACK':
            nx = 'X' not in seg['flags']
            break

    # RELRO: segmento GNU_RELRO presente
    relro = any(s['type'] == 'GNU_RELRO' for s in segments)

    # Full RELRO: BIND_NOW en DYNAMIC
    full_relro = False
    if relro:
        full_relro = b'BIND_NOW' in data or b'\x18\x00\x00\x00\x00\x00\x00\x00' in data

    # Stack canary: presencia de __stack_chk_fail en binario
    canary = b'__stack_chk_fail' in data or b'stack_chk' in data

    # FORTIFY_SOURCE: presencia de funciones _chk
    fortify = b'_chk' in data and (b'sprintf_chk' in data or b'strcpy_chk' in data or b'memcpy_chk' in data)

    # ASLR: no detectable desde el binario (es del OS), se indica como "OS-dependent"
    return {
        'pie': pie,
        'nx': nx,
        'relro': 'Full' if full_relro else ('Partial' if relro else 'None'),
        'canary': canary,
        'fortify': fortify,
        'aslr': 'OS-dependent',
        'summary': _protection_summary(pie, nx, relro, canary),
    }


def _protection_summary(pie: bool, nx: bool, relro: bool, canary: bool) -> str:
    enabled = []
    if pie: enabled.append('PIE')
    if nx: enabled.append('NX')
    if relro: enabled.append('RELRO')
    if canary: enabled.append('Canary')
    if not enabled:
        return '⚠️  Sin protecciones — CRÍTICO para exploit'
    if len(enabled) == 4:
        return '🔒 Todas las protecciones activas — difícil de explotar'
    return f'⚠️  Protecciones parciales: {", ".join(enabled)}'


def _find_interesting_strings(data: bytes, min_len: int = 6) -> List[str]:
    """Extrae strings interesantes del binario."""
    interesting_patterns = [
        b'password', b'passwd', b'secret', b'token', b'key', b'admin',
        b'root', b'sudo', b'/bin/', b'/etc/', b'http', b'https',
        b'exec', b'system', b'popen', b'flag{', b'CTF',
    ]
    results = []
    # Strings ASCII de longitud mínima
    current = b''
    for byte in data:
        if 32 <= byte < 127:
            current += bytes([byte])
        else:
            if len(current) >= min_len:
                s = current.decode('ascii', errors='ignore')
                if any(p.decode() in s.lower() for p in interesting_patterns):
                    results.append(s)
            current = b''
    return list(dict.fromkeys(results))  # dedup preservando orden


# ─── PE Parser ───────────────────────────────────────────────────────────────

PE_MAGIC = b'MZ'
PE_SIGNATURE = b'PE\x00\x00'

PE_MACHINE = {
    0x0000: 'Unknown', 0x014c: 'x86 (i386)', 0x0200: 'IA64',
    0x8664: 'x86-64 (AMD64)', 0xaa64: 'ARM64', 0x01c0: 'ARM',
    0x01c4: 'ARMv7', 0x01f0: 'PowerPC',
}

PE_CHARS = {
    0x0001: 'RELOCS_STRIPPED', 0x0002: 'EXECUTABLE',
    0x0020: 'LARGE_ADDRESS_AWARE', 0x0100: 'SYSTEM',
    0x0200: 'DLL', 0x2000: 'FILE_UP_SYSTEM_ONLY',
}

PE_SUBSYSTEM = {
    1: 'Native', 2: 'Windows GUI', 3: 'Windows CUI',
    7: 'POSIX CUI', 9: 'Windows CE GUI', 10: 'EFI Application',
}


def parse_pe(path: str) -> Dict:
    """
    Parsea un binario PE (Windows .exe / .dll).

    Extrae:
    - Arquitectura, tipo (EXE/DLL), timestamp, entry point
    - Secciones (.text, .data, .rdata, .rsrc, etc.)
    - Directorios de datos (Import, Export, TLS, etc.)
    - Detección de protecciones (ASLR/DynamicBase, DEP/NX, CFG, SafeSEH)

    Args:
        path: ruta al binario PE

    Returns:
        dict con información completa del PE
    """
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except (FileNotFoundError, PermissionError) as e:
        return {"error": str(e), "path": path}

    if len(data) < 2 or data[:2] != PE_MAGIC:
        return {"error": "No es un PE válido (MZ magic incorrecto)", "path": path}

    # Offset al PE header
    pe_offset = struct.unpack_from('<I', data, 0x3c)[0]
    if pe_offset + 4 > len(data) or data[pe_offset:pe_offset + 4] != PE_SIGNATURE:
        return {"error": "PE signature no encontrada", "path": path}

    off = pe_offset + 4  # Después de 'PE\0\0'

    # COFF Header (20 bytes)
    coff_fmt = '<HHIIIHH'
    (machine, num_sections, timestamp, sym_table_ptr,
     num_symbols, opt_hdr_size, characteristics) = struct.unpack_from(coff_fmt, data, off)
    off += struct.calcsize(coff_fmt)

    # Optional Header
    is_pe32_plus = False
    entry_point = 0
    image_base = 0
    dll_characteristics = 0
    subsystem = 0

    if opt_hdr_size >= 2:
        magic = struct.unpack_from('<H', data, off)[0]
        is_pe32_plus = (magic == 0x20b)  # PE32+ (64-bit)

        if is_pe32_plus:
            (_, major_linker, minor_linker, code_size,
             init_size, uninit_size, entry_point, code_base) = struct.unpack_from('<HBBIIIII', data, off)
            off_ibase = off + 24
            image_base = struct.unpack_from('<Q', data, off_ibase)[0]
            off_sub = off + 68
        else:
            (_, major_linker, minor_linker, code_size,
             init_size, uninit_size, entry_point, code_base, data_base) = struct.unpack_from('<HBBIIIIII', data, off)
            off_ibase = off + 28
            image_base = struct.unpack_from('<I', data, off_ibase)[0]
            off_sub = off + 68

        if off_sub + 4 <= len(data):
            subsystem = struct.unpack_from('<H', data, off_sub)[0]
            dll_characteristics = struct.unpack_from('<H', data, off_sub + 2)[0]

    # Secciones
    sections_off = pe_offset + 4 + 20 + opt_hdr_size
    sections = []
    for i in range(num_sections):
        sec_off = sections_off + i * 40
        if sec_off + 40 > len(data):
            break
        (name_raw, virtual_size, virtual_addr, raw_size, raw_offset,
         _, _, _, _, sec_chars) = struct.unpack_from('<8sIIIIIIIII', data, sec_off)
        name = name_raw.rstrip(b'\x00').decode('utf-8', errors='replace')
        sections.append({
            'name': name,
            'virtual_addr': hex(virtual_addr),
            'virtual_size': virtual_size,
            'raw_offset': hex(raw_offset),
            'raw_size': raw_size,
            'executable': bool(sec_chars & 0x20000000),
            'writable': bool(sec_chars & 0x80000000),
            'readable': bool(sec_chars & 0x40000000),
        })

    # Detección de protecciones
    aslr   = bool(dll_characteristics & 0x0040)  # DYNAMIC_BASE
    dep    = bool(dll_characteristics & 0x0100)  # NX_COMPAT
    cfg    = bool(dll_characteristics & 0x4000)  # GUARD_CF
    safeseh = bool(dll_characteristics & 0x0400)  # NO_SEH ausente = SafeSEH activo
    is_dll  = bool(characteristics & 0x2000)

    return {
        'path': path,
        'format': 'PE',
        'type': 'DLL' if is_dll else 'EXE',
        'bits': 64 if is_pe32_plus else 32,
        'arch': PE_MACHINE.get(machine, f'0x{machine:x}'),
        'entry_point': hex(entry_point),
        'image_base': hex(image_base),
        'timestamp': timestamp,
        'subsystem': PE_SUBSYSTEM.get(subsystem, f'0x{subsystem:x}'),
        'sections_count': len(sections),
        'sections': sections,
        'protections': {
            'aslr': aslr,
            'dep': dep,
            'cfg': cfg,
            'safe_seh': safeseh,
            'summary': _pe_protection_summary(aslr, dep, cfg),
        },
        'file_size': len(data),
        'interesting_strings': _find_interesting_strings(data)[:20],
    }


def _pe_protection_summary(aslr: bool, dep: bool, cfg: bool) -> str:
    enabled = []
    if aslr: enabled.append('ASLR')
    if dep:  enabled.append('DEP/NX')
    if cfg:  enabled.append('CFG')
    if not enabled:
        return '⚠️  Sin protecciones — fácil de explotar'
    return f'Protecciones: {", ".join(enabled)}'


# ─── Mach-O Parser ───────────────────────────────────────────────────────────

MACHO_MAGIC = {
    0xfeedface: ('32-bit', 'Big-Endian'),
    0xcefaedfe: ('32-bit', 'Little-Endian'),
    0xfeedfacf: ('64-bit', 'Big-Endian'),
    0xcffaedfe: ('64-bit', 'Little-Endian'),
    0xcafebabe: ('FAT', 'Big-Endian'),   # Universal binary
}

MACHO_CPUTYPE = {
    7: 'x86', 0x1000007: 'x86-64',
    12: 'ARM', 0x100000c: 'ARM64',
    18: 'PowerPC', 0x1000012: 'PowerPC64',
}

MACHO_FILETYPE = {
    1: 'MH_OBJECT', 2: 'MH_EXECUTE', 3: 'MH_FVMLIB',
    4: 'MH_CORE', 5: 'MH_PRELOAD', 6: 'MH_DYLIB',
    7: 'MH_DYLINKER', 8: 'MH_BUNDLE', 9: 'MH_DYLIB_STUB',
    10: 'MH_DSYM',
}


def parse_macho(path: str) -> Dict:
    """
    Parsea un binario Mach-O (macOS/iOS executable).

    Args:
        path: ruta al binario Mach-O

    Returns:
        dict con arquitectura, tipo, load commands, secciones
    """
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except (FileNotFoundError, PermissionError) as e:
        return {"error": str(e), "path": path}

    if len(data) < 4:
        return {"error": "Archivo demasiado pequeño", "path": path}

    magic = struct.unpack_from('>I', data, 0)[0]
    if magic not in MACHO_MAGIC:
        magic = struct.unpack_from('<I', data, 0)[0]
        if magic not in MACHO_MAGIC:
            return {"error": "No es un Mach-O válido", "path": path}

    bits, endian_name = MACHO_MAGIC[magic]
    endian = '<' if 'Little' in endian_name else '>'

    if bits == 'FAT':
        return {'path': path, 'format': 'Mach-O FAT (Universal Binary)',
                'note': 'Contiene múltiples arquitecturas', 'bits': 'multi'}

    is_64 = bits == '64-bit'
    cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
        f'{endian}IIIIII', data, 4)

    # PIE: MH_PIE flag = 0x200000
    pie = bool(flags & 0x200000)
    # No heap execution: MH_NO_HEAP_EXECUTION = 0x1000000
    no_heap = bool(flags & 0x1000000)

    return {
        'path': path,
        'format': 'Mach-O',
        'bits': bits,
        'endian': endian_name,
        'arch': MACHO_CPUTYPE.get(cputype, f'0x{cputype:x}'),
        'filetype': MACHO_FILETYPE.get(filetype, f'0x{filetype:x}'),
        'load_commands_count': ncmds,
        'flags': hex(flags),
        'protections': {
            'pie': pie,
            'no_heap_exec': no_heap,
            'arc': b'objc_release' in data,
        },
        'file_size': len(data),
        'interesting_strings': _find_interesting_strings(data)[:20],
    }


# ─── Auto-detect & unified API ───────────────────────────────────────────────

def parse_binary(path: str) -> Dict:
    """
    Auto-detecta el formato (ELF/PE/Mach-O) y parsea el binario.

    Args:
        path: ruta al binario

    Returns:
        dict con información completa del binario + formato detectado
    """
    try:
        with open(path, 'rb') as f:
            magic = f.read(4)
    except (FileNotFoundError, PermissionError) as e:
        return {"error": str(e), "path": path}

    if magic[:4] == ELF_MAGIC:
        return parse_elf(path)
    elif magic[:2] == PE_MAGIC:
        return parse_pe(path)
    elif struct.unpack_from('>I', magic)[0] in MACHO_MAGIC or \
         struct.unpack_from('<I', magic)[0] in MACHO_MAGIC:
        return parse_macho(path)
    else:
        return {"error": f"Formato desconocido (magic: {magic.hex()})", "path": path,
                "magic": magic.hex()}


def detect_protections(path: str) -> Dict:
    """
    Detecta protecciones de seguridad en un binario (ELF o PE).
    Wrapper de alto nivel sobre parse_elf/parse_pe.

    Returns:
        dict con: pie, nx/dep, relro/aslr, canary/safeseh, summary
    """
    result = parse_binary(path)
    if 'error' in result:
        return result
    return result.get('protections', {"error": "No se pudo determinar protecciones"})
