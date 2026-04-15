# Hado v0.4 — Capabilities Audit

**Fecha:** 2026-04-14  
**Versión auditada:** v0.4.0 (188 tests + 56 capability tests)  
**Propósito:** Respuesta honesta a "¿puede Hado usarse para zero-day / exploit tooling?"

---

## Veredicto ejecutivo

Hado es un **DSL de reconocimiento y análisis de seguridad**, no un exploit framework. Es production-ready para la fase de recon del pentest lifecycle. Para exploit development real (buffer overflows, shellcode, ROP chains), se necesitan herramientas como pwntools, scapy, ropper — Hado no las reemplaza, puede orquestarlas.

```
Hado sweet spot:
Recon → Scan → Analysis → Report

NOT:
Exploit → Shellcode → Payload delivery → Post-exploitation
```

---

## Mapa completo de capacidades

### ✅ Production-Ready (funciona hoy, sin condiciones)

| Capacidad | Módulo | Backend(s) | Notas |
|-----------|--------|-----------|-------|
| Port scanning (TCP connect) | `scanner.py` | Python, Go, C, Rust | nmap primary + socket fallback |
| Go port scan con goroutines | `go_transpiler.py` | Go | `sync.WaitGroup` + `net.DialTimeout`, stdlib only |
| C port scan POSIX | `c_transpiler.py` | C | `hado_scan_port()` con `socket()`/`connect()` |
| Rust port scan | `rust_transpiler.py` | Rust | `TcpStream::connect_timeout` |
| Subdomain enumeration DNS | `recon.py` | Python | DNS resolution via `socket.gethostbyname` |
| HTTP brute force | `attack.py` | Python | `requests` con wordlist |
| FTP brute force | `attack.py` | Python | `ftplib` stdlib |
| HTTP header analysis (A-F grade) | `analysis.py` | Python | 9 headers OWASP, sin red necesaria si pasas dict |
| Port risk scoring | `analysis.py` | Python | DB de puertos críticos (Telnet=CRITICAL, etc.) |
| SHA-256/512/1, MD5 hashing | `crypto.py` | Python | stdlib `hashlib`, sin deps externas |
| Base64 encode/decode | `crypto.py` | Python | stdlib `base64` |
| HMAC-SHA256 | `crypto.py` | Python | stdlib `hmac` |
| Crypto-secure token generation | `crypto.py` | Python | stdlib `secrets` |
| Markdown/HTML/JSON/text reports | `report.py` | Python | auto-persist a `hado_report.json` |
| Multi-dataset consolidation | `report.py` | Python | `consolidate(*datasets)` |
| Pipe operator `->` | transpiler | Python | se expande en pasos `_pipe_N` |
| DNS records (A, MX, TXT, NS) | `recon.py` | Python | subprocess `dig` |
| WHOIS lookup | `recon.py` | Python | `python-whois` o `whois` subprocess |

---

### ⚠️ Funcional con Condiciones

| Capacidad | Condición | Impacto si falta |
|-----------|-----------|-----------------|
| SSH brute force | Requiere `pip install paramiko` | Retorna `{"error": "paramiko not installed"}` — falla explícito, no silencioso |
| Packet capture | Requiere root + `scapy` o `tcpdump` | Retorna lista vacía `[]` |
| Directory fuzzing | Solo accesible vía Python directo (`from hado.cybersec.fuzzer import fuzz`) | No hay keyword `.ho` — sin sintaxis nativa |
| Cryptografía | Solo accesible vía Python directo (`from hado.cybersec.crypto import ...`) | No hay sintaxis `.ho` — spec dice "planned for v0.2", aún pendiente en v0.4 |
| Subdomain DNS enum | Requiere resolución DNS funcional | En red aislada retorna lista vacía |
| Nmap scan (modo avanzado) | Requiere nmap instalado | Fallback automático a socket TCP connect |

---

### ❌ No Implementado — Gaps para Zero-Day Work

Estas son las capacidades que un investigador de zero-days esperaría y que **Hado v0.4 no tiene**:

#### 1. Raw Packet Crafting
```hado
// Lo que NO existe en Hado:
envía tcp a "192.168.1.1" con flags [SYN] y puerto 80
envía udp a "1.2.3.4" con payload "\x41\x41\x41\x41"
```
**Para esto:** usar Scapy directamente en Python.  
**Por qué importa:** SYN scans, OS fingerprinting, fragmentation attacks.

#### 2. Buffer Overflow / Memory Primitives
```hado
// Lo que NO existe:
genera pattern 1024  // cyclic pattern para offset
calcula offset "Aa0A"
sobrescribe ret en 0x4141  
```
**Para esto:** pwntools (`cyclic`, `p64`, `flat`).  
**Por qué importa:** exploit development requiere control preciso de memoria.

#### 3. Shellcode Generation / Injection
No hay primitivas para:
- Generar shellcode (msfvenom-style)
- Ejecutar shellcode en memoria
- Syscall wrappers (`mmap`, `mprotect`, `execve`)

#### 4. Binary Parsing (ELF/PE/Mach-O)
```hado
// Lo que NO existe:
info = lee elf "binary"         // no es un ELFNode en el AST
secciones = parse pe "malware.exe"
```
**Para esto:** `pyelftools`, `pefile`, `lief`.

#### 5. Encryption Nativa
```hado
// Lo que NO existe en sintaxis .ho (sí en módulo Python):
cifrado = encripta datos con aes clave "secreto"
firma = firma mensaje con rsa clave "priv.pem"
```
`crypto.py` tiene hashing pero no AES/RSA. Spec lo prometía para v0.2, pendiente en v0.4.

#### 6. CVE Database Integration
```hado
busca vulns en target donde severity >= HIGH
```
Esta sintaxis **compila pero no conecta a ninguna DB real** (NVD, Shodan, Vulners).
Genera código placeholder que no ejecuta búsqueda real.

#### 7. ROP Chains / Gadget Finding
No existe nada relacionado con:
- `busca gadgets en "binary"`
- `construye rop chain con [pop_rdi, ret, main]`

#### 8. Post-Exploitation / Lateral Movement
No hay keywords para:
- Process injection
- Privilege escalation checks
- Persistence mechanisms
- C2 communication

#### 9. TLS/SSL Inspection
No hay syntax para:
- Certificate inspection
- MITM primitives
- SSL stripping
- HSTS bypass detection

#### 10. Concurrencia General en Hado
```hado
// Lo que NO existe:
ejecuta en paralelo
  escanea "host1" en ports [80]
  escanea "host2" en ports [80]
```
La única concurrencia es automática en el **Go backend** para `escanea`.
El Python backend es secuencial para todo.

---

## Estado real por backend

### Python ✅ Funcional Completo

El backend más maduro. Delega a módulos cybersec Python reales.

```hado
// Todo esto funciona y ejecuta código real:
scan    = escanea target "192.168.1.1" en ports [22, 80, 443, 3306]
subs    = busca subdomains de "target.com"
headers = analiza headers de "https://target.com"
         ataca "http-post" en "https://login.target.com" con wordlist "pass.txt"
         genera reporte con scan, subs, headers -> guarda "report.md"
```

### Go ✅ Funcional — Solo Port Scan

El Go backend genera código compilable real **exclusivamente para `escanea`**. Todos los demás constructs cybersec generan comentarios `// TODO`.

```go
// ✅ Genera esto — compila y escanea 10x más rápido que Python:
func hado_scan(target string, ports []int) []int {
    var wg sync.WaitGroup
    // goroutines reales con net.DialTimeout
}

// ❌ Esto genera TODO:
// analiza headers de "https://example.com"
// busca subdomains de "target.com"
```

**Gap principal:** El Go compilado no tiene acceso a los módulos Python cybersec. Para un scanner standalone que va a producción, Go es la respuesta. Para un assessment completo, Python.

### C ✅ Funcional — Solo Port Scan

Genera `hado_scan_port()` con POSIX sockets reales. HTTP es comentado con hints para libcurl. Útil para:
- Herramientas de pentesting embebidas
- Shellcode runners (requiere agregar manualmente)
- Módulos de kernel (requiere código adicional)

```c
// ✅ Genera código real con gcc/clang:
int hado_scan_port(const char *host, int port) {
    struct sockaddr_in addr;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    // ...
}
```

**Limitación real:** El type system es simplificado — todos los tipos complejos son `void*`. Para exploit C real, el código generado necesita refactoring manual.

### Rust ⚠️ Parcial — Scan + Recon básico

Más completo que C para cybersec: tiene `CyberScan` (TcpStream) y `CyberRecon` (to_socket_addrs). HTTP requiere `reqwest` (dep externa). `CyberAttack` y `CyberCapture` → `// TODO`.

---

## Hado como orquestador vs. como herramienta

La distinción más importante:

```
❌ Lo que Hado NO es:
   pwntools, Metasploit, Scapy, ROPgadget

✅ Lo que Hado SÍ es:
   Un lenguaje de scripting para security workflows
   con verbos claros y generación de código multi-target
```

### El flujo correcto para zero-day research con Hado:

```
Fase 1: Recon      → Hado nativo (subdomain enum, port scan, header analysis)
Fase 2: Analysis   → Hado nativo (port risk scoring, report generation)
Fase 3: Exploit    → Python/pwntools/scapy FUERA de Hado
Fase 4: Post-expl  → Python/Metasploit FUERA de Hado
Fase 5: Report     → Hado nativo (genera reporte con todos los resultados)
```

---

## Módulos cybersec — Mapa de dependencias

```
hado.cybersec.scanner  → nmap (opcional) | socket (stdlib) ✅
hado.cybersec.recon    → socket (stdlib) | dig subprocess ✅
hado.cybersec.analysis → requests (opcional) | funciona sin red con dict ✅
hado.cybersec.attack   → requests (stdlib) | paramiko (opcional) | ftplib (stdlib) ✅
hado.cybersec.fuzzer   → requests (opcional) + ThreadPoolExecutor (stdlib) ✅
hado.cybersec.crypto   → hashlib + base64 + hmac + secrets (stdlib) ✅ ZERO deps
hado.cybersec.report   → json + datetime (stdlib) ✅ ZERO deps
hado.cybersec.capture  → scapy (opcional) | tcpdump subprocess ⚠️ requiere root
```

**La buena noticia:** 7 de 8 módulos funcionan sin instalar nada extra.

---

## Roadmap para cerrar las gaps

### Fase 5 (próxima — Rust backend completo)
- Implementar `CyberAttack` en Rust (brute force nativo)
- Implementar `CyberCapture` en Rust (usando `libpcap` bindings)
- Objetivo: Rust compilado con scan + recon + brute force sin deps externas

### Fase 6 (C backend completo)
- Implementar HTTP con libcurl real (no comentarios)
- Type system más robusto (no todo `void*`)
- Objetivo: C que compile con gcc sin modificaciones manuales

### Fase 7 (keywords faltantes — v0.7)
- `hashea texto con sha256` → sintaxis nativa para crypto
- `fuzzea url con wordlist` → sintaxis nativa para fuzzing
- `ejecuta en paralelo` → concurrencia general en Python

### Fase 8 — Para acercarse a zero-day tooling real
- `envía packet tcp con flags [SYN]` → integración con scapy
- `lee elf "binary"` → integración con pyelftools
- `busca vulns en target` → integración con NVD API / Shodan

---

## Tests de referencia

El estado documentado arriba está verificado por `tests/test_capabilities.py` (56 tests, 0 failures).

```bash
python -m pytest tests/test_capabilities.py -v
# 56 passed — cobertura completa de capacidades y limitaciones
```

Para re-auditar después de cada fase:
```bash
python -m pytest tests/test_capabilities.py tests/test_go_backend.py tests/test_cybersec.py -v
```

---

*Generado con [Hado DSL](https://github.com/chrisz-toledo/hado)*
