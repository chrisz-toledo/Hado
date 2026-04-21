# Hado

**Un DSL de ciberseguridad diseñado para generación de código con IA. Verbos en español. Sustantivos en inglés. Cero boilerplate.**

```hado
// 3 líneas. Sin imports. Output real.
scan    = escanea target "192.168.1.1" en ports [80, 443, 22, 3306]
headers = analiza headers de "https://example.com"
genera reporte con scan, headers
```

> **Estado: v0.5 — Python ✅ funcional · Go ✅ funcional · Rust ✅ funcional · C ⚠️ alpha**
> 474 tests · [Roadmap](docs/roadmap.md)

⚠️ *Advertencia: Los backends Go y Rust han sido completados y verificados mediante análisis automatizado, pero aún requieren validación manual en la terminal local del autor.*

---

## Prueba real: esto funciona en producción

El script anterior fue ejecutado contra un servidor de producción real el 2026-04-12. Output:

```
[1/3] Escaneando puertos...
{'target': '[redacted]', 'open_ports': [21, 22, 80, 443, 3306], 'method': 'nmap'}

[2/3] Analizando headers de seguridad HTTP...
{'grade': 'F', 'security_score': 0, 'missing_headers': [9 headers]}

[3/3] Generando reporte...
```

3 líneas de Hado. Cero `import` escritos por el usuario. Scan nmap real. Análisis de headers HTTP real. Reporte JSON real.

→ [Evidencia completa](docs/evidence/v0.2-proof-of-concept.md)

---

## ¿Qué es Hado?

Hado es un lenguaje de dominio específico para ciberseguridad que transpila a **Python, Go, C y Rust**. Está diseñado para que los LLMs (Claude, GPT, Gemini) puedan escribir código de ciberseguridad de forma más eficiente, más económica y con menos errores.

El usuario escribe 12 tokens en Hado — el transpiler genera 45+ tokens de código ejecutable con imports, manejo de errores y boilerplate incluido.

Hado no compite con Python como lenguaje de propósito general. Es un **DSL multi-target**: el mismo código Hado compila a Python para prototipado rápido, Go para scanners concurrentes con goroutines, Rust para herramientas memory-safe, y C para exploits y trabajo a nivel de kernel.

### Estado de los backends

| Target | Estado | Versión | Caso de uso |
|--------|--------|---------|-------------|
| Python | ✅ **Funcional** | 0.5 | Scripting, OSINT, prototipado rápido |
| Go     | ✅ **Funcional** | 1.0 | Scanners concurrentes, binarios standalone |
| Rust   | ✅ **Funcional** | 0.5 | Herramientas memory-safe, fuzzing, parsers |
| C      | ⚠️ **Alpha**     | 0.1 | Exploits, shellcode, módulos de kernel |

**Go v1.0**: `escanea` genera goroutines reales con `sync.WaitGroup` + `net.DialTimeout`. Solo stdlib — cero dependencias externas.

---

## Por qué Hado

El problema: los LLMs desperdician tokens en boilerplate.

```python
# Python: 47 tokens para escanear un host
import socket
results = {}
for port in [22, 80, 443]:
    s = socket.socket()
    s.settimeout(1)
    results[port] = s.connect_ex(("192.168.1.1", port)) == 0
    s.close()
```

```hado
# Hado: 8 tokens
escanea target "192.168.1.1" en ports [22, 80, 443]
```

La solución: un lenguaje donde cada token lleva el máximo significado semántico. Sin imports, sin ceremonia, sin boilerplate.

---

## Quick Start

```bash
git clone https://github.com/chrisz-toledo/hado.git
cd hado
pip install -e .
```

Crea `hello.ho`:
```hado
muestra "Hola mundo desde Hado!"

nombre = "Christian"
muestra "Bienvenido, " + nombre
```

Ejecuta:
```bash
hado run hello.ho
```

Ver código generado:
```bash
hado compile hello.ho                  # Python (default)
hado compile --target go hello.ho      # Go
hado compile --target c hello.ho       # C
hado compile --target rust hello.ho    # Rust
hado targets                           # Lista todos los backends
```

---

## Resumen del lenguaje

### 1. Cero boilerplate
Sin imports, sin requires, sin decoradores. El transpiler resuelve las dependencias por contexto.

```hado
// Sin imports — el transpiler los inyecta automáticamente
datos = desde "https://api.github.com/repos/chrisz-toledo/hado"
muestra datos
```

### 2. Verbos españoles como operadores
```hado
muestra "resultado"              // print
filtra donde x > 0               // filter
escanea target en ports [...]    // port scan
busca subdomains de "dom"        // subdomain recon
captura packets en "eth0"        // packet capture
analiza headers de "url"         // security header analysis
genera reporte con datos         // report generation
```

### 3. Pipes conectan todo
```hado
"target.com" -> busca subdomains -> filtra alive -> escanea ports [80, 443] -> genera reporte
```

### 4. Tipos implícitos
```hado
nombre = "Carlos"      // str
edad   = 25            // int
activo = cierto        // bool (true)
datos  = desde "url"   // dict (HTTP JSON)
ports  = [22, 80, 443] // list
```

### 5. Bloques por indentación
```hado
si edad >= 18
  muestra "adulto"
sino
  muestra "menor"
```

### 6. Sustantivos técnicos en inglés
Los términos de ciberseguridad se mantienen en inglés (CVEs, protocolos, herramientas siempre son en inglés):
```hado
// Verbos españoles + sustantivos ingleses
escanea target "192.168.1.1" en ports [22, 80, 443]
busca subdomains de "example.com"
captura packets en interface "eth0"
ataca "ssh" en target con wordlist "rockyou.txt"
```

### 7. Cuatro targets de compilación
```bash
hado compile script.ho                # Python (default)
hado compile --target go script.ho    # Go  (go build)
hado compile --target c script.ho     # C   (gcc/clang)
hado compile --target rust script.ho  # Rust (rustc/cargo)
hado run script.ho                    # Ejecutar via Python
hado targets                          # Lista backends y estado
```

---

## Ejemplos de ciberseguridad

### Pipeline de recon
```hado
dominio = "target.com"

// Subdominios vivos
subs = busca subdomains de dominio

// Escaneo de puertos en cada subdominio
para cada sub en subs
  escanea sub en ports [80, 443, 8080, 8443]

// Reporte final
genera reporte con subs -> guarda "recon-report.md"
```

### Análisis de seguridad web
```hado
url = "https://example.com"
analiza headers de url
```

Verifica los 9 headers de seguridad (HSTS, CSP, X-Frame-Options, etc.) y retorna una calificación A–F.

### Brute force (solo entornos autorizados)
```hado
// Solo usar en sistemas propios o con permiso explícito
ataca "ssh" en "192.168.1.100" con wordlist "rockyou.txt"
```

### Assessment OSINT completo
```hado
fn osint(objetivo)
  muestra "=== OSINT: " + objetivo + " ==="

  subs = busca subdomains de objetivo
  muestra "Subdominios: " + cuenta subs

  para cada sub en subs
    escanea sub en ports [22, 80, 443, 3306, 5432, 8080]

  busca vulns en subs
  genera reporte con subs -> guarda objetivo + "-osint.md"

osint("target.com")
```

### Lo mismo en Go — concurrencia automática
```bash
hado compile --target go assessment.ho
go build assessment.go
./assessment
```

El backend Go genera `hado_scan()` con goroutines y `sync.WaitGroup`. El mismo código Hado que en Python escanea en secuencia, en Go escanea todos los puertos en paralelo automáticamente.

---

## Diseño ASCII-first

Hado resuelve tres problemas con las tildes españolas en programación:

1. **Accesibilidad de teclado** — ñ, á, é no existen en la mayoría de teclados
2. **Costo de tokenización para LLMs** — las tildes se tokenizan como 2–3 tokens en lugar de 1
3. **Errores de generación de LLMs** — los LLMs frecuentemente omiten tildes

**Solución**: los keywords siempre son ASCII. El normalizador maneja los identificadores del usuario de forma transparente.

| Con tilde | Forma ASCII | Ambas son válidas |
|-----------|------------|-------------------|
| `año`     | `anho` o `anio` | ✓ |
| `función` | `funcion` | ✓ |
| `también` | `tambien` | ✓ |

Los string literals **nunca** se normalizan — `muestra "Año nuevo"` preserva el string exactamente.

---

## Para desarrolladores LLM

Usa este system prompt para habilitar la generación de Hado en tu aplicación de IA:

```
Eres un experto en Hado, un DSL de ciberseguridad que transpila a Python, Go, C y Rust.

Reglas para generar código Hado:
- Verbos españoles para acciones: muestra, filtra, escanea, busca, captura, ataca, analiza, genera
- Sustantivos ingleses para términos técnicos: target, port, host, payload, vuln, packet, interface, header
- -> para pipes: datos -> filtra donde x > 0 -> guarda "out.txt"
- Sin imports, sin llaves, sin async/await, sin type annotations
- Bloques por indentación (2 espacios o 1 tab)
- Solo ASCII: sin tildes (á,é,í,ó,ú), sin ñ, sin ¿ o ¡
- Booleanos: cierto/falso. Lógica: y/o/no. Null: nulo
- Mínimo: cada token debe llevar significado
```

Ver [docs/llm-guide.md](docs/llm-guide.md) para la guía completa con todos los keywords, patrones comunes y anti-patrones.

---

## Arquitectura

```
┌─────────────┐
│  .ho file   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Normalizer │  ñ→nh, á→a, ¿→(removed)  (ASCII-only)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│    Lexer    │  tokens: KEYWORD, IDENT, NUMBER, STRING, PIPE, INDENT/DEDENT
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Parser    │  recursive descent → AST compartido
└──────┬──────┘
       │
       ├──────────────┬──────────────┬──────────────┐
       ▼              ▼              ▼              ▼
┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐
│  Python   │  │    Go     │  │   Rust    │  │     C     │
│ ✅ v0.5   │  │ ✅ v1.0   │  │ ✅ v0.5   │  │ ⚠️ v0.1   │
└─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
      │               │              │               │
      ▼               ▼              ▼               ▼
   .py file        .go file       .c file        .rs file
  (exec'd)       (go build)    (gcc/clang)   (rustc/cargo)
```

---

## Roadmap

| Fase | Versión | Estado | Enfoque |
|------|---------|--------|---------|
| 1 | v0.1 | ✅ Completa | Core compiler, Python backend |
| 2 | v0.2 | ✅ Completa | Lexer/parser robusto, módulos cybersec reales |
| 3 | v0.3 | ✅ Completa | Python backend completo (100% features) |
| 4 | v0.4 | ✅ Completa*| Go backend funcional — goroutines, stdlib |
| 5 | v0.5 | ✅ Completa*| Rust backend funcional — memory safety, tokio |
| 6 | v0.6 | ⚠️ Alpha    | C backend — libpcap, raw sockets (en progreso) |

*\*Nota: Completadas a nivel de código y tests automatizados, pendientes de validación manual en terminal local.*
| 7 | v0.7 | ⏳ | Módulos, multi-return, error handling |
| 8 | v0.8 | ⏳ | Tooling: compile, check, fmt, VS Code extension |
| — | v1.0 | ⏳ | Todos los backends + 300+ tests + ecosistema |

Ver [docs/roadmap.md](docs/roadmap.md) para los prompts de trabajo y verificación de cada fase.

---

## Contribuir

Ver [CONTRIBUTING.md](CONTRIBUTING.md).

**Regla de doc-sync**: toda PR que modifique el compilador, el AST o un backend debe actualizar el README, spec.md y roadmap.md en el mismo commit. La documentación desactualizada es un bug.

---

## Licencia

MIT — ver [LICENSE](LICENSE).

---

*Construido con [Hado DSL](https://github.com/chrisz-toledo/hado)*
