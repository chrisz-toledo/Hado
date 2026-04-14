# Hado — Roadmap de Desarrollo

> Estructurado con la filosofía de **Thinking in Systems** (Donella Meadows).  
> Cada fase tiene un prompt de trabajo, un prompt de verificación, y condiciones de rechazo.  
> **Regla de oro: no avanzar de fase hasta que la verificación pase al 100%.**

---

## Análisis del Sistema Hado

Antes de construir, entender lo que se está construyendo como sistema.

### Stocks (lo que se acumula)
| Stock | Estado actual | Objetivo v1.0 |
|---|---|---|
| AST node types | ~35 nodos | ~50 nodos |
| Backend implementations | 1 real (Python), 3 stubs | 4 reales |
| Test coverage | 117 tests | 400+ tests |
| Módulos cybersec | 5 (scanner, analysis, report, crypto, recon) | 12+ |
| Keywords del lenguaje | 40 | ~55 |
| Ejemplos funcionales | 7 | 20+ |

### Flows (qué cambia los stocks)
- **Flow entrante**: Nueva keyword → nueva regla de parser → nuevo nodo AST → nuevo visitor en CADA backend
- **Flow saliente**: Features removidas, keywords deprecadas, sintaxis simplificada
- **Delay crítico**: Agregar algo al backend Python tarda 1 hora. Propagarlo a Go/Rust/C tarda 4-8 horas cada uno.

### Feedback Loops

```
[Bug encontrado] ──→ [Test nuevo] ──→ [Fix] ──→ [117+ tests] ──→ [Estabilidad]
                          ↑___________________________________|
                          (loop balanceador — evita regresiones)

[Más features Python] ──→ [Más casos de uso] ──→ [Más tests] ──→ [Mejor AST]
        ↑______________________________________________|
        (loop reforzador — el AST mejora con el uso)

[Más backends] ──→ [Más usuarios] ──→ [Más bugs reportados] ──→ [Mejor compilador]
        ↑_____________________________________________________________|
        (loop reforzador — la comunidad mejora el lenguaje)
```

### Leverage Points (dónde un cambio pequeño tiene impacto grande)
1. **El AST** — cualquier nodo nuevo se propaga a todos los backends automáticamente (máximo leverage)
2. **`_TOKEN_PATTERNS` + `KEYWORDS`** — cambiar aquí afecta todo el lenguaje
3. **La arquitectura de `_HELPER_IMPORTS`** — determina qué tan limpio es el zero-boilerplate
4. **El test suite** — 1 test bien escrito previene 10 bugs futuros

### Principio de Resiliencia
La arquitectura `AST → múltiples backends` es inherentemente resiliente: si un backend falla, los otros siguen funcionando. El AST es el buffer entre el lenguaje y los targets.

---

## Estado Actual: v0.2 ✅

**Lo que funciona en producción (verificado 2026-04-12):**
- Lexer completo: `#` comments, `|` pipes, todos los tokens
- Parser: todos los verbos cyber, comma-args, `escanea ports de target`
- Python backend: `scanner.py`, `analysis.py`, `report.py`, `crypto.py`, `recon.py`
- Pipe chains en nivel de statement (`busca X | filtra Y | muestra`)
- `genera report con a, b, c` (multi-arg)
- 117/117 tests pasando

**Lo que aún son stubs:**
- Go backend: genera código placeholder no compilable
- Rust backend: genera código placeholder no compilable
- C backend: genera código placeholder no compilable
- `captura packets` (en Python): lógica real falta
- `ataca` (brute force): lógica real falta
- `enumera directories` (fuzzer): keyword no existe aún

---

## Fase 3 — Python Backend Completo (v0.3)

> **Filosofía de sistemas**: Antes de construir más backends, maximizar el stock del backend Python. Un backend al 100% es más valioso que 4 backends al 25%.

### ¿Qué falta en Python?

| Módulo | Estado | Implementación real necesaria |
|---|---|---|
| `scanner.py` | ✅ Real | nmap + socket — DONE |
| `analysis.py` | ✅ Real | requests + header scoring — DONE |
| `report.py` | ✅ Real | markdown/html/json/text — DONE |
| `crypto.py` | ✅ Real | hashlib + hmac — DONE |
| `recon.py` | ⚠️ Parcial | subdomain enum básico (dns lookup) |
| `capture.py` | ❌ Stub | Necesita scapy: `sniff(filter="tcp port 80")` |
| `attack.py` | ❌ Stub | Necesita paramiko + ftplib para brute force |
| `fuzzer.py` | ❌ No existe | Necesita keyword `enumera` + requests async |
| `exploit.py` | ❌ No existe | Framework básico — Fase 5 (C backend) |

---

### PROMPT DE TRABAJO — Fase 3

```
Proyecto: Hado DSL (github.com/chrisz-toledo/hado)
Tarea: Completar el backend Python con implementaciones reales para los módulos faltantes.

MÓDULO 1: src/hado/cybersec/capture.py
- Implementar capture(interface, filter_expr, count) usando scapy
- Si scapy no está disponible, fallback a socket raw (requiere root)
- Retornar lista de dicts con: src_ip, dst_ip, protocol, port, payload_preview
- El verb en Hado es: captura packets en interface "eth0" donde port == 443

MÓDULO 2: src/hado/cybersec/attack.py
- Implementar brute_force(service, target, wordlist, username) 
- Soportar services: "ssh", "ftp", "http-basic", "http-form"
- SSH via paramiko, FTP via ftplib, HTTP via requests
- Retornar dict con: service, target, found, credentials (si encontró), attempts
- El verb en Hado es: ataca ssh en target con wordlist y username

MÓDULO 3: src/hado/cybersec/fuzzer.py
- Implementar fuzz(target, wordlist, method, threads) usando requests + ThreadPoolExecutor
- Descubrir directorios/endpoints con respuesta 200/301/302/403
- El verb en Hado es: enumera directories en target (NUEVO — agregar al parser)
- Retornar dict con: target, found_paths, status_codes, total_requests

MÓDULO 4: Mejorar src/hado/cybersec/recon.py
- Agregar email_harvest(domain) usando requests a Hunter.io o búsqueda directa
- Agregar whois_lookup(domain) usando python-whois
- Agregar dns_records(domain) para A, MX, TXT, NS

MÓDULO 5: Agregar keyword "enumera" al parser
- En lexer: agregar "enumera" a KEYWORDS
- En parser: parse_enumera() que maneje "enumera directories en target"
- En transpiler: _visit_Enumerate() que genere _hado_fuzz(target)
- En ast_nodes: class Enumerate(Node)

REGLAS:
- Cero stubs. Si una librería externa no está disponible, graceful degradation con mensaje claro.
- Cada módulo necesita tests en tests/test_cybersec.py
- No romper los 117 tests existentes
- Al terminar: python -m pytest tests/ debe mostrar 130+ tests passing
```

### PROMPT DE VERIFICACIÓN — Fase 3

```
Tengo el código de Hado v0.3 listo. Antes de marcar la fase como completa, 
ejecuta estas verificaciones en orden. Si alguna falla, reporta el error exacto 
y NO avances a la siguiente fase.

VERIFICACION 1 — Tests no regresionaron:
  Comando: python -m pytest tests/ -v
  Criterio: >= 130 tests, 0 failures
  Si falla: git diff HEAD~1 -- tests/ y reportar qué se rompió

VERIFICACION 2 — capture.py no es stub:
  Comando: python -c "from hado.cybersec.capture import capture; import inspect; 
  src = inspect.getsource(capture); assert len(src.split('\n')) > 20, 'ES STUB'"
  Criterio: pasa sin AssertionError

VERIFICACION 3 — attack.py soporta SSH:
  Comando: python -c "from hado.cybersec.attack import brute_force; 
  result = brute_force('ssh', '127.0.0.1', ['wrong1','wrong2'], 'nobody');
  assert 'found' in result and 'attempts' in result"
  Criterio: pasa sin error (no necesita encontrar credenciales, solo ejecutar)

VERIFICACION 4 — fuzzer.py existe y es callable:
  Comando: python -c "from hado.cybersec.fuzzer import fuzz; 
  r = fuzz('http://example.com', ['index','admin','api'], threads=2);
  assert 'found_paths' in r and 'total_requests' in r"
  Criterio: pasa sin error

VERIFICACION 5 — keyword "enumera" funciona:
  Comando: python -c "from hado import compile_to_source;
  out = compile_to_source('enumera directories en objetivo', target='python');
  assert '_hado_fuzz' in out or 'fuzz' in out, 'No genera código de fuzzing'"
  Criterio: pasa sin AssertionError

VERIFICACION 6 — Scan real en localhost:
  Comando: hado run examples/test-local.ho
  Criterio: output contiene 'open_ports' y 'method' sin errores

CONDICION DE RECHAZO: Si cualquier verificación falla → 
  NO avanzar a Fase 4. Reportar el error específico y seguir trabajando.
```

---

## Fase 4 — Go Backend Real (v0.4)

> **Filosofía de sistemas**: El backend Go no es una copia del Python. Tiene un modelo mental diferente (concurrencia, canales, goroutines). Diseñarlo para ese modelo, no para simular Python.

### Por qué Go para Hado

| Python | Go |
|---|---|
| Scripts de recon, prototyping | Scanners de alta velocidad |
| Análisis de headers | Port scanners concurrentes (1000+ ports/seg) |
| OSINT | Binarios standalone para deploy |
| Scapy para packet capture | Concurrencia nativa sin threading overhead |

### Qué debe generar `escanea target en ports [22, 80, 443]` en Go:

```go
package main

import (
    "fmt"
    "net"
    "sync"
    "time"
)

func hadoScannear(target string, ports []int) map[int]bool {
    results := make(map[int]bool)
    var mu sync.Mutex
    var wg sync.WaitGroup

    for _, port := range ports {
        wg.Add(1)
        go func(p int) {
            defer wg.Done()
            addr := fmt.Sprintf("%s:%d", target, p)
            conn, err := net.DialTimeout("tcp", addr, time.Second)
            open := err == nil
            if conn != nil { conn.Close() }
            mu.Lock()
            results[p] = open
            mu.Unlock()
        }(port)
    }
    wg.Wait()
    return results
}
```

### PROMPT DE TRABAJO — Fase 4

```
Proyecto: Hado DSL (github.com/chrisz-toledo/hado)
Tarea: Implementar el backend Go con código Go real y compilable.

ARCHIVO: src/hado/backends/go_transpiler.py

El transpiler debe generar código Go que:
1. COMPILA con `go build` sin errores
2. Usa goroutines para concurrencia donde sea apropiado
3. Genera un main() funcional
4. Resuelve imports automáticamente (fmt, net, sync, os, encoding/json)

FUNCIONES A IMPLEMENTAR EN GO:

1. escanea target en ports [X, Y, Z]
   → Generar función con goroutines + sync.WaitGroup + net.DialTimeout
   → Retornar map[int]bool de resultados

2. busca subdomains de "domain"
   → Generar función con net.LookupHost para cada posible subdominio
   → Lista de subdominios comunes hardcodeada (www, mail, ftp, api, dev, staging)
   → Retornar []string de subdominios activos

3. analiza headers de "target"
   → Generar función con net/http GET request
   → Verificar los 9 security headers
   → Retornar struct con grade y missing headers

4. genera reporte con datos
   → Generar código que marshala a JSON con encoding/json
   → Escribir a archivo report.json

5. muestra X
   → fmt.Println(X)

6. Variables, asignaciones, if/else, para/while
   → Sintaxis Go correcta (`:=` para primera asignación, `=` para reasignación)
   → if sin paréntesis, llaves obligatorias
   → for range para loops

ESTRUCTURA del archivo generado:
```go
package main

import (
    "encoding/json"
    "fmt"
    "net"
    // ... solo imports necesarios, auto-detectados
)

// [funciones helper]

func main() {
    // [código transpilado]
}
```

REGLAS:
- El código generado DEBE compilar: go build -o /tmp/hado_test_go el_archivo.go
- Tests: agregar tests/test_go_backend.py que compilen y ejecuten el código generado
- No usar librerías externas en el código Go (solo stdlib) para que funcione sin go mod
- Al terminar: 15+ tests Go pasando
```

### PROMPT DE VERIFICACIÓN — Fase 4

```
Verificación del Go backend de Hado v0.4.
Ejecutar en orden, no avanzar si alguno falla.

VERIFICACION 1 — Tests no regresionaron:
  python -m pytest tests/ -q
  Criterio: 0 failures (todo lo que pasaba antes sigue pasando)

VERIFICACION 2 — Go genera código compilable:
  python -c "
  from hado import compile_to_source
  code = '''
  target = \"127.0.0.1\"
  scan = escanea target en ports [80, 443]
  muestra scan
  '''
  go_code = compile_to_source(code, target='go')
  with open('/tmp/test_hado.go', 'w') as f:
      f.write(go_code)
  "
  go build -o /tmp/hado_test /tmp/test_hado.go
  Criterio: go build termina sin errores

VERIFICACION 3 — Go ejecuta y produce output:
  /tmp/hado_test
  Criterio: output contiene información de puertos sin panic ni error

VERIFICACION 4 — Goroutines están presentes:
  grep -c "go func\|goroutine\|sync.WaitGroup" /tmp/test_hado.go
  Criterio: >= 1 (el scanner usa concurrencia real)

VERIFICACION 5 — Tests específicos de Go:
  python -m pytest tests/test_go_backend.py -v
  Criterio: >= 15 tests passing

CONDICION DE RECHAZO: go build falla = backend no es real = no avanzar.
```

---

## Fase 5 — Rust Backend Real (v0.5)

> **Filosofía de sistemas**: Rust tiene el feedback loop más fuerte de todos: el compilador rechaza código inseguro. Usar ese loop como ventaja — si el Hado-generado compila en Rust, es memory-safe por definición.

### Qué debe generar en Rust

```rust
use std::net::TcpStream;
use std::time::Duration;

fn hado_scan(target: &str, ports: &[u16]) -> Vec<(u16, bool)> {
    ports.iter().map(|&port| {
        let addr = format!("{}:{}", target, port);
        let open = TcpStream::connect_timeout(
            &addr.parse().unwrap(),
            Duration::from_secs(1)
        ).is_ok();
        (port, open)
    }).collect()
}
```

### PROMPT DE TRABAJO — Fase 5

```
Proyecto: Hado DSL (github.com/chrisz-toledo/hado)
Tarea: Implementar el backend Rust con código Rust real que compile con rustc.

ARCHIVO: src/hado/backends/rust_transpiler.py

REGLAS CRÍTICAS para Rust:
1. El código generado DEBE compilar: rustc archivo.rs -o /tmp/hado_rust_test
2. Manejo de errores con Result<T, Box<dyn std::error::Error>>
3. No usar unsafe{} a menos que sea absolutamente necesario
4. Usar iteradores y closures idiomáticos de Rust
5. Variables inmutables por defecto (let), mutables solo cuando sea necesario (let mut)

FUNCIONES A IMPLEMENTAR:

1. escanea target en ports [X, Y]
   → std::net::TcpStream::connect_timeout()
   → Vec<(u16, bool)> como resultado

2. muestra X
   → println!("{:?}", x)

3. Variables y tipos
   → Inferencia de tipos en let/let mut
   → String vs &str manejo correcto

4. Loops (para X en Y)
   → for x in y.iter() {}

5. genera reporte con datos
   → serde_json si disponible, manual JSON serialization si no
   → Escribir a archivo con std::fs::write()

GENERAR también un Cargo.toml mínimo cuando se usen dependencias externas.

Al terminar: rustc debe compilar el output de al menos 10 programas Hado.
```

### PROMPT DE VERIFICACIÓN — Fase 5

```
VERIFICACION 1 — No regresiones: python -m pytest tests/ -q → 0 failures
VERIFICACION 2 — Rust compila:
  hado compile mcguire.ho --target rust -o /tmp/test.rs
  rustc /tmp/test.rs -o /tmp/hado_rust_bin
  Criterio: rustc termina sin error (warnings OK, errors NO)
VERIFICACION 3 — Output correcto:
  /tmp/hado_rust_bin
  Criterio: produce output sin panic
VERIFICACION 4 — Sin unsafe:
  grep -c "unsafe" /tmp/test.rs
  Criterio: 0
CONDICION DE RECHAZO: rustc error = no avanzar.
```

---

## Fase 6 — C Backend Real (v0.6)

> **Filosofía de sistemas**: C es el backend más cercano al metal. Tiene el delay más alto (más difícil de generar correctamente) pero el leverage más alto para exploits y kernel work. Diseñar para seguridad primero — malloc/free explícitos, no buffer overflows en el código generado.

### PROMPT DE TRABAJO — Fase 6

```
Proyecto: Hado DSL (github.com/chrisz-toledo/hado)
Tarea: Implementar el backend C que genere código compilable con gcc/clang.

FUNCIONES CRÍTICAS:

1. escanea target en ports [X, Y]
   → sys/socket.h + connect() con timeout via SO_RCVTIMEO
   → Struct para resultados: typedef struct { int port; int open; } PortResult;

2. captura packets en interface "eth0"
   → libpcap: pcap_open_live() + pcap_loop()
   → Generar Makefile que enlaza con -lpcap

3. genera reporte con datos
   → fprintf() a archivo JSON manual (sin dependencias)

REGLAS:
- gcc -Wall -o /tmp/hado_c_test el_archivo.c → 0 errors (warnings permitidos)
- No buffer overflows en el código generado (usar snprintf no sprintf)
- strncpy no strcpy
- Verificar malloc != NULL antes de usar
- Generar Makefile automáticamente cuando se necesiten librerías externas
```

### PROMPT DE VERIFICACIÓN — Fase 6

```
VERIFICACION 1 — No regresiones: python -m pytest tests/ -q → 0 failures
VERIFICACION 2 — C compila: 
  hado compile examples/01-escaneo-basico.ho --target c -o /tmp/test.c
  gcc -Wall /tmp/test.c -o /tmp/hado_c_bin
  Criterio: gcc termina sin error
VERIFICACION 3 — No buffer overflows obvios:
  grep -c "sprintf[^n]" /tmp/test.c  → 0
  grep -c "strcpy[^n]" /tmp/test.c   → 0
CONDICION DE RECHAZO: gcc error = no avanzar.
```

---

## Fase 7 — Sistema de Módulos y Funciones Avanzadas (v0.7)

> **El leverage point más alto después del AST**: un sistema de módulos permite que la comunidad extienda el lenguaje sin tocar el compilador.

### Features a implementar

```hado
# Importar módulos .ho entre sí
importa "mi_scanner.ho" como scanner

# Funciones con tipos implícitos
fn escaneo_completo(objetivo, puertos)
    scan = escanea objetivo en ports puertos
    headers = analiza headers de objetivo
    devuelve scan, headers

# Error handling
intenta
    resultado = escanea ports de target_externo
atrapa error
    muestra "Error de red: " + error

# Listas y dicts literales ya funcionan — mejorar acceso
datos["key"]
lista[0]
```

### PROMPT DE TRABAJO — Fase 7

```
Tarea: Implementar sistema de módulos y mejoras de funciones en Hado v0.7.

FEATURE 1: importa "archivo.ho" como alias
  - En lexer: agregar "importa" a KEYWORDS
  - En parser: parse_importa() → ImportStatement(path, alias)
  - En transpiler Python: ejecutar compile_to_source en el archivo importado
    e incluir las funciones como módulo
  - Verificar: importa "utils.ho" como utils; utils.mi_funcion()

FEATURE 2: Mejorar manejo de errors (lanza/atrapa ya existen en keywords)
  - Parser: parse_try_catch() para el bloque intenta/atrapa
  - AST: TryStatement(body, error_var, handler)
  - Transpiler Python: try/except Exception as {error_var}:
  - Verificar: intenta → atrapa error → muestra error funciona

FEATURE 3: Funciones con múltiples return values
  - fn f(a, b) → devuelve a, b → Python: return a, b
  - x, y = f(1, 2) → Python: x, y = f(1, 2)
  - Agregar TupleDestructuring a parser

FEATURE 4: Acceso a dict/lista
  - datos["key"] → ya funciona? verificar
  - lista[0] → ya funciona? verificar
  - datos.key (dot notation) → agregar si no existe

VERIFICACION: 150+ tests passing, todos los ejemplos compilan
```

---

## Fase 8 — Tooling y Ecosistema (v0.8)

> **Última fase antes de v1.0**: herramientas que hacen el lenguaje usable para humanos (aunque el target principal sea LLMs).

### PROMPT DE TRABAJO — Fase 8

```
Tarea: Implementar tooling básico para Hado v0.8.

TOOL 1: hado compile --target [python|go|rust|c]
  - Ya existe? Verificar CLI: hado --help
  - Si no: agregar subcomando compile a src/hado/cli.py
  - Output: archivo .py/.go/.rs/.c en el directorio actual

TOOL 2: hado check archivo.ho
  - Verificar sintaxis sin ejecutar
  - Output: "OK" o lista de errores con línea y columna
  - Útil para linters y pre-commit hooks

TOOL 3: hado fmt archivo.ho
  - Auto-formateador: indentación consistente, espacios alrededor de operadores
  - Similiar a gofmt / rustfmt

TOOL 4: syntax highlighting
  - Archivo .ho.tmLanguage para VS Code
  - Keywords en un color, strings en otro, comentarios en otro
  - Publicar como extension básica

VERIFICACION:
  hado compile mcguire.ho --target go → genera archivo .go que compila
  hado check bad_syntax.ho → lista errores
  hado fmt messy.ho → archivo formateado sin cambios semánticos
```

---

## Condición Final para v1.0

Hado es v1.0 cuando pasan TODAS estas verificaciones en CI/CD:

```bash
# Test suite completo
python -m pytest tests/ -q --tb=short
# Criterio: >= 300 tests, 0 failures

# Todos los backends compilan
hado compile examples/01-escaneo-basico.ho --target python && python out.py
hado compile examples/01-escaneo-basico.ho --target go    && go build out.go
hado compile examples/01-escaneo-basico.ho --target rust  && rustc out.rs
hado compile examples/01-escaneo-basico.ho --target c     && gcc out.c
# Criterio: todos compilan sin error

# Zero boilerplate verificado
hado compile examples/01-escaneo-basico.ho --target python
grep -c "^import\|^from" out.py  # Hado lo genera, el usuario no lo escribe
# Criterio: > 0 imports generados automáticamente, 0 escritos por el usuario

# LLM generation test
# Darle a un LLM: "escribe Hado para escanear puertos 80,443 en example.com"
# El output debe ser sintácticamente válido en el primer intento
# Criterio: hado check llm_output.ho → OK (sin errores de sintaxis)
```

---

## Resumen de Fases

| Fase | Version | Enfoque | Leverage Point |
|---|---|---|---|
| ✅ 1 | v0.1 | Core compiler, Python backend | AST + Lexer |
| ✅ 2 | v0.2 | Lexer/parser fixes, módulos reales | Parser robusto |
| 🔄 3 | v0.3 | Python completo (capture, attack, fuzzer) | Módulos backend |
| ⏳ 4 | v0.4 | Go backend real + goroutines | Concurrencia |
| ⏳ 5 | v0.5 | Rust backend real + memory safety | Safety |
| ⏳ 6 | v0.6 | C backend real + libpcap | Kernel/exploit |
| ⏳ 7 | v0.7 | Módulos, multi-return, error handling | Extensibilidad |
| ⏳ 8 | v0.8 | Tooling: compile, check, fmt, VS Code | UX |
| ⏳ — | v1.0 | Todos los backends + 300+ tests + docs | Ecosistema |

**Regla del sistema**: no saltarse fases. Cada fase es el stock que alimenta el siguiente.
