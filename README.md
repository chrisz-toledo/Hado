# Habla

**A cybersecurity DSL designed for AI-native code generation. Spanish verbs. English nouns. Zero boilerplate.**

```habla
busca subdomains de "target.com" -> filtra alive -> escanea ports [80, 443] -> genera reporte
```

---

## What is Habla?

Habla is a domain-specific language for cybersecurity that transpiles to **Python, Go, C, and Rust**. It is designed so that LLMs (Claude, GPT, Gemini) can write cybersecurity code more efficiently, more cheaply, and with fewer errors. The user writes 12 tokens in Habla — the transpiler generates 45+ tokens of executable code.

Habla is not a general-purpose language competing with Python. It is a **multi-target DSL**: the same Habla code compiles to Python for rapid prototyping, Go for concurrent scanners, Rust for memory-safe tools, and C for exploits and kernel-level work.

---

## Why Habla?

The problem: LLMs waste tokens on boilerplate.

```python
# Python: 47 tokens to scan a host
import socket
results = {}
for port in [22, 80, 443]:
    s = socket.socket()
    s.settimeout(1)
    results[port] = s.connect_ex(("192.168.1.1", port)) == 0
    s.close()
```

```habla
# Habla: 8 tokens
escanea target "192.168.1.1" en ports [22, 80, 443]
```

The solution: a language where every token carries maximum semantic meaning. No imports, no ceremony, no boilerplate.

---

## Quick Start

```bash
pip install habla-lang
```

Create `hello.habla`:
```habla
muestra "Hola mundo desde Habla!"

nombre = "Christian"
muestra "Bienvenido, " + nombre
```

Run it:
```bash
habla run hello.habla
```

---

## Language Overview

### 1. Zero boilerplate
No imports, no requires, no decorators. The transpiler resolves dependencies from context.

```habla
// Sin imports — el transpiler los inyecta automaticamente
datos = desde "https://api.github.com/repos/chrisz-toledo/habla"
muestra datos
```

### 2. Spanish verbs as operators
```habla
muestra "resultado"          // print
filtra donde x > 0          // filter
escanea target en ports [...] // port scan
busca subdomains de "dom"    // subdomain recon
captura packets en "eth0"    // packet capture
```

### 3. Pipes connect everything
```habla
"target.com" -> busca subdomains -> filtra alive -> escanea ports [80, 443] -> genera reporte
```

### 4. Implicit types
```habla
nombre = "Carlos"      // str
edad   = 25            // int
activo = cierto        // bool
datos  = desde "url"   // dict (HTTP JSON)
```

### 5. Indentation-based blocks
```habla
si edad >= 18
  muestra "adulto"
sino
  muestra "menor"
```

### 6. English nouns for technical terms
Technical cybersecurity terms stay in English (CVEs, protocols, tools are always in English):
```habla
// Spanish verbs + English nouns
escanea target "192.168.1.1" en ports [22, 80, 443]
busca subdomains de "example.com"
captura packets en interface "eth0"
```

### 7. Four compilation targets
```bash
habla compile script.habla               # Python (default)
habla compile --target go script.habla   # Go  (go build)
habla compile --target c script.habla    # C   (gcc/clang)
habla compile --target rust script.habla # Rust (rustc/cargo)
habla run script.habla                   # Execute via Python
habla targets                            # List all backends and their status
```

---

## Cybersecurity Examples

### Recon pipeline
```habla
dominio = "target.com"

// Subdominios vivos
subs = busca subdomains de dominio

// Escaneo de puertos en cada subdominio
para cada sub en subs
  escanea sub en ports [80, 443, 8080, 8443]

// Reporte final
genera reporte con subs -> guarda "recon-report.md"
```

### Security header analysis
```habla
url = "https://example.com"
respuesta = desde url
muestra "Analizando headers de " + url
analiza headers de url
```

### Brute force (authorized environments only)
```habla
// Solo usar en entornos propios o con permiso explicito
ataca "ssh" en "192.168.1.100" con wordlist "rockyou.txt"
```

### Full OSINT assessment
```habla
fn osint(objetivo)
  muestra "=== OSINT: " + objetivo + " ==="

  subs = busca subdomains de objetivo -> filtra alive
  muestra "Subdominios: " + cuenta subs

  para cada sub en subs
    escanea sub en ports [22, 80, 443, 3306, 5432, 8080]

  busca vulns en subs
  genera reporte con subs -> guarda objetivo + "-osint.md"

osint("target.com")
```

---

## ASCII-first Design

Habla solves three problems with Spanish diacritics in programming:

1. **Keyboard accessibility** — ñ, á, é don't exist on most keyboards
2. **LLM tokenization cost** — diacritics tokenize as 2-3 tokens instead of 1
3. **LLM generation errors** — LLMs frequently omit diacritics

**Solution**: Keywords are always ASCII. The normalizer handles user identifiers transparently.

| With diacritic | ASCII form | Both are valid |
|---------------|-----------|----------------|
| `año` | `anho` or `anio` | ✓ |
| `función` | `funcion` | ✓ |
| `también` | `tambien` | ✓ |
| `¿qué pasa?` | `que pasa?` | ✓ |

String literals are **never** normalized — `muestra "Año nuevo"` preserves the string exactly.

---

## For LLM Developers

Use this system prompt to enable Habla generation in your AI application:

```
You are an expert in Habla, a cybersecurity DSL that transpiles to Python, Go, C, and Rust.

Rules for generating Habla code:
- Use Spanish verbs for actions: muestra, filtra, escanea, busca, captura, ataca, analiza, genera
- Use English nouns for tech terms: target, port, host, payload, vuln, packet, interface, header
- Use -> for pipes: datos -> filtra donde x > 0 -> guarda "out.txt"
- No imports, no curly braces, no async/await, no type annotations
- Indentation-based blocks (2 spaces or 1 tab)
- ASCII only: no tildes (á,é,í,ó,ú), no ñ, no ¿ or ¡
- Booleans: cierto/falso. Logic: y/o/no. Null: nulo
- Keep it minimal: every token must carry meaning
```

See [docs/llm-guide.md](docs/llm-guide.md) for the complete guide including all keywords, common patterns, and anti-patterns.

---

## Architecture

```
┌─────────────┐
│ .habla file │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Normalizer │  ñ→nh, á→a, ¿→ (ASCII-only)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│    Lexer    │  tokens: KEYWORD, IDENT, NUMBER, STRING, PIPE, INDENT/DEDENT
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Parser    │  recursive descent → AST
└──────┬──────┘
       │
       ├──────────────┬──────────────┬──────────────┐
       ▼              ▼              ▼              ▼
┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐
│  Python   │  │    Go     │  │     C     │  │   Rust    │
│  Backend  │  │  Backend  │  │  Backend  │  │  Backend  │
└─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
      │               │              │               │
      ▼               ▼              ▼               ▼
   .py file        .go file       .c file        .rs file
   (exec'd)      (go build)    (gcc/clang)   (rustc/cargo)
```

---

## Roadmap

### Phase 1 — Prototype (v0.1) ← Current
- [x] Lexer + Parser + Transpiler
- [x] Variables, conditionals, loops, functions, pipes
- [x] Four backends: Python, Go (stub), C, Rust (stub)
- [x] Cybersec modules: scanner, recon, capture, attack, analysis, report
- [x] CLI: run, compile --target, repl
- [x] 7 example programs

### Phase 2 — Python Expansion (v0.2)
- [ ] All cybersec modules fully functional in Python
- [ ] Standard library (red, archivo, texto, crypto)
- [ ] Better error reporting with suggestions
- [ ] Plugin system for extending the language

### Phase 3 — Go Backend (v0.3)
- [ ] Go backend fully functional
- [ ] Native integration: subfinder, nuclei, httpx, naabu
- [ ] Standalone binary generation (no runtime dependency)
- [ ] Automatic goroutines for parallel operations

### Phase 4 — Rust Backend (v0.4)
- [ ] Rust backend fully functional
- [ ] Integration with rustscan, feroxbuster, cargo-audit
- [ ] Memory-safe binary generation
- [ ] Fuzzer and protocol parser support via cargo-fuzz

### Phase 5 — C Backend (v0.5)
- [ ] C backend fully functional
- [ ] Integration with libpcap, OpenSSL, raw sockets
- [ ] Shellcode and exploit generation
- [ ] Kernel module and driver templates

### Phase 6 — Intelligence (v0.6)
- [ ] Auto-resolve dependencies per target (pip, go mod, cargo, make)
- [ ] Detection of insecure patterns in code
- [ ] Automatic target recommendation based on use case
- [ ] Integration with cybersec APIs (Shodan, VirusTotal, etc.)

### Phase 7 — Ecosystem (v1.0)
- [ ] Multi-target package manager
- [ ] LSP (Language Server Protocol) for editors
- [ ] VS Code extension with syntax highlighting
- [ ] Interactive web playground
- [ ] Support for additional targets (Zig, Nim, Assembly)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE).

---

*Built with [Habla DSL](https://github.com/chrisz-toledo/habla)*
