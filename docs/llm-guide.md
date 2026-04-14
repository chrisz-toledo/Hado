# Hado LLM Guide — How to Generate Hado Code

This document is designed to be given to an LLM (Claude, GPT, etc.) as context so it can generate correct Hado code without hallucinations.

---

## What is Hado? (for the LLM)

Hado is a cybersecurity DSL that transpiles to Python, Go, C, and Rust. It uses Spanish verbs as operators and English nouns for technical terms. It is indentation-based, has zero imports, zero type annotations, and uses `->` pipes to chain operations.

The transpiler handles all boilerplate — the LLM just writes the logic.

---

## System Prompt Template

Copy this into your system prompt to enable correct Hado code generation:

```
You are an expert in Hado, a cybersecurity DSL that transpiles to Python, Go, C, and Rust.

RULES FOR GENERATING HABLA CODE:

Syntax:
- Indentation-based blocks (2 spaces or 1 tab). NO curly braces.
- NO imports, NO type annotations, NO async/await, NO decorators.
- Comments: // single line only.
- String concatenation: "text" + variable (transpiler wraps in str()).
- Pipe operator: -> chains sequential operations.

Keywords (Spanish verbs — ALL ASCII, never use tildes):
- Control: si, sino, mientras, para, cada, en, fn, devuelve
- I/O: muestra, lee, guarda, desde
- Data: filtra, ordena, cuenta
- Cyber: escanea, busca, captura, ataca, analiza, genera
- Logic: y (and), o (or), no (not), es (==)
- Values: cierto (true), falso (false), nulo (null)

Cybersecurity constructs (no imports needed):
- Port scan: escanea target "ip" en ports [22, 80, 443]
- Port scan (variable): escanea variable en ports [80, 443]
- Subdomain recon: subs = busca subdomains de "domain.com"
- Packet capture: captura packets en interface "eth0" donde "tcp port 80"
- Brute force: ataca "ssh" en target con wordlist "rockyou.txt"
- Header analysis: analiza headers de url
- Report: genera reporte con datos

Pipe steps (after ->):
- filtra donde condicion
- filtra alive
- ordena por campo
- cuenta
- muestra
- guarda "file.txt"
- genera reporte

English nouns for technical terms:
target, port, host, payload, vuln, packet, interface, header, ports, subdomains, alive, severity, wordlist, reporte

ASCII normalization:
- NEVER use ñ, á, é, í, ó, ú in keywords — they are always ASCII
- User identifiers CAN have diacritics (the normalizer handles them)
- ñ → nh, á → a, é → e, í → i, ó → o, ú → u
```

---

## Complete Keyword Reference

### Control flow
| Keyword | Meaning | Python equivalent |
|---------|---------|------------------|
| `si` | if | `if` |
| `sino` | else | `else` |
| `mientras` | while | `while` |
| `para` / `cada` | for loop | `for` |
| `en` | in | `in` |
| `fn` | function definition | `def` |
| `devuelve` | return | `return` |

### I/O and data operations
| Keyword | Meaning | Python equivalent |
|---------|---------|------------------|
| `muestra` | print | `print()` |
| `lee "f"` | read file | `open("f").read()` |
| `guarda X en "f"` | write file | `open("f","w").write(X)` |
| `desde "url"` | HTTP GET | `requests.get(url).json()` |
| `filtra donde cond` | filter | `[x for x in ... if cond]` |
| `ordena por campo` | sort | `sorted(..., key=...)` |
| `cuenta X` | count/length | `len(X)` |

### Cybersecurity
| Keyword | Meaning | Python module |
|---------|---------|--------------|
| `escanea target X en ports [...]` | Port scan | `hado.cybersec.scanner` |
| `busca subdomains de X` | Subdomain enum | `hado.cybersec.recon` |
| `busca vulns en target` | Vuln search | `hado.cybersec.analysis` |
| `captura packets en interface X` | Packet capture | `hado.cybersec.capture` |
| `ataca "service" en target con wordlist "f"` | Brute force | `hado.cybersec.attack` |
| `analiza headers de X` | Security analysis | `hado.cybersec.analysis` |
| `genera reporte con datos` | Report generation | `hado.cybersec.report` |

### Logic operators
| Hado | Python | Go | C | Rust |
|-------|--------|-----|---|------|
| `y` | `and` | `&&` | `&&` | `&&` |
| `o` | `or` | `\|\|` | `\|\|` | `\|\|` |
| `no` | `not` | `!` | `!` | `!` |
| `es` | `==` | `==` | `==` | `==` |
| `cierto` | `True` | `true` | `1` | `true` |
| `falso` | `False` | `false` | `0` | `false` |
| `nulo` | `None` | `nil` | `NULL` | `None` |

---

## 10 Most Common Patterns

### 1. Variable assignment
```hado
nombre = "Carlos"
edad = 25
activo = cierto
lista = [1, 2, 3]
```

### 2. Print / display
```hado
muestra "Hola mundo"
muestra "Usuario: " + nombre
muestra "Total: " + cuenta lista
```

### 3. Conditional
```hado
si edad >= 18
  muestra "adulto"
sino
  muestra "menor"
```

### 4. For loop
```hado
para item en lista
  muestra item
```

### 5. Function definition
```hado
fn saludar(nombre)
  muestra "Hola, " + nombre
  devuelve "ok"
```

### 6. HTTP request
```hado
datos = desde "https://api.ejemplo.com/users"
```

### 7. Port scan
```hado
escanea target "192.168.1.1" en ports [22, 80, 443]
```

### 8. Subdomain recon with assignment
```hado
subs = busca subdomains de "ejemplo.com"
para s en subs
  muestra s
```

### 9. Pipe chain
```hado
busca subdomains de "target.com" -> filtra alive -> genera reporte
```

### 10. Save results
```hado
guarda resultados en "output.txt"
```

---

## Anti-patterns (what NOT to generate)

```python
# WRONG — no imports
import requests

# WRONG — no braces
if (x > 0) {
  print(x)
}

# WRONG — no async/await
async def fetch():
  data = await requests.get(url)

# WRONG — no type annotations
def scan(target: str, ports: List[int]) -> dict:

# WRONG — no diacritics in keywords
función = 42    # correct: fn nombre()
señal = "ok"    # correct: senhal = "ok" (or just signal = "ok")

# WRONG — no semicolons
muestra "hola";

# WRONG — no parentheses on control flow
si (x > 0)      # correct: si x > 0

# WRONG — no print() — use muestra
print("hola")   # correct: muestra "hola"

# WRONG — no def — use fn
def my_func():  # correct: fn my_func()

# WRONG — no return — use devuelve
return x        # correct: devuelve x
```

---

## Critical rules for reliable generation

1. **Every token must carry meaning.** No boilerplate, no ceremony.
2. **Cyber constructs need no imports.** The transpiler auto-injects them.
3. **Use `cuenta X` not `len(X)`.** Hado wraps Python builtins.
4. **String concat with `+`.** The transpiler wraps variables in `str()`.
5. **`para X en Y` not `for X in Y`.** All control flow is in Spanish.
6. **`guarda X en "file"` not `save(X, "file")`.** File I/O is a keyword.
7. **Indentation is 2 spaces.** Consistent. No tabs-vs-spaces ambiguity.
8. **`busca subdomains de X` works in assignments.** `subs = busca subdomains de domain` is valid.
9. **`cuenta X` works in expressions.** `muestra "Total: " + cuenta lista` is valid.
10. **`->` pipes left to right.** Each step receives the previous output.

---

## Generation checklist

Before outputting Hado code, verify:

- [ ] No imports at the top
- [ ] No type annotations anywhere
- [ ] No curly braces (blocks are indentation-based)
- [ ] No parentheses around `si`/`mientras` conditions
- [ ] All control flow keywords are Spanish (`si`, `para`, `fn`, etc.)
- [ ] Technical nouns are English (`target`, `ports`, `interface`, etc.)
- [ ] No diacritics in keywords (`muestra` not `müestra`)
- [ ] String concatenation uses `+`
- [ ] Cyber verbs used directly (no function call syntax)
- [ ] Comments use `//` not `#`

---

## ASCII Normalization Reference

The parser automatically normalizes these — both forms are valid in identifiers:

| With diacritic | ASCII form |
|---------------|-----------|
| `ñ` | `nh` |
| `á, é, í, ó, ú` | `a, e, i, o, u` |
| `ü` | `u` |
| `¿, ¡` | (ignored) |

**KEYWORDS are always ASCII.** The language was designed ASCII-first so LLMs never need to guess whether to use tildes.
