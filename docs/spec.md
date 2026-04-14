# Hado Language Specification v0.1.0

Hado is a cybersecurity DSL that transpiles to Python, Go, C, and Rust. This is the formal language specification.

## 1. Lexical structure

### 1.1 Character set

Hado source files are UTF-8 encoded. The normalizer converts Spanish diacritics to ASCII before lexing. Keywords are always ASCII.

### 1.2 Comments

```hado
// This is a comment — everything to end of line is ignored
```

### 1.3 Indentation

Hado uses significant whitespace (Python-style). Blocks are defined by consistent indentation. Either spaces or tabs may be used, but not mixed. Tabs count as 4 spaces. The lexer emits INDENT and DEDENT tokens to mark block boundaries.

### 1.4 Keywords (40 total)

Control flow:
```
si  sino  mientras  para  cada  en  fn  devuelve
```

I/O and data:
```
muestra  lee  guarda  abre
filtra  ordena  agrupa  cuenta  suma
crea  borra  actualiza  envia
```

Cybersecurity:
```
escanea  busca  captura  ataca  intercepta  analiza  genera
```

Error handling and concurrency:
```
cuando  listos  espera  lanza  atrapa
```

Logic and values:
```
es  no  y  o  de  con  sin  como  donde  desde
cierto  falso  nulo  vacio
```

Modifiers:
```
por  a  al
```

Cybersecurity parameters (context-sensitive):
```
target  ports  subdomains  alive  packets  interface
headers  severity  wordlist  vulns  reporte
```

### 1.5 Token types (20)

```
KEYWORD  IDENTIFIER  NUMBER  STRING  OPERATOR  PIPE
NEWLINE  INDENT  DEDENT
LPAREN  RPAREN  LBRACKET  RBRACKET  LBRACE  RBRACE
COMMA  COLON  DOT  COMMENT  EOF
```

### 1.6 Operators

```
->    # pipe
==  !=  >=  <=  >  <    # comparison
+  -  *  /  %            # arithmetic
=                         # assignment
.                         # property access
```

## 2. Types

Hado uses implicit typing. The transpiler infers types from context.

| Hado literal | Python | Go | C | Rust |
|--------------|--------|-----|--------|-----------|
| `42` | `int` | `int` | `int` | `i64` |
| `3.14` | `float` | `float64` | `double` | `f64` |
| `"texto"` | `str` | `string` | `const char*` | `&str` |
| `cierto` | `True` | `true` | `1` | `true` |
| `falso` | `False` | `false` | `0` | `false` |
| `nulo` | `None` | `nil` | `NULL` | `None` |
| `[1, 2]` | `list` | `[]int{}` | array | `Vec<_>` |
| `{"k": v}` | `dict` | `map[string]interface{}` | struct | `HashMap` |

## 3. Statements

### 3.1 Assignment
```hado
variable = expresion
```

### 3.2 Conditional
```hado
si condicion
  bloque_verdadero
sino
  bloque_falso
```

### 3.3 While loop
```hado
mientras condicion
  bloque
```

### 3.4 For loop
```hado
para variable en iterable
  bloque

cada variable en iterable
  bloque
```

Both `para` and `cada` are identical — use whichever reads better.

### 3.5 Function definition
```hado
fn nombre(param1 param2)
  bloque
  devuelve valor
```

Parameters are space-separated OR comma-separated:
```hado
fn suma(a, b)
  devuelve a + b

fn mult a b
  devuelve a * b
```

### 3.6 Display
```hado
muestra expresion
```

### 3.7 File I/O
```hado
contenido = lee "archivo.txt"
guarda datos en "output.txt"
```

### 3.8 HTTP
```hado
datos = desde "https://api.com/endpoint"
datos = desde "https://api.com" con headers {"Authorization": token}
```

## 4. Expressions

### 4.1 Pipe operator
```hado
expresion -> paso1 -> paso2 -> paso3
```

Each step receives the output of the previous step as its implicit input.

Built-in pipe steps:
- `filtra donde condicion` — filter by condition
- `filtra alive` — filter truthy values
- `ordena por campo` — sort by field
- `cuenta` — count elements
- `muestra` — print (terminal step)
- `guarda "archivo"` — write to file (terminal step)
- `genera reporte` — generate report (terminal step)
- `escanea ports [...]` — scan ports of piped input
- `busca subdomains` — find subdomains of piped input

### 4.2 Comparison operators
```hado
x == y    // igual
x != y    // distinto
x >= y    // mayor o igual
x <= y    // menor o igual
x > y     // mayor que
x < y     // menor que
x es y    // igual (alternativa)
x en L    // pertenece a la lista
```

### 4.3 Logical operators
```hado
a y b     // and
a o b     // or
no a      // not
```

### 4.4 String concatenation
```hado
"Hola " + nombre
```

### 4.5 Property access and indexing
```hado
respuesta.status
resultado.open_ports
lista[0]
diccionario["clave"]
```

## 5. Cybersecurity constructs

All cybersecurity constructs work both as statements and as expression-level constructs (assignable to variables, usable in string concatenation, etc.).

### 5.1 Port scan
```hado
escanea target "ip" en ports [22, 80, 443]
resultado = escanea target "192.168.1.1" en ports [22, 80]
escanea variable en ports [80, 443]
```

Python backend: calls `hado.cybersec.scanner.scan()` which uses nmap (if available) or raw sockets.

### 5.2 Subdomain recon
```hado
subs = busca subdomains de "ejemplo.com"
subs = busca subdomains de dominio
```

Python backend: calls `hado.cybersec.recon.find_subdomains()` which does DNS-based enumeration.

### 5.3 Vulnerability search
```hado
busca vulns en target donde severity >= HIGH
```

### 5.4 Packet capture
```hado
captura packets en interface "eth0" donde "tcp port 443"
```

Python backend: calls `hado.cybersec.capture.capture()` which uses scapy or tcpdump.

### 5.5 Brute force
```hado
ataca "ssh" en target con wordlist "rockyou.txt"
ataca "http" en "https://login.ejemplo.com" con usuario "admin" y wordlist "passwords.txt"
```

Supported services: `ssh`, `http`, `http-post`, `http-get`, `ftp`.
Python backend: calls `hado.cybersec.attack.attack()` using paramiko (SSH), requests (HTTP), ftplib (FTP).

### 5.6 Security analysis
```hado
analiza headers de url
analiza resultados
```

Python backend: calls `hado.cybersec.analysis.analyze()` which scores HTTP security headers (A-F grade) and analyzes port risk.

### 5.7 Report generation
```hado
genera reporte con resultados
genera reporte con datos -> guarda "report.md"
```

Formats: markdown, html, json, text. Python backend: calls `hado.cybersec.report.report()`.

## 6. Cryptography (Python module — v0.1)

The `hado.cybersec.crypto` Python module provides:

| Function | Description |
|----------|-------------|
| `hash_md5(text)` | MD5 hash (checksums only) |
| `hash_sha1(text)` | SHA-1 hash |
| `hash_sha256(text)` | SHA-256 hash |
| `hash_sha512(text)` | SHA-512 hash |
| `b64_encode(text)` | Base64 encoding |
| `b64_decode(text)` | Base64 decoding |
| `hmac_sha256(key, msg)` | HMAC-SHA256 signature |
| `generate_token(n)` | Cryptographic random hex token |
| `verify_hash(text, expected, algo)` | Hash verification |

Native Hado syntax for crypto operations is planned for v0.2.

## 7. ASCII normalization

Applied to identifiers and keywords only, not to string literals:

| Input | Normalized |
|-------|-----------|
| `ñ` | `nh` |
| `á` | `a` |
| `é` | `e` |
| `í` | `i` |
| `ó` | `o` |
| `ú` | `u` |
| `ü` | `u` |
| `¿`, `¡` | (removed) |

## 8. Multi-target transpilation

```bash
hado compile script.ho                  # Python (default)
hado compile --target go script.ho      # Go
hado compile --target c script.ho       # C
hado compile --target rust script.ho    # Rust
hado run script.ho                      # Execute via Python
hado run --target go script.ho          # Show generated Go
hado targets                               # List all backends
```

Backend status (v0.1):

| Target | Status | Use case |
|--------|--------|----------|
| Python | Functional | Scripting, OSINT, automation |
| Go | Stub | Concurrent scanners, standalone binaries |
| C | Functional | Exploits, shellcode, kernel modules |
| Rust | Stub | Fuzzing, parsers, memory-safe tools |

## 9. AST node catalog (31 node types)

Program, Assignment, IfStatement, WhileStatement, ForStatement, FunctionDef, ReturnStatement, ShowStatement, SaveStatement, ReadStatement, ExpressionStatement, PipeExpression, FilterExpression, SortExpression, CountExpression, CyberScan, CyberRecon, CyberCapture, CyberAttack, CyberAnalyze, CyberFindVulns, GenerateReport, HttpGet, HttpPost, BinaryOp, UnaryOp, Identifier, NumberLiteral, StringLiteral, BooleanLiteral, NullLiteral, ListLiteral, DictLiteral, PropertyAccess, IndexAccess, FunctionCall.

## 10. Compiler pipeline

```
source.ho → Normalizer → Lexer → Parser → AST → Backend → target code
                 (ASCII)   (tokens)  (tree)        (Python/Go/C/Rust)
```

The normalizer strips diacritics. The lexer produces tokens including INDENT/DEDENT. The parser builds a recursive-descent AST. The backend traverses the AST using the visitor pattern and generates target code with appropriate imports.
