# Hado Tutorial — From Zero to Security Assessment

This tutorial walks you through Hado step by step, building real cybersecurity tools as you go.

## Prerequisites

```bash
git clone https://github.com/chrisz-toledo/hado.git
cd hado
pip install -e .
```

Verify the install:
```bash
hado targets
```

You should see four backends listed: Python (functional), Go (stub), C (functional), Rust (stub).

## Step 1: Hello World

Create `hello.ho`:

```hado
muestra "Hola desde Hado!"
```

Run it:

```bash
hado run hello.ho
```

Output:
```
Hola desde Hado!
```

That single line transpiles to `print("Hola desde Hado!")` — no imports, no boilerplate.

## Step 2: Variables and types

```hado
target = "127.0.0.1"
ports = [22, 80, 443, 8080]
activo = cierto
pi = 3.14

muestra "Target: " + target
muestra "Puertos: " + ports
muestra "Activo: " + activo
```

No type annotations. No `let`, `var`, or `const`. Assign and go. Types are inferred by the transpiler.

Key values: `cierto` (true), `falso` (false), `nulo` (null/none).

## Step 3: Your first scan

```hado
target = "127.0.0.1"
escanea target en ports [22, 80, 443]
```

This generates Python that uses `socket.connect_ex` (or `nmap` if available). The output shows which ports are open or closed on your local machine.

## Step 4: Conditionals

```hado
puerto = 80

si puerto == 80
  muestra "Puerto HTTP detectado"
sino
  muestra "Puerto desconocido"
```

`si` = if, `sino` = else. Indentation defines the block — no braces needed.

## Step 5: Loops

```hado
targets = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

para t en targets
  muestra "Escaneando: " + t
  escanea t en ports [22, 80, 443]
```

`para X en Y` = for X in Y. You can also write `cada X en Y` — they're identical.

## Step 6: Functions

```hado
fn escanear_target(ip)
  muestra "Iniciando escaneo de " + ip
  resultado = escanea ip en ports [22, 80, 443, 3306, 5432]
  devuelve resultado

resultado1 = escanear_target("192.168.1.1")
resultado2 = escanear_target("192.168.1.2")
```

`fn` defines a function, `devuelve` returns a value. Parameters are space or comma separated.

## Step 7: HTTP requests

```hado
url = "https://httpbin.org/json"
datos = desde url
muestra datos
```

`desde` makes a GET request and returns the JSON response. No `import requests` needed — the transpiler handles it.

## Step 8: Pipe chains

The signature feature of Hado:

```hado
busca subdomains de "example.com" -> filtra alive -> muestra
```

Each `->` passes the result of the previous step to the next. This replaces dozens of lines of Python boilerplate with a single readable pipeline.

## Step 9: Subdomain recon

```hado
dominio = "example.com"
subs = busca subdomains de dominio
muestra "Encontrados: " + cuenta subs

para s en subs
  muestra "  -> " + s

guarda subs en "subdomains.txt"
```

`busca subdomains de X` enumerates subdomains via DNS. `cuenta X` returns the length. `guarda X en Y` writes to a file.

## Step 10: Security analysis

```hado
url = "https://example.com"
muestra "Analizando headers de seguridad..."
analiza headers de url
```

This checks HTTP security headers (HSTS, CSP, X-Frame-Options, etc.) and returns a grade from A to F.

## Step 11: Full assessment pipeline

```hado
fn assessment(dominio)
  muestra "=== Assessment de " + dominio + " ==="

  // Recon
  muestra "Fase 1: Subdominios"
  subs = busca subdomains de dominio
  muestra "Encontrados: " + cuenta subs

  // Scan
  muestra "Fase 2: Escaneo de puertos"
  para sub en subs
    escanea sub en ports [80, 443, 8080, 8443]

  // Report
  muestra "Fase 3: Reporte"
  genera reporte con subs
  muestra "Assessment completado."

assessment("example.com")
```

## Step 12: See the generated code

```bash
hado compile assessment.ho
```

This shows the Python output. You can also target other backends:

```bash
hado compile --target go assessment.ho
hado compile --target c assessment.ho
hado compile --target rust assessment.ho
```

Save to a file:
```bash
hado compile --target c assessment.ho -o assessment.c
```

## What happens under the hood?

```
.ho → Normalizer → Lexer → Parser → AST → Backend → exec()
          (ASCII)    (tokens)  (tree)        (Python)
```

The normalizer strips diacritics (so `señal` and `senhal` are the same identifier). The lexer tokenizes including INDENT/DEDENT for blocks. The parser builds an AST. The Python backend traverses it and generates code with auto-injected imports. `hado run` executes this in memory.

## Next steps

- Browse the [cybersec cookbook](cybersec-cookbook.md) for real-world recipes
- Read the [language specification](spec.md) for the full reference
- Check [design decisions](design-decisions.md) to understand why Hado works the way it does
- See [multi-target](multi-target.md) for the Go, C, and Rust backend vision
- Read the [LLM guide](llm-guide.md) to integrate Hado with AI systems
