# Habla — Design Decisions

This document explains the "why" behind every major design decision in Habla.

---

## 1. Why a DSL and not a general-purpose language?

A DSL lets us make strong assumptions about the problem domain. Cybersecurity has a well-defined vocabulary, a set of common patterns, and a clear program shape: recon, scan, analyze, report.

A general-purpose language must handle every possible use case, which forces it to be more abstract and verbose. Habla hardwires the patterns that appear 90% of the time in cybersecurity code and compresses them into first-class constructs.

The tradeoff: Habla is not designed for web servers or data science pipelines. It doesn't need to be. The domain focus is what makes it powerful.

---

## 2. Why transpile instead of compiling natively?

Transpiling is faster to implement, allows leveraging existing ecosystems, and keeps the feedback loop short. Each target was chosen for a specific cybersecurity use case:

**Python first** — The entire cybersecurity tooling ecosystem (nmap, scapy, requests, paramiko, dnspython) is in Python. Transpiling to Python means Habla code uses this entire ecosystem without re-implementing anything. Python is also what most security researchers already know.

**Go** — Concurrent scanners, standalone binaries, cloud-native security tools. Go compiles to a single binary with no dependencies, making it ideal for tools that need to be deployed across infrastructure. Libraries like nmap/v3, subfinder, nuclei, and gopacket provide the cybersecurity primitives.

**C** — Exploits, shellcode, kernel modules, embedded/IoT security research. C gives direct access to memory, syscalls, and hardware — essential for low-level security work. POSIX sockets for scanning, libcurl for HTTP.

**Rust** — Fuzzing, parser development, memory-safe tools. Rust provides C-level performance with memory safety guarantees, which is critical for security tools that process untrusted input.

We can add native compilation later (via LLVM) without changing the language.

---

## 3. Why bilingual (Spanish verbs + English nouns)?

Cybersecurity is an English-dominated domain. CVEs, protocol names, tool names, and technical concepts are all in English. Translating them would confuse practitioners who think in English technical terms and make the code harder to read alongside documentation.

The insight: the **operators** of the language (what you do) benefit from being in Spanish because they're common verbs that LLMs generate confidently and cheaply. The **nouns** (what you do it to) stay in English because that's the domain's natural language.

This mirrors how practitioners actually talk: "vamos a **escanear** los **ports** del **target**" — spanglish is the natural mode.

---

## 4. Why ASCII-only keywords?

Three problems with Spanish diacritics in a programming language:

**Keyboard accessibility**: ñ, á, é, í, ó, ú are not on most keyboards worldwide. A security researcher in Asia or Eastern Europe would need to configure their keyboard layout.

**LLM tokenization cost**: Most LLMs tokenize `ñ` as 2-3 tokens instead of 1. Diacritics increase token count, which increases API costs and context window usage.

**LLM generation errors**: LLMs frequently "forget" diacritics. If `función` is a keyword and an LLM writes `funcion`, you get a syntax error. This is a reliability problem at scale.

**Solution**: Keywords are designed ASCII-first and never contain diacritics. For user-defined identifiers, the normalizer applies replacements before lexing: both `año` and `anho` resolve to the same identifier. This way, LLM errors become non-errors.

The normalization is applied only to code, not to string literal contents. `muestra "Año nuevo"` preserves the string exactly as written.

---

## 5. Why pipes (`->`) as the central operator?

Cybersecurity workflows are naturally sequential pipelines:

```
target → recon → scan → analyze → report
```

This matches how practitioners think and how LLMs generate code (step by step). The pipe operator makes this structure explicit and readable.

Pipes also reduce variable naming burden. Instead of:

```python
subdomains = find_subdomains(domain)
alive = [s for s in subdomains if resolves(s)]
scan_results = [scan(s, [80, 443]) for s in alive]
report = generate_report(scan_results)
```

You write:

```habla
busca subdomains de domain -> filtra alive -> escanea ports [80, 443] -> genera reporte
```

The Python version is approximately 60 tokens. The Habla version is 12 tokens. That's a 5x compression ratio.

The transpiler generates intermediate `_pipe_N` variables for each step, maintaining full debuggability in the generated code.

---

## 6. Why indentation instead of braces?

Braces (`{`, `}`) are 2 tokens per block (open + close). They often generate "off by one" errors in LLM output (missing closing brace). They're also unnecessary when indentation is enforced consistently.

Indentation-based blocks (Python-style) use zero tokens for block delimiters, are visually clearer, and are already familiar to the Python ecosystem that security researchers use.

The tradeoff: copy-pasting code between contexts can lose indentation. This is a known limitation shared with Python, and it's acceptable given the benefits of zero-token block delimiters.

---

## 7. Why zero imports?

Imports are pure boilerplate. Every Habla program that uses `desde` needs `import requests`. Every program that uses `escanea` needs socket imports. Making the user write these is wasted tokens for the LLM, an error-prone step (wrong module name, missing dependency), and a readability problem (imports at the top of a short script add noise).

The transpiler tracks which constructs are used during AST traversal and injects the necessary imports at the top of the generated code. This is deterministic — there's no ambiguity about which imports are needed.

For Python, the transpiler maintains two import registries: `_MODULE_IMPORTS` for standard library modules and `_HELPER_IMPORTS` for cybersecurity helper functions. The same principle applies to Go (`import`), C (`#include`), and Rust (`use`).

---

## 8. Why cybersecurity as the first domain?

**AI-native use case**: Security researchers are early adopters of LLMs. They regularly ask AI to write recon scripts, scan tools, and exploit PoCs. A DSL optimized for this workflow reduces cost and errors.

**High boilerplate ratio**: Cybersecurity Python scripts have enormous boilerplate (imports, error handling, output formatting). The compression ratio of Habla is highest here — a 40-line Python script becomes 8 lines of Habla.

**Well-defined vocabulary**: The nouns (target, port, vuln, payload) and verbs (scan, recon, exploit, analyze) are universally understood. This makes LLM generation more reliable because the token space is constrained.

**Ethical dual-use**: By making offensive capabilities easy to express, we also make defensive automation equally accessible. This democratizes security research for smaller organizations that can't afford dedicated red teams.

---

## 9. Why recursive-descent parsing?

A recursive-descent parser maps directly to the grammar structure: each parse method corresponds to a grammar rule. This makes the parser easy to extend (adding a new construct means adding a new method), easy to debug (the call stack shows the parse path), and produces clear error messages.

The parser handles INDENT/DEDENT tokens emitted by the lexer to manage blocks, similar to Python's approach. This avoids the complexity of a separate grammar for indentation while keeping the parser stateless.

---

## 10. Why the visitor pattern for code generation?

Each backend (Python, Go, C, Rust) traverses the same AST using `_visit_{NodeType}()` dispatch methods. This means adding a new AST node requires adding one visitor method per backend — the change is localized and predictable.

The alternative (a switch statement per backend) would create a single massive function that's hard to maintain and test. The visitor pattern keeps each node's generation logic self-contained.

---

## 11. Why Python-first execution model?

`habla run script.habla` transpiles to Python and executes in memory via `exec()`. There's no compilation step, no intermediate files, no waiting. This matches the "write and run" workflow that security researchers expect from scripting tools.

For Go, C, and Rust, `habla run` shows the generated code because compilation requires external toolchains. `habla compile -o output.go` generates the file for the user to compile with their own tools.

---

## 12. Why four backends instead of just Python?

Different cybersecurity use cases require different runtime characteristics:

| Use case | Why not Python? | Better target |
|----------|----------------|---------------|
| Standalone scanner binary | Python requires interpreter | Go |
| Exploit development | Python is too slow, no memory control | C |
| Fuzzer for parser | Memory safety + speed required | Rust |
| Network tool for cloud | Single binary, no dependencies | Go |
| Kernel module research | Direct hardware access needed | C |

The multi-target approach means the same Habla source can be compiled for different deployment targets without rewriting the logic.
