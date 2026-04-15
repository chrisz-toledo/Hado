# Habla Multi-Target — Go, C, and Rust Backend Vision

Habla transpiles a single `.habla` source file to four different target languages. This document details the vision, current status, and use cases for each non-Python backend.

---

## Architecture overview

```
                    ┌─────────────────────────────┐
                    │        source.habla          │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │   Normalizer → Lexer → Parser │
                    │          (shared AST)          │
                    └──────────────┬───────────────┘
                                   │
            ┌──────────┬───────────┼───────────┬──────────┐
            ▼          ▼           ▼           ▼          │
      ┌──────────┐ ┌────────┐ ┌────────┐ ┌────────┐     │
      │  Python  │ │   Go   │ │   C    │ │  Rust  │     │
      │ Backend  │ │Backend │ │Backend │ │Backend │     │
      └────┬─────┘ └───┬────┘ └───┬────┘ └───┬────┘     │
           │           │          │          │           │
      script.py   main.go    main.c    main.rs          │
      (exec)      (go build) (gcc)     (cargo)          │
```

All four backends inherit from `BaseTranspiler` and implement the visitor pattern. The AST is identical regardless of target — only the code generation differs.

---

## Current status (v0.1)

| Target | Status | Control flow | Cyber modules | Execution |
|--------|--------|-------------|---------------|-----------|
| Python | Functional | Full | Full (7 modules) | `habla run` / `exec()` |
| Go | Stub | Full | Stubs (comments) | `go build` |
| C | Functional | Full | Partial (sockets) | `gcc` |
| Rust | Stub | Full | Stubs (comments) | `cargo build` |

"Stub" means the backend generates compilable code with correct control flow, but cybersecurity operations produce comments pointing to the right libraries instead of calling them directly.

---

## Go Backend

### Vision

Go is the target for concurrent scanners, standalone binaries, and cloud-native security tools. Go's goroutines make it natural to express concurrent scanning (hundreds of ports simultaneously), and `go build` produces a single binary with no dependencies.

### Use cases

**Concurrent port scanner**: Habla's `escanea target en ports [...]` transpiles to a goroutine-based scanner that checks all ports simultaneously instead of sequentially.

**Standalone recon tool**: A single `habla compile --target go recon.habla -o recon.go && go build -o recon recon.go` produces a binary you can deploy to any server without installing Python or dependencies.

**Cloud security automation**: Go binaries run natively in containers, Lambda functions, and Kubernetes jobs. A Habla-generated Go scanner can be deployed as a CronJob for continuous monitoring.

### Generated code characteristics

- Package `main` with `func main()`
- Variables use `:=` (short declaration)
- Control flow uses braces: `if cond { }`, `for _, x := range list { }`
- Booleans: `true`/`false`
- Print: `fmt.Println()`
- Auto-import tracking: `fmt`, `os`, `net/http` added as needed
- Logical operators: `y` → `&&`, `o` → `||`, `no` → `!`

### Target libraries (v0.2+)

| Habla construct | Go library |
|----------------|------------|
| `escanea` | `github.com/Ullaakut/nmap/v3` |
| `busca subdomains` | `github.com/projectdiscovery/subfinder/v2` |
| `busca vulns` | `github.com/projectdiscovery/nuclei/v3` |
| `captura packets` | `github.com/google/gopacket` |
| `ataca "ssh"` | `golang.org/x/crypto/ssh` |

### Roadmap

- v0.2: Stub generation (current — compilable with TODOs)
- v0.3: Scanner module (nmap/v3 integration)
- v0.4: Recon module (subfinder integration)
- v0.5: Full cybersec module parity with Python

---

## C Backend

### Vision

C is the target for exploits, shellcode, kernel modules, and embedded/IoT security research. C gives direct access to memory, syscalls, and hardware — the fundamental building blocks of offensive security.

### Use cases

**Exploit development**: Buffer overflows, format string attacks, and ROP chains require precise memory control that only C provides.

**Shellcode generation**: Habla scripts can generate C code that compiles to position-independent shellcode for payload development.

**Kernel module research**: Security researchers analyzing kernel vulnerabilities need C for module development and debugging.

**Embedded/IoT security**: Firmware analysis and IoT exploit development require C for cross-compilation to ARM, MIPS, and other architectures.

### Generated code characteristics

- ANSI C with `int main(int argc, char *argv[])`
- Auto-includes: `stdio.h`, `stdlib.h`, `string.h`
- Type inference: `double` for floats, `int` for integers, `const char*` for strings
- Print: `printf()` with format specifiers
- Booleans: `1`/`0`
- Helper function `habla_scan_port()` using POSIX sockets (`socket`, `connect`, `setsockopt`)
- Cybersecurity operations use raw socket calls where possible

### Compilation

```bash
habla compile --target c script.habla -o script.c
gcc -o scanner script.c
./scanner
```

For network operations, link with: `gcc -o scanner script.c -lcurl` (HTTP) or no extra flags needed (sockets are POSIX standard).

### Roadmap

- v0.1: Basic transpilation with socket scanner (current)
- v0.3: libcurl HTTP integration
- v0.4: libpcap packet capture
- v0.5: Full cybersec module parity

---

## Rust Backend

### Vision

Rust is the target for fuzzing, parser development, and memory-safe tools. Rust provides C-level performance with compile-time memory safety guarantees — critical for security tools that process untrusted input.

### Use cases

**Fuzzing**: Rust's memory safety and speed make it ideal for building fuzzers that test parsers, protocol implementations, and file format handlers.

**Protocol parsers**: Building safe parsers for network protocols (HTTP, DNS, TLS) that handle malformed input without crashing.

**Memory-safe exploit tooling**: Tools that analyze memory layouts, inspect binary formats, or process crash dumps benefit from Rust's safety guarantees.

**High-performance scanning**: When Python is too slow for millions of targets and you need safety guarantees that C doesn't provide.

### Generated code characteristics

- Edition 2021 with `fn main()`
- Variables use `let mut` for assignments
- Control flow: `if cond { }`, `for x in list.iter() { }`
- Print: `println!()` macro
- Booleans: `true`/`false`
- String handling with `String` and `&str`
- Error handling hints via `Result<>` types
- Cargo.toml dependency suggestions in comments (e.g., `reqwest` for HTTP)

### Target crates (v0.2+)

| Habla construct | Rust crate |
|----------------|------------|
| `desde` | `reqwest` |
| `escanea` | `tokio` + `std::net::TcpStream` |
| `busca subdomains` | `trust-dns-resolver` |
| `captura packets` | `pcap` |
| `ataca "ssh"` | `ssh2` |

### Compilation

```bash
habla compile --target rust script.habla -o src/main.rs
cargo build --release
./target/release/scanner
```

### Roadmap

- v0.2: Stub generation (current — compilable with TODOs)
- v0.4: Async scanner (tokio-based)
- v0.5: DNS resolver integration
- v0.6: Full cybersec module parity

---

## Cross-compilation workflow

The recommended workflow for multi-target development:

1. **Develop in Python**: Write and test your Habla script with `habla run script.habla`. Python execution is instant and gives you full cybersec module access.

2. **Verify cross-compilation**: Run `habla compile --target go script.habla` (and c, rust) to ensure the code compiles cleanly for all targets.

3. **Deploy to target**: When you need a standalone binary, concurrent execution, or memory safety, compile to the appropriate target and build with the native toolchain.

```bash
# Development
habla run recon.habla

# Deploy as Go binary
habla compile --target go recon.habla -o recon.go
go build -o recon recon.go

# Deploy as C binary
habla compile --target c recon.habla -o recon.c
gcc -O2 -o recon recon.c

# Deploy as Rust binary
habla compile --target rust recon.habla -o src/main.rs
cargo build --release
```

---

## Adding a new backend

To add a fifth target (e.g., JavaScript/TypeScript):

1. Create `src/habla/backends/js_backend.py` inheriting from `BaseTranspiler`
2. Implement all `_visit_{NodeType}()` methods
3. Register in `src/habla/backends/__init__.py` (`TARGETS` dict + `get_backend()`)
4. Add to CLI target choices in `src/habla/cli.py`
5. Add tests in `tests/test_transpiler.py`

The shared AST means the new backend only needs to handle code generation — lexing, parsing, and normalization are reused automatically.
