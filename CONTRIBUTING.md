# Contributing to Habla

Thank you for your interest in contributing to Habla!

## Getting started

```bash
git clone https://github.com/chrisz-toledo/habla
cd habla
pip install -e ".[dev]"
```

## Running tests

```bash
pytest tests/
```

## Code style

- Python code follows Black formatting (`black src/ tests/`)
- All user-facing error messages must be in Spanish
- New language features require: parser support + all four backends (Python, Go, C, Rust) + tests + documentation

## Adding a new keyword

1. Add the keyword to `KEYWORDS` in `src/habla/lexer.py`
2. Add an AST node in `src/habla/ast_nodes.py` if needed
3. Add parsing logic in `src/habla/parser.py`
4. Add transpilation in all four backends:
   - `src/habla/backends/python_transpiler.py`
   - `src/habla/backends/go_backend.py`
   - `src/habla/backends/c_transpiler.py`
   - `src/habla/backends/rust_transpiler.py`
5. Add tests in `tests/`
6. Update `docs/spec.md`

## Adding a cybersec module

1. Create the module in `src/habla/cybersec/`
2. Export from `src/habla/cybersec/__init__.py`
3. Add the `_habla_X` import mapping in `src/habla/backends/python_transpiler.py`
4. Add Go/C/Rust codegen stubs in the respective backends (with comments pointing to the native library to use per target)
5. Add an example in `examples/`

## Design principles

- Every token must carry maximum semantic meaning (no boilerplate)
- Spanish verbs + English nouns (never translate technical terms)
- ASCII-only keywords (no diacritics in the language spec)
- Zero imports for the user (the transpiler handles all imports)
- Error messages always in Spanish

## Reporting issues

Open an issue at https://github.com/chrisz-toledo/habla/issues
