"""
Tests de Phase 3 — cybersec modules y enumera keyword.
"""

import pytest


# ─── fuzzer ──────────────────────────────────────────────────────────────────

def test_fuzz_returns_correct_structure():
    from habla.cybersec.fuzzer import fuzz
    result = fuzz("http://example.com", wordlist=["index", "admin"], threads=2, timeout=3)
    assert isinstance(result, dict)
    assert "found_paths" in result
    assert "status_codes" in result
    assert "total_requests" in result
    assert "target" in result
    assert result["total_requests"] == 2


def test_fuzz_normalizes_url():
    from habla.cybersec.fuzzer import fuzz, _normalize_url
    assert _normalize_url("example.com") == "https://example.com"
    assert _normalize_url("http://example.com/") == "http://example.com"
    assert _normalize_url("https://example.com") == "https://example.com"


def test_fuzz_with_mode():
    from habla.cybersec.fuzzer import fuzz
    result = fuzz("http://example.com", wordlist=["test"], mode="files", threads=1, timeout=2)
    assert result["mode"] == "files"


def test_fuzz_default_wordlist():
    from habla.cybersec.fuzzer import fuzz, _DEFAULT_WORDLIST
    result = fuzz("http://example.com", threads=2, timeout=2)
    assert result["total_requests"] >= len(_DEFAULT_WORDLIST)


# ─── recon ────────────────────────────────────────────────────────────────────

def test_dns_records_returns_dict():
    from habla.cybersec.recon import dns_records
    result = dns_records("example.com")
    assert isinstance(result, dict)
    # Solo verifica la estructura — no sabemos si dig está disponible


def test_whois_lookup_returns_dict_with_domain():
    from habla.cybersec.recon import whois_lookup
    result = whois_lookup("example.com")
    assert isinstance(result, dict)
    assert result["domain"] == "example.com"


def test_email_harvest_returns_list():
    from habla.cybersec.recon import email_harvest
    result = email_harvest("example.com")
    assert isinstance(result, list)


def test_find_subdomains_returns_list():
    from habla.cybersec.recon import find_subdomains
    result = find_subdomains("example.com", wordlist=["www"])
    assert isinstance(result, list)


# ─── transpiler: enumera ──────────────────────────────────────────────────────

def test_enumera_directories_compiles():
    from habla import compile_to_source
    out = compile_to_source("enumera directories en objetivo")
    assert "_habla_fuzz" in out
    assert "objetivo" in out
    assert "directories" in out


def test_enumera_files_compiles():
    from habla import compile_to_source
    out = compile_to_source('enumera files en "https://example.com"')
    assert "_habla_fuzz" in out
    assert "files" in out


def test_enumera_with_wordlist_compiles():
    from habla import compile_to_source
    out = compile_to_source('enumera directories en objetivo usando lista')
    assert "_habla_fuzz" in out
    assert "wordlist=lista" in out or "wordlist" in out


def test_enumera_import_included():
    from habla import compile_to_source
    out = compile_to_source("enumera directories en objetivo")
    assert "from habla.cybersec.fuzzer import fuzz as _habla_fuzz" in out


def test_enumera_assignment():
    from habla import compile_to_source
    out = compile_to_source("paths = enumera directories en objetivo")
    assert "paths = _habla_fuzz" in out


# ─── transpiler: recon mejorado ───────────────────────────────────────────────

def test_busca_subdomains_compiles():
    from habla import compile_to_source
    out = compile_to_source('busca subdomains de "example.com"')
    assert "_habla_find_subdomains" in out


# ─── parser: enumera AST ─────────────────────────────────────────────────────

def test_enumera_produces_correct_ast():
    from habla.lexer import Lexer
    from habla.parser import Parser
    from habla.ast_nodes import CyberEnumerate, ExpressionStatement

    tokens = Lexer("enumera directories en target").tokenize()
    ast = Parser(tokens).parse()
    stmt = ast.statements[0]
    assert isinstance(stmt, ExpressionStatement)
    node = stmt.expr
    assert isinstance(node, CyberEnumerate)
    assert node.mode == "directories"


def test_enumera_files_ast():
    from habla.lexer import Lexer
    from habla.parser import Parser
    from habla.ast_nodes import CyberEnumerate, ExpressionStatement

    tokens = Lexer("enumera files en objetivo").tokenize()
    ast = Parser(tokens).parse()
    node = ast.statements[0].expr
    assert isinstance(node, CyberEnumerate)
    assert node.mode == "files"
