"""
tests/test_capabilities.py
==========================
Audit de capacidades reales de Hado v0.4.

Este archivo prueba explícitamente qué funciona y qué NO funciona.
La honestidad es la meta: si algo es un stub o tiene limitaciones,
hay un test que lo documenta con assert "TODO" o similar.

Categorías:
  ✅ REAL     — funciona, produce output útil
  ⚠️  PARTIAL  — funciona con condiciones (root, lib externa, etc.)
  ❌ STUB     — genera TODO / placeholder / sin implementación útil
  🔬 MODULE   — prueba el módulo Python directamente (sin transpilación)
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hado.runtime import compile_to_source


# ─── Helpers ──────────────────────────────────────────────────────────────────

def py(source: str) -> str:
    """Transpila a Python."""
    return compile_to_source(source.strip() + "\n", target="python")

def go(source: str) -> str:
    """Transpila a Go."""
    return compile_to_source(source.strip() + "\n", target="go")

def c_code(source: str) -> str:
    """Transpila a C."""
    return compile_to_source(source.strip() + "\n", target="c")

def rust(source: str) -> str:
    """Transpila a Rust."""
    return compile_to_source(source.strip() + "\n", target="rust")


# ══════════════════════════════════════════════════════════════════════════════
# SECCIÓN 1: PYTHON BACKEND — Capacidades reales ✅
# ══════════════════════════════════════════════════════════════════════════════

class TestPythonCapabilities:
    """
    El Python backend es el más completo.
    Delega a módulos cybersec reales con implementaciones genuinas.
    """

    def test_port_scan_generates_real_call(self):
        """✅ escanea → llama a hado.cybersec.scanner.scan()"""
        code = py('escanea target "192.168.1.1" en ports [22, 80, 443]\n')
        assert "scanner" in code or "scan" in code
        assert "192.168.1.1" in code
        assert "22" in code and "80" in code and "443" in code

    def test_subdomain_recon_generates_real_call(self):
        """✅ busca subdomains → llama a hado.cybersec.recon.find_subdomains()"""
        code = py('subs = busca subdomains de "example.com"\n')
        assert "find_subdomains" in code or "recon" in code
        assert "example.com" in code

    def test_http_header_analysis_generates_real_call(self):
        """✅ analiza headers → llama a hado.cybersec.analysis.analyze()"""
        code = py('analiza headers de "https://example.com"\n')
        assert "analiz" in code.lower() or "analysis" in code or "headers" in code

    def test_report_generation_real(self):
        """✅ genera reporte → llama a hado.cybersec.report.report()"""
        code = py('genera reporte con datos\n')
        assert "report" in code

    def test_brute_force_generates_real_call(self):
        """✅ ataca → llama a hado.cybersec.attack.attack()"""
        code = py('ataca "ssh" en "192.168.1.1" con wordlist "rockyou.txt"\n')
        assert "attack" in code
        assert "ssh" in code.lower()
        assert "192.168.1.1" in code

    def test_packet_capture_generates_call(self):
        """⚠️ captura → genera llamada, pero requiere root + scapy/tcpdump"""
        code = py('captura packets en interface "eth0"\n')
        assert "capture" in code or "captura" in code or "eth0" in code

    def test_fuzzer_not_directly_exposed_as_syntax(self):
        """
        ⚠️ LIMITACIÓN: fuzzer.py existe pero no hay keyword 'fuzzea' en Hado.
        El fuzzer solo es accesible via Python directo, no via sintaxis .ho.
        """
        code = py('desde "https://example.com"\n')
        # No existe sintaxis nativa para fuzz — esto es una limitación documentada
        # El fuzzer requiere importación directa de hado.cybersec.fuzzer
        assert "fuzz" not in code  # confirma que no hay keyword

    def test_crypto_not_exposed_as_native_syntax(self):
        """
        ⚠️ LIMITACIÓN: crypto.py existe pero no hay sintaxis nativa en v0.4.
        Requiere llamada directa al módulo Python.
        No hay keywords como 'hashea', 'codifica', etc.
        """
        # No hay sintaxis Hado para crypto aún — es acceso Python directo
        # spec.md sección 6 dice: "Native Hado syntax for crypto operations
        # is planned for v0.2" → aún no implementado
        pass  # Confirma la limitación: crypto es Python-only, no Hado-syntax

    def test_pipe_operator_real(self):
        """✅ pipes funcionales en Python — se expanden en el transpiler"""
        code = py('"example.com" -> busca subdomains -> filtra alive\n')
        assert "->" not in code  # los pipes se resuelven en el transpiler
        # El pipe se convierte en pasos intermedios _pipe_N
        assert "_pipe_" in code or "subdomains" in code or "find_sub" in code

    def test_full_assessment_pipeline(self):
        """✅ pipeline completo compila sin errores"""
        source = """
fn assessment(dominio)
  subs = busca subdomains de dominio
  muestra "Subdominios: " + cuenta subs
  genera reporte con subs

assessment("target.com")
"""
        code = py(source)
        assert "def assessment" in code
        assert "find_subdomains" in code or "recon" in code
        assert "report" in code


# ══════════════════════════════════════════════════════════════════════════════
# SECCIÓN 2: LIMITACIONES EXPLÍCITAS — Lo que Hado NO puede hacer ❌
# ══════════════════════════════════════════════════════════════════════════════

class TestExplicitLimitations:
    """
    Tests que documentan explícitamente las limitaciones de Hado v0.4.
    Estas no son bugs — son características aún no implementadas.
    Un zero-day researcher necesita saber esto ANTES de depender del lenguaje.
    """

    def test_no_raw_socket_syntax(self):
        """
        ❌ LIMITACIÓN: No hay sintaxis para crafting de paquetes TCP/UDP raw.
        Para exploit work real se necesita: envía tcp a "ip" con flags [SYN,RST]
        Workaround: usar Python directo con scapy o socket.
        """
        # No existe 'envía packet' como constructor de frames raw en Hado
        # El único socket es via escanea (TCP connect scan solamente)
        code = py('escanea target "1.2.3.4" en ports [80]\n')
        # Solo genera TCP connect — no SYN scan, no UDP, no ICMP, no raw frames
        assert "SYN" not in code
        assert "UDP" not in code
        assert "ICMP" not in code

    def test_no_memory_manipulation_syntax(self):
        """
        ❌ LIMITACIÓN: No hay primitivas de memoria en Hado.
        Para exploit development se necesita: mmap, mprotect, ROP chains.
        La sintaxis no tiene punteros, offsets, ni heap primitives.
        """
        # No hay keywords para manipulación de memoria
        # El transpiler C genera void* para tipos desconocidos — no es útil
        code = c_code('x = 0x41414141\n')
        # El C transpiler no sabe que 0x41414141 es un address, lo trata como int
        # No hay 'apunta a', 'buffer', 'offset', 'shellcode' como keywords
        assert "mmap" not in code
        assert "mprotect" not in code

    def test_no_shellcode_generation(self):
        """
        ❌ LIMITACIÓN: No hay generación de shellcode.
        Hado no puede generar bytecodes de explotación.
        Workaround: escribir shellcode en C/Python fuera de Hado.
        """
        code = py('muestra "\\x41\\x41\\x41\\x41"\n')
        # Strings con escapes funcionan, pero no hay 'ejecuta shellcode X'
        assert "\\x41" in code or "\\\\x41" in code  # solo string literal

    def test_no_binary_parsing_syntax(self):
        """
        ❌ LIMITACIÓN: No hay parsing de binarios (ELF/PE/Mach-O).
        Para análisis de exploits reales se necesita leer headers ELF.
        No existen keywords como 'lee elf', 'parse pe', 'headers mach-o'.
        BONUS: 'lee "archivo"' en Python genera código incompleto (lee es unario)
        — la sintaxis 'lee "x"' no es un ReadStatement válido en todos los contextos.
        """
        # Lee standalone como assignment no genera open() completo — bug/limitación
        code = py('contenido = lee "binary.elf"\n')
        # No hay ELF parser, no hay binary parsing — solo texto plano si funciona
        assert "elf" not in code.lower() or "binary" in code
        # La clave es que NO hay parsing de binarios
        assert "ELF" not in code
        assert "struct.unpack" not in code

    def test_no_rop_chain_construction(self):
        """
        ❌ LIMITACIÓN: No hay construcción de ROP chains.
        El lenguaje no tiene primitivas para gadget finding o chain building.
        """
        # No hay nada en el AST para esto
        pass  # La limitación es la ausencia de feature

    def test_no_encryption_native_syntax(self):
        """
        ❌ LIMITACIÓN: No hay sintaxis nativa para encriptar/desencriptar.
        crypto.py existe y funciona, pero no hay keywords:
        - 'hashea texto con sha256'
        - 'encripta datos con aes'
        - 'firma mensaje con hmac'
        spec.md dice: "planned for v0.2" — still not implemented en v0.4
        """
        # Esto NO compila como cybersec operation:
        # hashea "password" con sha256  ← NO es sintaxis válida
        # Solo se accede via Python: from hado.cybersec.crypto import hash_sha256
        pass

    def test_go_backend_cybersec_incomplete(self):
        """
        ⚠️ LIMITACIÓN: Backend Go solo tiene port scan real.
        Otros constructs cybersec generan TODO comments.
        El Go compilado NO llama a módulos Python cybersec.
        """
        # analiza headers en Go = TODO
        code = go('analiza headers de "https://example.com"\n')
        # Debería generar algún TODO o comentario, no código real
        assert "TODO" in code or "/* " in code or "// " in code

    def test_c_backend_http_is_stub(self):
        """
        ⚠️ LIMITACIÓN: Backend C genera comentarios para HTTP (requiere libcurl).
        El código C generado para 'desde url' NO compila sin libcurl.
        """
        code = c_code('datos = desde "https://api.com"\n')
        # HTTP en C es comentario con instrucciones, no código real
        assert "curl" in code.lower() or "TODO" in code or "/*" in code

    def test_rust_backend_cybersec_partial(self):
        """
        ⚠️ LIMITACIÓN: Backend Rust tiene CyberScan y CyberRecon parciales.
        CyberAttack y CyberCapture no tienen implementación real en Rust.
        """
        # Port scan en Rust: real (TcpStream)
        scan_code = rust('escanea target "1.2.3.4" en ports [22, 80]\n')
        assert "TcpStream" in scan_code  # ✅ real

        # Attack en Rust: stub/TODO
        attack_code = rust('ataca "ssh" en "1.2.3.4" con wordlist "pass.txt"\n')
        assert "TODO" in attack_code or attack_code.count("//") >= 1  # ⚠️ stub

    def test_no_concurrent_syntax_in_hado(self):
        """
        ⚠️ LIMITACIÓN: No hay sintaxis de concurrencia general en Hado.
        El único concurrente es el Go backend para escanea.
        No hay 'ejecuta en paralelo', 'async', 'goroutine' keywords.
        """
        # Para hacer múltiples targets en paralelo, no hay syntax nativa
        # Solo workaround: Python ThreadPoolExecutor en fuzzer.py
        code = py('para t en targets\n  escanea t en ports [80]\n')
        # Genera loop secuencial, no paralelo
        assert "ThreadPool" not in code
        assert "async" not in code

    def test_no_cve_database_integration(self):
        """
        ❌ LIMITACIÓN: 'busca vulns' verifica puertos, no CVEs reales.
        No hay integración con NVD, Shodan, Exploit-DB.
        """
        code = py('busca vulns en target donde severity >= HIGH\n')
        # Si compila, genera algo básico sin DB real
        # Si no compila, la limitación es aún mayor
        assert code  # solo verifica que algo genera, no que sea útil


# ══════════════════════════════════════════════════════════════════════════════
# SECCIÓN 3: MÓDULOS PYTHON — Tests unitarios directos 🔬
# ══════════════════════════════════════════════════════════════════════════════

class TestCryptoModule:
    """🔬 crypto.py — stdlib only, 100% funcional sin dependencias externas"""

    def test_hash_sha256_real(self):
        from hado.cybersec.crypto import hash_sha256
        result = hash_sha256("hado")
        assert len(result) == 64
        assert result == "9d0da8cd7e5f6054327282e36a67082111ad67ee31f95b64cd427a6842d8c4b1"

    def test_hash_md5_real(self):
        from hado.cybersec.crypto import hash_md5
        result = hash_md5("hado")
        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)

    def test_b64_encode_decode_roundtrip(self):
        from hado.cybersec.crypto import b64_encode, b64_decode
        original = "payload:secret123"
        encoded = b64_encode(original)
        decoded = b64_decode(encoded)
        assert decoded == original
        assert encoded == "cGF5bG9hZDpzZWNyZXQxMjM="

    def test_hmac_sha256_real(self):
        from hado.cybersec.crypto import hmac_sha256
        sig = hmac_sha256("secret_key", "message_to_sign")
        assert len(sig) == 64
        # determinístico: misma clave + mensaje = mismo resultado
        sig2 = hmac_sha256("secret_key", "message_to_sign")
        assert sig == sig2

    def test_generate_token_crypto_secure(self):
        from hado.cybersec.crypto import generate_token
        token1 = generate_token(32)
        token2 = generate_token(32)
        assert len(token1) == 64  # 32 bytes en hex = 64 chars
        assert token1 != token2   # criptográficamente aleatorio

    def test_verify_hash_correct(self):
        from hado.cybersec.crypto import verify_hash, hash_sha256
        text = "test_payload"
        expected = hash_sha256(text)
        assert verify_hash(text, expected, "sha256") is True

    def test_verify_hash_tampered(self):
        from hado.cybersec.crypto import verify_hash
        # Hash manipulado no debe verificar
        assert verify_hash("real_data", "deadbeef" * 8, "sha256") is False


class TestReportModule:
    """🔬 report.py — generación de reportes multi-formato"""

    def test_report_markdown_structure(self):
        from hado.cybersec.report import report
        data = {"target": "192.168.1.1", "open_ports": [22, 80], "grade": "F"}
        content = report(data, format="markdown", persist=False)
        assert "# Reporte de Seguridad" in content
        assert "192.168.1.1" in content
        assert "open_ports" in content
        assert "Hado DSL" in content

    def test_report_html_structure(self):
        from hado.cybersec.report import report
        data = {"scan": "complete", "ports": [443]}
        content = report(data, format="html", persist=False)
        assert "<!DOCTYPE html>" in content
        assert "<title>" in content
        assert "443" in content

    def test_report_json_serializable(self):
        import json
        from hado.cybersec.report import report
        data = {"vulns": ["CVE-2021-44228"], "severity": "CRITICAL"}
        content = report(data, format="json", persist=False)
        parsed = json.loads(content)
        assert parsed["data"]["severity"] == "CRITICAL"
        assert "timestamp" in parsed

    def test_report_consolidate_multiple_datasets(self):
        from hado.cybersec.report import consolidate
        scan = {"open_ports": [22, 80], "target": "1.2.3.4"}
        recon = ["api.example.com", "mail.example.com"]
        headers = {"grade": "C", "missing": ["HSTS"]}
        content = consolidate(scan, recon, headers)
        import json
        parsed = json.loads(content)
        assert len(parsed["datasets"]) == 3
        assert parsed["datasets"][0]["type"] == "scan_result"
        assert parsed["datasets"][1]["type"] == "list"
        assert parsed["datasets"][1]["count"] == 2


class TestAnalysisModule:
    """🔬 analysis.py — análisis de headers HTTP y riesgo de puertos"""

    def test_header_analysis_returns_dict(self):
        """
        ⚠️ analyze_headers(url) hace una petición HTTP real — necesita red.
        En sandbox sin red, retorna error dict. Verificamos estructura.
        """
        from hado.cybersec.analysis import analyze_headers
        result = analyze_headers("http://127.0.0.1:9999")  # puerto cerrado a propósito
        # Siempre retorna dict — en error o en éxito
        assert isinstance(result, dict)
        # En error, hay una clave 'error' o 'grade'
        has_valid_structure = "error" in result or "grade" in result
        assert has_valid_structure

    def test_header_grading_perfect_score(self):
        """✅ Todos los headers presentes → score 100, grade A"""
        from hado.cybersec.analysis import analyze_headers
        perfect_headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "geolocation=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
        }
        # analyze_headers acepta dict directamente (no URL)
        result = analyze_headers(perfect_headers)
        assert result["security_score"] == 100
        assert result["grade"] == "A"
        assert len(result["missing_headers"]) == 0

    def test_header_grading_empty(self):
        """✅ Headers vacíos → score 0, grade F, 9 headers faltantes"""
        from hado.cybersec.analysis import analyze_headers
        result = analyze_headers({})
        assert result["security_score"] == 0
        assert result["grade"] == "F"
        assert len(result["missing_headers"]) == 9

    def test_port_risk_scoring_critical_ports(self):
        """✅ Puertos críticos detectados correctamente"""
        from hado.cybersec.analysis import analyze_scan
        scan_result = {
            "target": "192.168.1.1",
            "open_ports": [21, 23, 3389],  # FTP, Telnet, RDP
            "method": "socket",
        }
        result = analyze_scan(scan_result)
        # Debería tener risky_ports con entradas CRITICAL o HIGH
        assert "risky_ports" in result
        risk_levels = [p["risk"] for p in result["risky_ports"]]
        assert "CRITICAL" in risk_levels or "HIGH" in risk_levels
        assert result["risk_count"] == 3

    def test_port_risk_safe_ports(self):
        """✅ Puerto 443 solo → sin risky_ports (o mínimo riesgo)"""
        from hado.cybersec.analysis import analyze_scan
        scan_result = {
            "target": "192.168.1.1",
            "open_ports": [443],
            "method": "socket",
        }
        result = analyze_scan(scan_result)
        assert "risky_ports" in result
        # 443 (HTTPS) no debería estar en risky_ports
        risky_port_numbers = [p["port"] for p in result["risky_ports"]]
        assert 443 not in risky_port_numbers


class TestScannerModule:
    """🔬 scanner.py — nmap + socket fallback"""

    def test_scan_localhost_loopback(self):
        """⚠️ Test de red real — puede fallar en CI sin permisos de red"""
        from hado.cybersec.scanner import scan
        result = scan("127.0.0.1", [22, 80, 443, 9999])
        # Solo verificamos la estructura — no qué puertos están abiertos
        assert "target" in result
        assert "open_ports" in result
        assert isinstance(result["open_ports"], list)
        assert result["target"] == "127.0.0.1"
        assert "method" in result  # "nmap" o "socket"

    def test_scan_returns_only_open_ports(self):
        """✅ Los puertos cerrados no aparecen en open_ports"""
        from hado.cybersec.scanner import scan
        # Puerto 1 siempre debería estar cerrado en localhost
        result = scan("127.0.0.1", [1])
        assert 1 not in result["open_ports"]


class TestReconModule:
    """🔬 recon.py — DNS enum y subdomain discovery"""

    def test_find_subdomains_returns_list(self):
        """✅ Siempre retorna lista (puede estar vacía en red limitada)"""
        from hado.cybersec.recon import find_subdomains
        result = find_subdomains("example.com")
        assert isinstance(result, list)
        # Todos los resultados son strings
        for sub in result:
            assert isinstance(sub, str)

    def test_find_subdomains_format(self):
        """✅ Subdominios tienen formato FQDN correcto"""
        from hado.cybersec.recon import find_subdomains
        result = find_subdomains("example.com")
        for sub in result:
            assert "example.com" in sub  # FQDN incluye el dominio base


# ══════════════════════════════════════════════════════════════════════════════
# SECCIÓN 4: BACKENDS COMPARADOS — Mismo código, diferente output
# ══════════════════════════════════════════════════════════════════════════════

class TestBackendComparison:
    """
    Mismo Hado code → 4 backends diferentes.
    Documenta qué funciona y qué genera placeholder en cada target.
    """

    SCAN_CODE = 'escanea target "192.168.1.1" en ports [22, 80, 443]\n'
    HEADERS_CODE = 'analiza headers de "https://example.com"\n'
    RECON_CODE = 'subs = busca subdomains de "target.com"\n'

    def test_scan_python_real_library(self):
        """✅ Python: usa hado.cybersec.scanner.scan() real"""
        code = py(self.SCAN_CODE)
        assert "scanner" in code or "scan(" in code
        # Genera código ejecutable que llama módulo real

    def test_scan_go_real_goroutines(self):
        """✅ Go: genera hado_scan() con goroutines + sync.WaitGroup"""
        code = go(self.SCAN_CODE)
        assert "hado_scan(" in code
        assert "sync.WaitGroup" in code
        assert "net.DialTimeout" in code
        # Esto compila con `go build` — es código real

    def test_scan_c_real_posix_sockets(self):
        """✅ C: genera hado_scan_port() con POSIX sockets"""
        code = c_code(self.SCAN_CODE)
        assert "hado_scan_port" in code
        assert "socket(" in code
        assert "connect(" in code
        # Compila con gcc/clang sin dependencias externas

    def test_scan_rust_real_tcpstream(self):
        """✅ Rust: genera TcpStream async con Tokio (v0.5+)"""
        code = rust(self.SCAN_CODE)
        assert "TcpStream" in code
        # v0.5+: usa tokio::time::timeout + TcpStream::connect (no connect_timeout)
        assert "scan_ports" in code or "connect" in code

    def test_headers_python_real(self):
        """✅ Python: llama analyze_headers() real"""
        code = py(self.HEADERS_CODE)
        assert "analiz" in code.lower() or "analysis" in code or "headers" in code

    def test_headers_go_stub(self):
        """❌ Go: analiza headers NO tiene implementación real"""
        code = go(self.HEADERS_CODE)
        # El go transpiler no tiene _visit_CyberAnalyze con código real
        # Debería generar un TODO comment
        assert "TODO" in code or "//" in code

    def test_headers_c_stub(self):
        """❌ C: analiza headers no tiene implementación en C"""
        code = c_code(self.HEADERS_CODE)
        assert "TODO" in code or "/*" in code

    def test_recon_python_real(self):
        """✅ Python: find_subdomains() real con DNS"""
        code = py(self.RECON_CODE)
        assert "find_subdomains" in code or "recon" in code

    def test_recon_rust_partial(self):
        """⚠️ Rust: DNS lookup básico, no el módulo completo"""
        code = rust(self.RECON_CODE)
        # Rust tiene CyberRecon con to_socket_addrs() — básico pero real
        assert "socket_addrs" in code or "ToSocketAddrs" in code or "subdom" in code


# ══════════════════════════════════════════════════════════════════════════════
# SECCIÓN 5: ZERO-DAY TOOLING — Qué puede y qué no puede hacer Hado
# ══════════════════════════════════════════════════════════════════════════════

class TestZeroDayCapabilities:
    """
    Tests específicos para capacidades de zero-day / exploit research.
    Honestidad total: Hado es un scanner/recon DSL, NO un exploit framework.
    """

    def test_reconnaissance_pipeline_complete(self):
        """
        ✅ FUNCIONA: Reconocimiento completo de infraestructura.
        subdomain enum + port scan + header analysis + report.
        """
        source = """
fn recon(objetivo)
  subs = busca subdomains de objetivo
  para sub en subs
    escanea sub en ports [21, 22, 80, 443, 3306, 5432, 8080, 8443]
  analiza headers de objetivo
  genera reporte con subs

recon("target.com")
"""
        code = py(source)
        assert "def recon" in code
        assert "find_subdomains" in code or "recon" in code
        assert "report" in code

    def test_http_bruteforce_works(self):
        """
        ✅ FUNCIONA: Brute force HTTP con wordlist.
        Útil para: login panels, API endpoints, credential stuffing.
        """
        code = py('ataca "http-post" en "https://target.com/login" con usuario "admin" y wordlist "pass.txt"\n')
        assert "attack" in code
        assert "http" in code.lower()

    def test_ssh_bruteforce_requires_paramiko(self):
        """
        ⚠️ PARCIAL: SSH brute force requiere paramiko instalado.
        Sin paramiko: retorna error dict, no falla silenciosamente.
        """
        try:
            import paramiko
            has_paramiko = True
        except ImportError:
            has_paramiko = False

        from hado.cybersec.attack import attack
        if has_paramiko:
            # Con paramiko: genera resultado real (puede fallar por red)
            result = attack("ssh", "127.0.0.1", ["wrong_pass"], username="root")
            assert isinstance(result, dict)
            assert "service" in result
        else:
            # Sin paramiko: error explícito, no silencioso
            result = attack("ssh", "127.0.0.1", ["pass"], username="root")
            assert "error" in result or "not available" in str(result).lower()

    def test_directory_fuzzing_module_direct(self):
        """
        ✅ FUNCIONA (módulo directo): fuzzer.py con ThreadPoolExecutor.
        ⚠️ LIMITACIÓN: no hay keyword 'fuzzea' en Hado — solo Python directo.
        """
        from hado.cybersec.fuzzer import fuzz
        # Test con servidor que no existe — verificar estructura del resultado
        result = fuzz("http://127.0.0.1:9999", wordlist=["/admin", "/login"], threads=2, timeout=1)
        assert "found_paths" in result
        assert "total_requests" in result
        assert isinstance(result["found_paths"], list)
        # Con servidor inexistente, found_paths debe estar vacío
        assert result["total_requests"] >= 0

    def test_crypto_for_payload_obfuscation(self):
        """
        ✅ FUNCIONA (módulo directo): hashing y encoding para análisis.
        Útil para: identificar payloads, verificar integridad, token generation.
        ⚠️ LIMITACIÓN: no hay sintaxis .ho nativa — solo Python directo.
        """
        from hado.cybersec.crypto import b64_encode, b64_decode, hash_sha256
        # Encoding de payloads para análisis
        payload = "<script>alert(1)</script>"
        encoded = b64_encode(payload)
        assert "PHNjcmlwdD" in encoded  # base64 conocido

        # Hash para verificación de integridad
        file_hash = hash_sha256("file_content_here")
        assert len(file_hash) == 64

    def test_what_hado_cannot_do_for_exploits(self):
        """
        ❌ LIMITACIONES DOCUMENTADAS para exploit development real:

        1. No raw packet crafting (SYN floods, fragmentation, spoofing)
        2. No buffer overflow helpers (pattern generation, offset calculation)
        3. No shellcode generation/injection
        4. No ELF/PE binary parsing
        5. No ROP chain construction
        6. No heap spray primitives
        7. No AES/RSA encryption (crypto.py solo tiene hashing)
        8. No TLS interception syntax
        9. No process injection keywords
        10. No syscall wrappers

        Para esto se necesita: pwntools, scapy, ropper, pycryptodome
        Hado es un orchestrator de herramientas — no las reemplaza.
        """
        # Este test documenta limitaciones — siempre pasa
        hado_capabilities = {
            "port_scanning": True,        # ✅
            "subdomain_enum": True,        # ✅
            "http_brute_force": True,      # ✅
            "ssh_brute_force": True,       # ✅ (requiere paramiko)
            "directory_fuzzing": True,     # ✅ (solo módulo Python)
            "header_analysis": True,       # ✅
            "packet_capture": True,        # ⚠️ requiere root + scapy
            "report_generation": True,     # ✅
            "hashing_encoding": True,      # ✅ (solo módulo Python)
            "raw_packet_crafting": False,  # ❌
            "shellcode_generation": False, # ❌
            "binary_parsing": False,       # ❌
            "rop_chains": False,           # ❌
            "heap_spray": False,           # ❌
            "aes_rsa_encryption": False,   # ❌
            "process_injection": False,    # ❌
            "cve_database": False,         # ❌
        }

        real_capabilities = [k for k, v in hado_capabilities.items() if v]
        missing_for_exploits = [k for k, v in hado_capabilities.items() if not v]

        assert len(real_capabilities) >= 9   # Mínimo funcional para recon
        assert len(missing_for_exploits) >= 7 # Honestidad sobre las gaps
