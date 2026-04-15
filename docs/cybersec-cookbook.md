# Habla Cybersecurity Cookbook

Common cybersecurity recipes in Habla. All examples require authorization on the target systems.

**Warning**: Only use these tools on systems you own or have explicit authorization to test.

---

## Reconnaissance

### Subdomain enumeration
```habla
dominio = "target.com"
subs = busca subdomains de dominio
muestra "Subdominios encontrados: " + cuenta subs
para s en subs
  muestra "  " + s
guarda subs en "subs.txt"
```

### Quick port scan
```habla
escanea target "192.168.1.1" en ports [21, 22, 23, 25, 80, 443, 3306, 5432, 8080, 8443]
```

### Scan with variable target
```habla
ip = "10.0.0.1"
escanea ip en ports [22, 80, 443]
```

### Full OSINT pipeline
```habla
dominio = "target.com"

// Fase 1: Subdominios vivos
subs = busca subdomains de dominio

// Fase 2: Puertos en cada subdominio
para sub en subs
  muestra "Escaneando " + sub
  escanea sub en ports [80, 443, 8080, 8443, 8888]

// Reporte
genera reporte con subs
```

### Multi-target scan
```habla
targets = ["192.168.1.1", "192.168.1.2", "192.168.1.254", "10.0.0.1"]

para ip en targets
  muestra "Escaneando " + ip
  escanea ip en ports [22, 80, 443, 3389, 8080]
```

---

## Web Application Testing

### Analizar headers de seguridad
```habla
url = "https://target.com"
analiza headers de url
```

This checks for: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy, Cache-Control, and Pragma. Returns a score (0-100) and grade (A-F).

### HTTP data retrieval
```habla
datos = desde "https://api.target.com/v1/users"
muestra datos
```

### Fuzzing de parametros HTTP
```habla
payloads = ["' OR 1=1--", "<script>alert(1)</script>", "../../../etc/passwd"]
base_url = "https://target.com/search?q="

para payload en payloads
  url = base_url + payload
  muestra "Probando: " + url
  respuesta = desde url
  muestra "Respuesta: " + respuesta
```

---

## Network Analysis

### Captura de trafico HTTP
```habla
captura packets en interface "eth0" donde "tcp port 80"
```

Uses scapy if available, falls back to tcpdump. Returns a list of packet summaries.

### Captura de trafico HTTPS
```habla
captura packets en interface "en0" donde "tcp port 443"
```

### Captura con conteo limitado
```habla
captura 50 packets en interface "wlan0" donde "udp"
```

---

## Credential Testing

### Brute force SSH
```habla
// SOLO en entornos autorizados
target = "192.168.1.100"
ataca "ssh" en target con wordlist "rockyou.txt"
```

Uses paramiko for SSH connections. Tests each password in the wordlist against the default user "admin".

### Brute force con usuario especifico
```habla
ataca "ssh" en "192.168.1.100" con usuario "root" y wordlist "passwords.txt"
```

### Brute force HTTP login
```habla
// SOLO en entornos autorizados
ataca "http" en "https://target.com/login" con usuario "admin" y wordlist "passwords.txt"
```

### Brute force FTP
```habla
ataca "ftp" en "192.168.1.50" con wordlist "common-passwords.txt"
```

---

## Cryptography (via Python module)

The `habla.cybersec.crypto` module is available in generated Python code:

```python
# In your generated Python, you can import directly:
from habla.cybersec.crypto import hash_sha256, b64_encode, generate_token, verify_hash

# Hash a password
h = hash_sha256("password123")

# Generate a secure token
token = generate_token(32)

# Verify a hash
ok = verify_hash("password123", h, "sha256")

# Base64 encode
encoded = b64_encode("sensitive data")
```

Native Habla syntax for crypto (`sha256 de "text"`) is coming in v0.2.

---

## Reporting

### Reporte simple
```habla
genera reporte con resultados
```

### Reporte con output a archivo
```habla
genera reporte con resultados -> guarda "security-report.md"
```

### Assessment completo con reporte
```habla
fn assessment(dominio)
  muestra "=== Security Assessment: " + dominio + " ==="

  // Recon
  subs = busca subdomains de dominio
  muestra "Subdominios: " + cuenta subs

  // Scan
  para sub en subs
    escanea sub en ports [80, 443, 22, 3306]

  // Headers
  analiza headers de dominio

  // Reporte
  genera reporte con subs
  muestra "Assessment completado para " + dominio

assessment("target.com")
```

---

## Pipes — Data Flow Recipes

### Recon to report pipeline
```habla
busca subdomains de "target.com" -> filtra alive -> genera reporte
```

### Filter and sort
```habla
datos -> filtra donde score > 50 -> ordena por nombre -> muestra
```

### Count results
```habla
subs = busca subdomains de "target.com"
muestra "Total: " + cuenta subs
```

---

## Multi-target compilation

Every recipe in this cookbook compiles to all four backends:

```bash
habla compile recipe.habla                  # Python (executable)
habla compile --target go recipe.habla      # Go (concurrent stubs)
habla compile --target c recipe.habla       # C (low-level sockets)
habla compile --target rust recipe.habla    # Rust (memory-safe)
```

Python is fully functional. Go, C, and Rust generate compilable code with comments pointing to the appropriate libraries for each platform.
