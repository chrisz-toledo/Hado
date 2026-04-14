"""
hado.cybersec.crypto — Hashing, encoding, and cryptographic utilities.

Imported automatically by the Python transpiler when crypto operations are used.
"""

from __future__ import annotations
import hashlib
import base64
import hmac
import secrets


def hash_md5(text: str) -> str:
    """Calculate MD5 hash of a string. Not for security — use for checksums."""
    return hashlib.md5(text.encode()).hexdigest()


def hash_sha1(text: str) -> str:
    """Calculate SHA-1 hash of a string."""
    return hashlib.sha1(text.encode()).hexdigest()


def hash_sha256(text: str) -> str:
    """Calculate SHA-256 hash of a string."""
    return hashlib.sha256(text.encode()).hexdigest()


def hash_sha512(text: str) -> str:
    """Calculate SHA-512 hash of a string."""
    return hashlib.sha512(text.encode()).hexdigest()


def b64_encode(data: str) -> str:
    """Base64-encode a string."""
    return base64.b64encode(data.encode()).decode()


def b64_decode(data: str) -> str:
    """Decode a base64-encoded string."""
    return base64.b64decode(data.encode()).decode()


def hmac_sha256(key: str, message: str) -> str:
    """Compute HMAC-SHA256 signature."""
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def generate_token(length: int = 32) -> str:
    """Generate a cryptographically secure random hex token."""
    return secrets.token_hex(length)


def verify_hash(text: str, expected: str, algorithm: str = "sha256") -> bool:
    """Verify that a text matches an expected hash."""
    algos = {
        "md5": hash_md5,
        "sha1": hash_sha1,
        "sha256": hash_sha256,
        "sha512": hash_sha512,
    }
    fn = algos.get(algorithm.lower())
    if fn is None:
        raise ValueError(f"Algoritmo no soportado: {algorithm}")
    return fn(text) == expected
