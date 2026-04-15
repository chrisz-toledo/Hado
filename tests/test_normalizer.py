"""Tests para el normalizador de caracteres ASCII."""

import pytest
from habla.normalizer import normalize


def test_basic_substitutions():
    assert normalize("funcion") == "funcion"
    assert normalize("función") == "funcion"
    assert normalize("año") == "anho"
    assert normalize("Año") == "Anho"


def test_all_vowels():
    assert normalize("á") == "a"
    assert normalize("é") == "e"
    assert normalize("í") == "i"
    assert normalize("ó") == "o"
    assert normalize("ú") == "u"
    assert normalize("ü") == "u"
    assert normalize("Á") == "A"
    assert normalize("É") == "E"
    assert normalize("Í") == "I"
    assert normalize("Ó") == "O"
    assert normalize("Ú") == "U"


def test_ignore_punctuation():
    assert normalize("¿que?") == "que?"
    assert normalize("¡hola!") == "hola!"


def test_preserves_string_literals():
    # El contenido de strings NO debe normalizarse
    source = 'muestra "Año nuevo"'
    result = normalize(source)
    assert '"Año nuevo"' in result
    assert "muestra" in result


def test_preserves_string_single_quotes():
    source = "muestra 'España'"
    result = normalize(source)
    assert "'España'" in result


def test_normalizes_code_not_strings():
    source = 'función = "función"'
    result = normalize(source)
    # La variable debe normalizarse
    assert result.startswith("funcion")
    # El string literal debe preservarse
    assert '"función"' in result


def test_empty_string():
    assert normalize("") == ""


def test_ascii_unchanged():
    code = "si x >= 10\n  muestra x"
    assert normalize(code) == code
