"""Tamper detection (spec item 5).

Any change to the sealed file must be caught at open: payload changes are
VaultTamperedError, broken magic/version/header are VaultFormatError, and
damage to the wrapped-key material means the vault simply cannot open
(an AegisError).
"""

import pytest

from aegis import Vault
from aegis.errors import AegisError, VaultFormatError, VaultTamperedError

from conftest import PASSWORD, flip_byte, load_header, pattern_bytes


@pytest.fixture
def sealed_vault(create_vault):
    created, path = create_vault(
        {"notes.txt": pattern_bytes(5000, seed=7),
         "papers/tax-2026.txt": pattern_bytes(2000, seed=8)}
    )
    created.session.lock()
    return path


def test_flip_payload_byte_detected(sealed_vault):
    _, _, payload_offset = load_header(sealed_vault)
    flip_byte(sealed_vault, payload_offset + 10)
    with pytest.raises(VaultTamperedError):
        Vault.open(sealed_vault, password=PASSWORD)


def test_flip_last_payload_byte_detected(sealed_vault):
    size = len(sealed_vault.read_bytes())
    flip_byte(sealed_vault, size - 1)  # inside the final chunk's auth tag
    with pytest.raises(VaultTamperedError):
        Vault.open(sealed_vault, password=PASSWORD)


def _flip_header_value_char(path, section, field, char_index=10):
    """Flip one character inside a base64 value in the header JSON,
    keeping the JSON and the base64 both well-formed."""
    data, header, _ = load_header(path)
    value = header[section][field].encode("utf-8")
    start = data.find(value)
    assert start >= 0
    pos = start + char_index
    original = data[pos:pos + 1]
    replacement = b"A" if original != b"A" else b"B"
    mutated = data[:pos] + replacement + data[pos + 1:]
    path.write_bytes(mutated)


def test_flip_wrapped_key_byte_cannot_open(sealed_vault):
    _flip_header_value_char(sealed_vault, "password_wrap", "wrapped_key")
    with pytest.raises(AegisError):
        Vault.open(sealed_vault, password=PASSWORD)


def test_flip_password_salt_byte_cannot_open(sealed_vault):
    _flip_header_value_char(sealed_vault, "password_wrap", "salt")
    with pytest.raises(AegisError):
        Vault.open(sealed_vault, password=PASSWORD)


def test_flip_magic_byte_is_format_error(sealed_vault):
    flip_byte(sealed_vault, 0)
    with pytest.raises(VaultFormatError):
        Vault.open(sealed_vault, password=PASSWORD)


def test_flip_version_byte_is_format_error(sealed_vault):
    flip_byte(sealed_vault, 9)  # low byte of the uint16 format version
    with pytest.raises(VaultFormatError):
        Vault.open(sealed_vault, password=PASSWORD)


def test_corrupt_header_json_is_format_error(sealed_vault):
    data = bytearray(sealed_vault.read_bytes())
    data[14] = ord("x")  # first header byte: '{' -> 'x' breaks the JSON
    sealed_vault.write_bytes(bytes(data))
    with pytest.raises(VaultFormatError):
        Vault.open(sealed_vault, password=PASSWORD)


@pytest.mark.parametrize(
    "keep",
    ["tiny", "header-cut", "half", "minus-one-byte"],
)
def test_truncated_file_refused(sealed_vault, keep):
    data = sealed_vault.read_bytes()
    if keep == "tiny":
        new = data[:4]
    elif keep == "header-cut":
        new = data[:20]
    elif keep == "half":
        new = data[:len(data) // 2]
    else:
        new = data[:-1]
    sealed_vault.write_bytes(new)
    with pytest.raises(AegisError):
        Vault.open(sealed_vault, password=PASSWORD)
