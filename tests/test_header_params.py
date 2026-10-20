"""Header parameter integrity (spec item 10).

A created vault records the default KDF params (65536 KiB / 3 / 4).  Edited
headers must never silently open: out-of-range values are VaultFormatError,
and an in-range but *changed* value derives a different key, so the open
fails instead of succeeding.
"""

import base64

import pytest

from aegis import Vault
from aegis.errors import AegisError, VaultFormatError
from aegis.format import CHUNK_SIZE, FORMAT_VERSION, MAGIC

from conftest import FAST_PARAMS, PASSWORD, load_header, rewrite_header


def test_default_vault_records_default_params(vault_path):
    created = Vault.create(vault_path, PASSWORD)  # no params -> defaults
    created.session.lock()

    data, header, _ = load_header(vault_path)
    assert data[:8] == MAGIC == b"AEGISVLT"
    assert int.from_bytes(data[8:10], "big") == FORMAT_VERSION == 1
    assert header["format"] == 1
    assert header["kdf"]["memory_kib"] == 65536
    assert header["kdf"]["time_cost"] == 3
    assert header["kdf"]["parallelism"] == 4
    assert header["kdf"]["hash_len"] == 32
    assert header["payload"]["chunk_size"] == CHUNK_SIZE == 1048576
    # Wrap material shapes per spec: 16-byte salts, 12-byte nonces,
    # 48-byte wrapped keys (32-byte key + 16-byte tag).
    for section in ("password_wrap", "recovery_wrap"):
        assert len(base64.b64decode(header[section]["salt"])) == 16
        assert len(base64.b64decode(header[section]["nonce"])) == 12
        assert len(base64.b64decode(header[section]["wrapped_key"])) == 48
    assert len(base64.b64decode(header["payload"]["nonce_prefix"])) == 8


def test_default_params_full_roundtrip(vault_path):
    created = Vault.create(vault_path, PASSWORD)  # full-strength defaults
    created.session.write("notes.txt", b"default-strength contents")
    created.session.save()
    created.session.lock()

    session = Vault.open(vault_path, password=PASSWORD)
    assert session.read("notes.txt") == b"default-strength contents"
    session.lock()


def test_fast_params_recorded_when_requested(vault_path):
    created = Vault.create(vault_path, PASSWORD, params=FAST_PARAMS)
    created.session.lock()
    _, header, _ = load_header(vault_path)
    assert header["kdf"]["memory_kib"] == 8192
    assert header["kdf"]["time_cost"] == 1
    assert header["kdf"]["parallelism"] == 1


def test_memory_edited_down_refused(vault_path):
    """65536 -> 32768 KiB is in range, but it is not the vault's params:
    the open must fail, never silently succeed."""
    created = Vault.create(vault_path, PASSWORD)
    created.session.lock()

    _, header, _ = load_header(vault_path)
    header["kdf"]["memory_kib"] = 32768
    rewrite_header(vault_path, header)

    with pytest.raises(AegisError):
        Vault.open(vault_path, password=PASSWORD)


@pytest.mark.parametrize(
    "field,value",
    [
        ("memory_kib", 8191),        # below the 8192 KiB floor
        ("memory_kib", 1048577),     # above the 1 GiB ceiling (item 10c)
        ("memory_kib", 2097152),     # far above the ceiling
        ("time_cost", 0),            # item 10d
        ("time_cost", 11),           # above the ceiling of 10
        ("parallelism", 0),
        ("parallelism", 17),         # above the ceiling of 16
    ],
)
def test_out_of_range_kdf_params_are_format_error(create_vault, field, value):
    created, path = create_vault()
    created.session.lock()

    _, header, _ = load_header(path)
    header["kdf"][field] = value
    rewrite_header(path, header)

    with pytest.raises(VaultFormatError):
        Vault.open(path, password=PASSWORD)


def test_shortened_salt_refused(create_vault):
    """Salt below the 16-byte floor -> VaultFormatError on open."""
    created, path = create_vault()
    created.session.lock()

    _, header, _ = load_header(path)
    header["password_wrap"]["salt"] = base64.b64encode(b"8 bytes!").decode()
    rewrite_header(path, header)

    with pytest.raises(VaultFormatError):
        Vault.open(path, password=PASSWORD)
