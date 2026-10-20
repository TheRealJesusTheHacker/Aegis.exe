"""Shared fixtures and helpers for the Aegis vault-core test suite.

Tests are written against the Phase 1 design spec (DESIGN.md), not against
the implementation.  All data is synthetic: deterministic patterned bytes and
fake entry names.  No real credentials or user data anywhere.

Most tests use small KDF params (8192 KiB / 1 / 1 — exactly the spec's
floors) so the suite stays fast; the default-param tests live in
test_header_params.py.
"""

import json
import pathlib
import sys

import pytest

# Make the repo root importable regardless of how pytest is invoked.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from aegis import Vault  # noqa: E402
from aegis.kdf import KdfParams  # noqa: E402

FAST_PARAMS = KdfParams(memory_kib=8192, time_cost=1, parallelism=1)

# Synthetic passphrases (fake, test-only).
PASSWORD = "synthetic master phrase one"
NEW_PASSWORD = "synthetic master phrase two"
WRONG_PASSWORD = "a completely wrong phrase"


def pattern_bytes(n, *, seed=0):
    """Deterministic synthetic bytes of length *n* (never real data)."""
    if n <= 0:
        return b""
    block = bytes(((i * 31 + seed * 17 + 7) % 256) for i in range(4096))
    return (block * (n // len(block) + 1))[:n]


@pytest.fixture
def fast_params():
    return FAST_PARAMS


@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "test-vault.aegis"


@pytest.fixture
def create_vault(tmp_path):
    """Factory: create a vault, optionally pre-filled with entries.

    Returns (CreatedVault, path).  Entries passed in are written and saved;
    the session is left open (unlocked).
    """

    def _create(entries=None, password=PASSWORD, name="vault.aegis",
                params=FAST_PARAMS):
        path = tmp_path / name
        created = Vault.create(path, password, params=params)
        if entries:
            for entry_name, data in entries.items():
                created.session.write(entry_name, data)
            created.session.save()
        return created, path

    return _create


# ---------------------------------------------------------------------------
# Raw file helpers (header parsing / byte flipping) for tamper + header tests.
# Layout per spec: MAGIC(8B) || version(uint16 BE) || header_len(uint32 BE)
# || header JSON || payload chunks.
# ---------------------------------------------------------------------------

def load_header(path):
    """Return (raw_file_bytes, header_dict, payload_offset)."""
    data = path.read_bytes()
    header_len = int.from_bytes(data[10:14], "big")
    header = json.loads(data[14:14 + header_len].decode("utf-8"))
    return data, header, 14 + header_len


def rewrite_header(path, header):
    """Write *header* back as JSON, fixing up header_len, keeping payload."""
    data = path.read_bytes()
    old_len = int.from_bytes(data[10:14], "big")
    payload = data[14 + old_len:]
    raw = json.dumps(header).encode("utf-8")
    path.write_bytes(data[:10] + len(raw).to_bytes(4, "big") + raw + payload)


def flip_byte(path, offset, mask=0xFF):
    data = bytearray(path.read_bytes())
    data[offset] ^= mask
    path.write_bytes(bytes(data))
