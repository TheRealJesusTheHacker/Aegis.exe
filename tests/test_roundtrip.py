"""Create/open round-trips (spec items 1-3).

Entries of many sizes — including exactly the 1 MiB chunk size and one byte
over — must come back byte-exact after lock + reopen.
"""

import os

import pytest

from aegis import Vault
from aegis.format import CHUNK_SIZE

from conftest import PASSWORD, pattern_bytes


@pytest.mark.parametrize(
    "size",
    [0, 1, 100, CHUNK_SIZE, CHUNK_SIZE + 1],
    ids=["empty", "one-byte", "100b", "exactly-chunk", "chunk-plus-one"],
)
def test_single_entry_roundtrip(create_vault, size):
    data = pattern_bytes(size, seed=size % 251)
    created, path = create_vault({"only.bin": data})
    created.session.lock()

    session = Vault.open(path, password=PASSWORD)
    assert session.names() == ["only.bin"]
    got = session.read("only.bin")
    assert isinstance(got, bytes)
    assert got == data
    session.lock()


def test_multiple_entries_about_three_mib(create_vault):
    entries = {
        "notes.txt": pattern_bytes(100, seed=1),
        "papers/tax-2026.txt": pattern_bytes(CHUNK_SIZE, seed=2),
        "papers/receipts/coffee.txt": pattern_bytes(CHUNK_SIZE, seed=3),
        "archive/blob.bin": pattern_bytes(CHUNK_SIZE - 100, seed=4),
        "tiny": pattern_bytes(1, seed=5),
        "zero-length": b"",
    }
    total = sum(len(v) for v in entries.values())
    assert 2 * CHUNK_SIZE < total < 4 * CHUNK_SIZE  # ~3 MiB across entries

    created, path = create_vault(entries)
    created.session.lock()

    session = Vault.open(path, password=PASSWORD)
    assert sorted(session.names()) == sorted(entries)
    for name, expected in entries.items():
        assert session.read(name) == expected
    session.lock()


def test_large_single_entry_eight_mib(create_vault):
    data = pattern_bytes(8 * CHUNK_SIZE, seed=99)
    created, path = create_vault({"big-file.bin": data})
    created.session.lock()

    session = Vault.open(path, password=PASSWORD)
    assert session.read("big-file.bin") == data
    session.lock()


def test_empty_vault_roundtrip(create_vault):
    created, path = create_vault()
    created.session.lock()

    session = Vault.open(path, password=PASSWORD)
    assert session.names() == []
    session.lock()


def test_random_bytes_byte_exact(create_vault):
    entries = {
        "rand/small.bin": os.urandom(257),
        "rand/medium.bin": os.urandom(65_537),
    }
    created, path = create_vault(entries)
    created.session.lock()

    session = Vault.open(path, password=PASSWORD)
    for name, expected in entries.items():
        assert session.read(name) == expected
    session.lock()


def test_overwrite_entry(create_vault):
    created, path = create_vault({"doc.txt": b"first version"})
    session = created.session
    session.write("doc.txt", b"second version, longer")
    session.save()
    session.lock()

    reopened = Vault.open(path, password=PASSWORD)
    assert reopened.read("doc.txt") == b"second version, longer"
    reopened.lock()


def test_remove_entry_persists(create_vault):
    created, path = create_vault({"keep.txt": b"stay", "gone.txt": b"leave"})
    session = created.session
    session.remove("gone.txt")
    session.save()
    assert session.names() == ["keep.txt"]
    session.lock()

    reopened = Vault.open(path, password=PASSWORD)
    assert reopened.names() == ["keep.txt"]
    assert reopened.read("keep.txt") == b"stay"
    reopened.lock()
