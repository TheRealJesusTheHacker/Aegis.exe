"""Session lifecycle (spec items 9, 11, 12).

Locking must block every operation and wipe the in-memory vault key; the
on-disk file is always a sealed vault holding only what was saved; a
password change re-wraps without touching the contents or the recovery path.
"""

import pytest

from aegis import Vault
from aegis.errors import VaultLockedError, WeakPasswordError, WrongPasswordError
from aegis.format import MAGIC

from conftest import NEW_PASSWORD, PASSWORD, WRONG_PASSWORD, pattern_bytes


# -- item 9: password change ---------------------------------------------------

def test_change_password(create_vault):
    created, path = create_vault({"notes.txt": b"contents stay put"})
    session = created.session
    session.change_password(NEW_PASSWORD)
    session.save()
    session.lock()

    with pytest.raises(WrongPasswordError):
        Vault.open(path, password=PASSWORD)

    reopened = Vault.open(path, password=NEW_PASSWORD)
    assert reopened.read("notes.txt") == b"contents stay put"
    reopened.lock()

    # The recovery key still opens the vault after a password change.
    by_recovery = Vault.open(path, recovery_key=created.recovery_key)
    assert by_recovery.read("notes.txt") == b"contents stay put"
    by_recovery.lock()


def test_change_password_too_short_refused(create_vault):
    created, _ = create_vault({"notes.txt": b"x"})
    with pytest.raises(WeakPasswordError):
        created.session.change_password("short")
    created.session.lock()


# -- item 11: lock --------------------------------------------------------------

def test_session_properties(create_vault):
    created, path = create_vault()
    session = created.session
    assert session.path == path
    assert session.is_locked is False
    session.lock()
    assert session.is_locked is True


def test_lock_blocks_all_operations(create_vault):
    created, _ = create_vault({"notes.txt": b"x"})
    session = created.session
    session.lock()
    assert session.is_locked is True

    with pytest.raises(VaultLockedError):
        session.names()
    with pytest.raises(VaultLockedError):
        session.read("notes.txt")
    with pytest.raises(VaultLockedError):
        session.write("new.txt", b"y")
    with pytest.raises(VaultLockedError):
        session.remove("notes.txt")
    with pytest.raises(VaultLockedError):
        session.save()
    with pytest.raises(VaultLockedError):
        session.change_password(NEW_PASSWORD)
    with pytest.raises(VaultLockedError):
        session.regenerate_recovery_key()


def _find_key_buffers(session):
    """White-box: collect bytearray attributes held by the session
    (the spec requires the vault key / KEKs to be held as bytearrays)."""
    buffers = []
    for value in vars(session).values():
        if isinstance(value, bytearray):
            buffers.append(value)
        elif hasattr(value, "__dict__"):
            for inner in vars(value).values():
                if isinstance(inner, bytearray):
                    buffers.append(inner)
    return buffers


def test_lock_zeroes_vault_key_buffer(create_vault):
    created, _ = create_vault({"notes.txt": b"x"})
    session = created.session

    candidates = [b for b in _find_key_buffers(session)
                  if len(b) == 32 and any(b)]
    assert candidates, "expected the live 32-byte vault key in memory"
    vault_key_buffer = candidates[0]

    session.lock()
    assert bytes(vault_key_buffer) == b"\x00" * 32


def test_lock_saves_dirty_changes(create_vault):
    created, path = create_vault()
    session = created.session
    session.write("unsaved.txt", b"written but never saved")
    session.lock()  # spec: lock() saves if dirty

    reopened = Vault.open(path, password=PASSWORD)
    assert reopened.read("unsaved.txt") == b"written but never saved"
    reopened.lock()


def test_reopen_after_lock_requires_credentials(create_vault):
    created, path = create_vault({"notes.txt": b"guarded"})
    created.session.lock()

    with pytest.raises(WrongPasswordError):
        Vault.open(path, password=WRONG_PASSWORD)

    session = Vault.open(path, password=PASSWORD)
    assert session.read("notes.txt") == b"guarded"
    session.lock()


def test_context_manager_locks_on_exit(create_vault):
    _, path = create_vault({"notes.txt": b"x"})
    with Vault.open(path, password=PASSWORD) as session:
        assert session.read("notes.txt") == b"x"
    assert session.is_locked is True
    with pytest.raises(VaultLockedError):
        session.read("notes.txt")


def test_close_locks_session(create_vault):
    created, _ = create_vault({"notes.txt": b"x"})
    session = created.session
    session.close()
    assert session.is_locked is True
    with pytest.raises(VaultLockedError):
        session.read("notes.txt")


# -- item 12: the disk file is always sealed, holding only saved state ----------

def test_disk_file_sealed_while_session_open(create_vault):
    created, path = create_vault()
    session = created.session

    marker = b"TOPSECRET-PLAINTEXT-MARKER-12345"
    session.write("secret-diary.txt", marker)
    session.save()

    # A second open on the same path reads exactly the saved contents.
    second = Vault.open(path, password=PASSWORD)
    assert second.read("secret-diary.txt") == marker
    second.lock()

    # Unsaved changes are NOT in the file.
    session.write("draft.txt", b"not saved yet")
    third = Vault.open(path, password=PASSWORD)
    assert third.names() == ["secret-diary.txt"]
    third.lock()

    # The session itself still sees its unsaved work.
    assert sorted(session.names()) == ["draft.txt", "secret-diary.txt"]

    # The sealed file leaks neither the entry contents nor the entry names.
    raw = path.read_bytes()
    assert raw[:8] == MAGIC
    assert marker not in raw
    assert b"secret-diary.txt" not in raw

    session.lock()


def test_created_vault_file_is_immediately_a_sealed_empty_vault(
        tmp_path, fast_params):
    path = tmp_path / "fresh.aegis"
    created = Vault.create(path, PASSWORD, params=fast_params)
    try:
        assert path.read_bytes()[:8] == MAGIC
        peek = Vault.open(path, password=PASSWORD)
        assert peek.names() == []
        peek.lock()
    finally:
        created.session.lock()
