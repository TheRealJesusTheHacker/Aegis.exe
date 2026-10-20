"""Regression tests for Re-Audit #2 fixes (N-01..N-04, F-10 residual).

Every scenario here mirrors one the re-audit demonstrated against
the round-1 fix code (or a direct consequence of the round-2
rulings). Synthetic data only, per the suite rules.
"""

import pytest

import aegis.format as fmt
import aegis.vault as vault_module
from aegis import Vault, VaultSession
from aegis.errors import (
    VaultChangedOnDiskError,
    VaultSaveError,
    WrongPasswordError,
)

from conftest import FAST_PARAMS, NEW_PASSWORD, PASSWORD

SAVE_MESSAGE = (
    "Aegis couldn't save this vault. Make sure there's room on "
    "the drive and the file isn't open somewhere else, then try again."
)
CHANGED_MESSAGE = (
    "This vault changed on disk after you opened it, so Aegis "
    "didn't save over it. Close it and open it again to see the "
    "newest copy."
)
THIRD_PASSWORD = "synthetic master phrase three"


def _fsync_directory_fails_once(monkeypatch):
    """Make the directory-fsync helper raise OSError on its next call.

    This simulates a post-publish failure (e.g. an error closing the
    directory descriptor after the rename/link already landed).
    """
    original = vault_module._fsync_directory
    state = {"calls": 0}

    def flaky(directory):
        state["calls"] += 1
        if state["calls"] == 1:
            raise OSError("simulated post-publish fsync failure")
        return original(directory)

    monkeypatch.setattr(vault_module, "_fsync_directory", flaky)


def _break_atomic_write(monkeypatch):
    def boom(self, data, **kwargs):
        raise OSError("simulated write failure")

    monkeypatch.setattr(VaultSession, "_atomic_write", boom)


# -- N-01: a post-publish failure must not invert the outcome -------------------


def test_change_password_survives_post_publish_fsync_failure(
    create_vault, monkeypatch
):
    created, path = create_vault({"notes.txt": b"still here"})
    session = created.session

    _fsync_directory_fails_once(monkeypatch)
    # The publish lands; the fsync failure after it must not turn
    # the change into a reported failure with a rolled-back header.
    session.change_password(NEW_PASSWORD)

    # In-memory header == disk: a further save works, and the vault
    # reopens with the NEW password while the OLD one is refused.
    session.write("after.txt", b"after the change")
    session.save()
    session.lock()

    with pytest.raises(WrongPasswordError):
        Vault.open(path, password=PASSWORD)
    reopened = Vault.open(path, password=NEW_PASSWORD)
    assert reopened.read("notes.txt") == b"still here"
    assert reopened.read("after.txt") == b"after the change"
    reopened.lock()


def test_save_survives_post_publish_fsync_failure(create_vault, monkeypatch):
    created, path = create_vault()
    session = created.session
    session.write("notes.txt", b"saved despite the fsync")

    _fsync_directory_fails_once(monkeypatch)
    session.save()  # publish landed; must report success
    session.lock()

    reopened = Vault.open(path, password=PASSWORD)
    assert reopened.read("notes.txt") == b"saved despite the fsync"
    reopened.lock()


def test_create_survives_post_publish_fsync_failure(tmp_path, monkeypatch):
    path = tmp_path / "fresh.aegis"
    _fsync_directory_fails_once(monkeypatch)
    created = Vault.create(path, PASSWORD, params=FAST_PARAMS)
    created.session.lock()

    reopened = Vault.open(path, password=PASSWORD)
    assert reopened.names() == []
    reopened.lock()


# -- N-02: a stale session must never silently revert newer state ----------------


def _two_sessions(create_vault, entries=None):
    created, path = create_vault(entries or {"notes.txt": b"original"})
    created.session.lock()
    first = Vault.open(path, password=PASSWORD)
    second = Vault.open(path, password=PASSWORD)
    return path, first, second


def test_stale_session_cannot_revert_credential_change(create_vault):
    path, s1, s2 = _two_sessions(create_vault)

    s1.change_password(NEW_PASSWORD)
    s1.lock()

    s2.write("stale.txt", b"stale write")
    with pytest.raises(VaultChangedOnDiskError) as excinfo:
        s2.save()
    assert str(excinfo.value) == CHANGED_MESSAGE

    # A credential change from the stale session refuses the same
    # way (and its in-memory header rolls back).
    with pytest.raises(VaultChangedOnDiskError):
        s2.change_password(THIRD_PASSWORD)

    # The on-disk vault still opens with s1's new password only,
    # and none of s2's stale writes landed.
    with pytest.raises(WrongPasswordError):
        Vault.open(path, password=PASSWORD)
    reopened = Vault.open(path, password=NEW_PASSWORD)
    assert reopened.read("notes.txt") == b"original"
    assert "stale.txt" not in reopened.names()
    reopened.lock()


def test_stale_session_content_save_refused(create_vault):
    path, s1, s2 = _two_sessions(create_vault)

    s1.write("notes.txt", b"newer from s1")
    s1.save()
    s1.lock()

    s2.write("notes.txt", b"stale from s2")
    with pytest.raises(VaultChangedOnDiskError):
        s2.save()

    reopened = Vault.open(path, password=PASSWORD)
    assert reopened.read("notes.txt") == b"newer from s1"
    reopened.lock()


def test_stale_session_lock_refuses_and_stays_open(create_vault):
    path, s1, s2 = _two_sessions(create_vault)

    s1.write("notes.txt", b"newer from s1")
    s1.save()
    s1.lock()

    s2.write("draft.txt", b"s2 unsaved work")
    with pytest.raises(VaultChangedOnDiskError):
        s2.lock()  # the save inside lock() is guarded too
    assert s2.is_locked is False
    assert s2.read("draft.txt") == b"s2 unsaved work"


def test_single_session_repeated_saves_keep_working(create_vault):
    created, path = create_vault()
    session = created.session
    for i in range(3):
        session.write("notes.txt", f"revision {i}".encode("utf-8"))
        session.save()  # fingerprint updates after every save
    session.lock()

    reopened = Vault.open(path, password=PASSWORD)
    assert reopened.read("notes.txt") == b"revision 2"
    reopened.lock()


def test_save_refused_when_vault_file_missing(create_vault):
    created, path = create_vault({"notes.txt": b"x"})
    session = created.session
    path.unlink()
    session.write("notes.txt", b"y")
    with pytest.raises(VaultChangedOnDiskError):
        session.save()


# -- N-03: raw OSErrors from the save paths become VaultSaveError -----------------


def test_save_oserror_becomes_vault_save_error(create_vault, monkeypatch):
    created, path = create_vault({"notes.txt": b"keep"})
    session = created.session
    session.write("draft.txt", b"unsaved work")

    _break_atomic_write(monkeypatch)
    with pytest.raises(VaultSaveError) as excinfo:
        session.save()
    assert str(excinfo.value) == SAVE_MESSAGE
    assert not isinstance(excinfo.value, OSError)

    # lock() surfaces the same mapped error and leaves the session
    # open with its work intact.
    with pytest.raises(VaultSaveError) as excinfo:
        session.lock()
    assert str(excinfo.value) == SAVE_MESSAGE
    assert session.is_locked is False
    assert session.read("draft.txt") == b"unsaved work"

    monkeypatch.undo()
    session.lock()
    reopened = Vault.open(path, password=PASSWORD)
    assert reopened.read("draft.txt") == b"unsaved work"
    reopened.lock()


def test_create_publish_oserror_becomes_vault_save_error(tmp_path, monkeypatch):
    _break_atomic_write(monkeypatch)
    path = tmp_path / "new.aegis"
    with pytest.raises(VaultSaveError) as excinfo:
        Vault.create(path, PASSWORD, params=FAST_PARAMS)
    assert str(excinfo.value) == SAVE_MESSAGE
    assert not path.exists()


# -- N-04: the dead dual APIs are gone ---------------------------------------------


def test_wrap_context_alias_removed():
    assert not hasattr(fmt, "wrap_context")
    assert "wrap_context" not in fmt.__all__
    assert hasattr(fmt, "wrap_context_password")
    assert hasattr(fmt, "wrap_context_recovery")


def test_chunk_aad_rejects_raw_bytes_context():
    with pytest.raises(TypeError):
        fmt.chunk_aad(b"RAWCTX", b"\x00" * fmt.NONCE_PREFIX_BYTES, 0, True)


# -- F-10 residual: a failed create zeroes the vault key ----------------------------


def test_create_failure_before_publish_zeroes_vault_key(tmp_path, monkeypatch):
    original_wrap = vault_module._wrap_vault_key
    seen = {"calls": 0, "vault_key": None}

    def failing_second_wrap(kek, vault_key, aad):
        seen["calls"] += 1
        if seen["calls"] == 2:
            seen["vault_key"] = vault_key  # the live VK bytearray
            raise RuntimeError("simulated wrap failure")
        return original_wrap(kek, vault_key, aad)

    monkeypatch.setattr(vault_module, "_wrap_vault_key", failing_second_wrap)
    path = tmp_path / "retry.aegis"
    with pytest.raises(RuntimeError):
        Vault.create(path, PASSWORD, params=FAST_PARAMS)

    assert seen["vault_key"] is not None
    assert bytes(seen["vault_key"]) == b"\x00" * 32
    assert not path.exists()

    monkeypatch.undo()
    created = Vault.create(path, PASSWORD, params=FAST_PARAMS)
    created.session.lock()
    reopened = Vault.open(path, password=PASSWORD)
    assert reopened.names() == []
    reopened.lock()
