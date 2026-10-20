"""Refusals and error behaviour (spec items 4 and 15).

Wrong credentials, duplicate creation, bad credential combinations, missing
entries, and unusable entry names must all be refused with the spec's exact
plain-language errors.
"""

import pytest

from aegis import Vault
from aegis.errors import (
    AegisError,
    EntryNotFoundError,
    UnlockError,
    VaultExistsError,
    VaultFormatError,
    VaultLockedError,
    VaultTamperedError,
    WeakPasswordError,
    WrongPasswordError,
    WrongRecoveryKeyError,
)

from conftest import FAST_PARAMS, PASSWORD, WRONG_PASSWORD


# -- wrong password (item 4) -------------------------------------------------

def test_wrong_password_refused(create_vault):
    created, path = create_vault({"notes.txt": b"synthetic contents"})
    created.session.lock()

    with pytest.raises(WrongPasswordError):
        Vault.open(path, password=WRONG_PASSWORD)


def test_vault_intact_after_wrong_password(create_vault):
    created, path = create_vault({"notes.txt": b"synthetic contents"})
    created.session.lock()

    with pytest.raises(WrongPasswordError):
        Vault.open(path, password=WRONG_PASSWORD)

    session = Vault.open(path, password=PASSWORD)
    assert session.read("notes.txt") == b"synthetic contents"
    session.lock()


# -- create refusals (item 15) ----------------------------------------------

def test_create_on_existing_vault_path(create_vault, vault_path):
    created, _ = create_vault(name=vault_path.name)
    created.session.lock()
    with pytest.raises(VaultExistsError):
        Vault.create(vault_path, PASSWORD, params=FAST_PARAMS)


def test_create_on_existing_plain_file(tmp_path):
    path = tmp_path / "already-here.aegis"
    path.write_bytes(b"someone else's file")
    with pytest.raises(VaultExistsError):
        Vault.create(path, PASSWORD, params=FAST_PARAMS)
    # The pre-existing file must not have been clobbered.
    assert path.read_bytes() == b"someone else's file"


@pytest.mark.parametrize("short", ["", "a", "1234567"])
def test_create_short_password_refused(vault_path, short):
    with pytest.raises(WeakPasswordError):
        Vault.create(vault_path, short, params=FAST_PARAMS)


def test_create_minimum_length_password_accepted(vault_path):
    created = Vault.create(vault_path, "12345678", params=FAST_PARAMS)
    created.session.lock()
    session = Vault.open(vault_path, password="12345678")
    assert session.names() == []
    session.lock()


# -- open credential combinations (item 15) ----------------------------------

def test_open_with_both_credentials_is_value_error(create_vault):
    created, path = create_vault()
    created.session.lock()
    with pytest.raises(ValueError):
        Vault.open(path, password=PASSWORD,
                   recovery_key=created.recovery_key)


def test_open_with_neither_credential_is_value_error(create_vault):
    created, path = create_vault()
    created.session.lock()
    with pytest.raises(ValueError):
        Vault.open(path)


# -- missing entries ----------------------------------------------------------

def test_read_missing_entry(create_vault):
    created, _ = create_vault({"present.txt": b"x"})
    with pytest.raises(EntryNotFoundError):
        created.session.read("absent.txt")
    created.session.lock()


def test_remove_missing_entry(create_vault):
    created, _ = create_vault({"present.txt": b"x"})
    with pytest.raises(EntryNotFoundError):
        created.session.remove("absent.txt")
    created.session.lock()


# -- entry name rules ----------------------------------------------------------
# Spec: 1..255 chars, no NUL, no leading "/", no ".." path segment,
# no backslash. Refusal is a plain AegisError with the spec's message.

BAD_NAME_MESSAGE = (
    "That name can't be used in a vault. "
    "Keep it a simple file or folder name."
)


@pytest.mark.parametrize(
    "bad_name",
    [
        "",
        "x" * 256,
        "/absolute.txt",
        "..",
        "a/../b",
        "a/..",
        "back\\slash.txt",
        "dir\\file.txt",
        "nul\x00byte",
    ],
)
def test_write_bad_name_refused(create_vault, bad_name):
    created, _ = create_vault()
    with pytest.raises(AegisError) as excinfo:
        created.session.write(bad_name, b"data")
    assert str(excinfo.value) == BAD_NAME_MESSAGE
    created.session.lock()


@pytest.mark.parametrize(
    "good_name",
    [
        "notes.txt",
        "papers/tax-2026.txt",
        "deep/nested/folder/file.bin",
        "x" * 255,
        "notes..txt",  # ".." inside a segment is not a ".." segment
        ".hidden",
    ],
)
def test_write_good_name_accepted(create_vault, good_name):
    created, _ = create_vault()
    created.session.write(good_name, b"data")
    assert created.session.read(good_name) == b"data"
    created.session.lock()


# -- exact error messages and hierarchy ---------------------------------------

EXACT_MESSAGES = [
    (VaultFormatError,
     "This file isn't a vault Aegis can open — it may be damaged, "
     "or it may not be an Aegis vault."),
    (WrongPasswordError,
     "That password doesn't open this vault. Check it and try again."),
    (WrongRecoveryKeyError,
     "That recovery key doesn't open this vault. "
     "Check it carefully and try again."),
    (VaultTamperedError,
     "This vault's contents don't check out — the file has been changed "
     "or damaged, so Aegis won't open it."),
    (VaultLockedError,
     "This vault is locked. Open it again to use it."),
    (WeakPasswordError,
     "That password is too short. Use at least 8 characters — "
     "a short phrase you can remember works well."),
    (VaultExistsError,
     "There's already a vault at that spot. "
     "Pick a different name or place."),
    (EntryNotFoundError,
     "That item isn't in this vault."),
]


@pytest.mark.parametrize("error_cls,expected", EXACT_MESSAGES,
                         ids=[c.__name__ for c, _ in EXACT_MESSAGES])
def test_error_user_messages_exact(error_cls, expected):
    exc = error_cls()
    assert str(exc) == expected
    assert exc.user_message == expected


def test_error_hierarchy():
    assert issubclass(VaultFormatError, AegisError)
    assert issubclass(UnlockError, AegisError)
    assert issubclass(WrongPasswordError, UnlockError)
    assert issubclass(WrongRecoveryKeyError, UnlockError)
    assert issubclass(VaultTamperedError, AegisError)
    assert issubclass(VaultLockedError, AegisError)
    assert issubclass(WeakPasswordError, AegisError)
    assert issubclass(VaultExistsError, AegisError)
    assert issubclass(EntryNotFoundError, AegisError)
