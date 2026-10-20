"""Recovery key behaviour (spec items 6, 7, 8).

The recovery key is the one way back in: it must open the vault, tolerate
re-typing with different spacing/dashes/case, refuse wrong or malformed
keys, survive a password change, and be replaceable by regeneration.
"""

import base64

import pytest

from aegis import Vault
from aegis.errors import WrongPasswordError, WrongRecoveryKeyError
from aegis.recovery import (
    RECOVERY_KEY_BYTES,
    format_recovery_key,
    generate_recovery_key,
    recovery_key_to_bytes,
)

from conftest import NEW_PASSWORD, PASSWORD, WRONG_PASSWORD, pattern_bytes

ENTRIES = {"notes.txt": pattern_bytes(1234, seed=3),
           "papers/tax-2026.txt": pattern_bytes(4321, seed=4)}


@pytest.fixture
def vault_with_recovery(create_vault):
    created, path = create_vault(ENTRIES)
    created.session.lock()
    return created, path


# -- item 6: recovery key opens; wrong / malformed refused --------------------

def test_recovery_key_opens_vault(vault_with_recovery):
    created, path = vault_with_recovery
    session = Vault.open(path, recovery_key=created.recovery_key)
    assert sorted(session.names()) == sorted(ENTRIES)
    for name, expected in ENTRIES.items():
        assert session.read(name) == expected
    session.lock()


def test_recovery_display_format(vault_with_recovery):
    created, _ = vault_with_recovery
    key = created.recovery_key
    groups = key.split("-")
    # Grouped in 4s, uppercase base32 alphabet, no padding characters.
    assert all(len(g) == 4 for g in groups[:-1])
    assert 1 <= len(groups[-1]) <= 4
    assert "=" not in key
    raw = recovery_key_to_bytes(key)
    assert len(raw) == RECOVERY_KEY_BYTES == 32


def test_wrong_recovery_key_refused(vault_with_recovery, create_vault):
    created, path = vault_with_recovery
    other, other_path = create_vault(name="other.aegis")
    other.session.lock()
    assert other.recovery_key != created.recovery_key
    with pytest.raises(WrongRecoveryKeyError):
        Vault.open(path, recovery_key=other.recovery_key)


def test_generated_wrong_recovery_key_refused(vault_with_recovery):
    _, path = vault_with_recovery
    with pytest.raises(WrongRecoveryKeyError):
        Vault.open(path, recovery_key=generate_recovery_key())


@pytest.mark.parametrize(
    "malformed",
    [
        "",
        "!!!",
        "not-a-recovery-key",
        "abc",
        "====",
        "AAAA-AAAA",          # well-formed base32, far too short once decoded
        "MYZXW6YQ",           # valid base32 of only 5 bytes
    ],
)
def test_malformed_recovery_key_refused(vault_with_recovery, malformed):
    _, path = vault_with_recovery
    with pytest.raises(WrongRecoveryKeyError):
        Vault.open(path, recovery_key=malformed)


@pytest.mark.parametrize(
    "transform",
    [
        lambda k: k.lower(),
        lambda k: k.replace("-", " "),
        lambda k: k.replace("-", ""),
        lambda k: "  " + k.lower().replace("-", "  ") + "  ",
        lambda k: k.replace("-", " - "),
    ],
    ids=["lowercase", "spaces", "no-separators", "extra-spaces", "spaced-dashes"],
)
def test_recovery_key_normalization(vault_with_recovery, transform):
    created, path = vault_with_recovery
    session = Vault.open(path, recovery_key=transform(created.recovery_key))
    assert sorted(session.names()) == sorted(ENTRIES)
    session.lock()


# -- item 7: recovery in, then change the password ----------------------------

def test_recovery_then_change_password(vault_with_recovery):
    created, path = vault_with_recovery
    session = Vault.open(path, recovery_key=created.recovery_key)
    session.change_password(NEW_PASSWORD)
    session.save()
    session.lock()

    with pytest.raises(WrongPasswordError):
        Vault.open(path, password=PASSWORD)

    by_new = Vault.open(path, password=NEW_PASSWORD)
    assert by_new.read("notes.txt") == ENTRIES["notes.txt"]
    by_new.lock()

    by_recovery = Vault.open(path, recovery_key=created.recovery_key)
    assert by_recovery.read("notes.txt") == ENTRIES["notes.txt"]
    by_recovery.lock()


# -- item 8: regeneration replaces the key -------------------------------------

def test_regenerate_recovery_key(vault_with_recovery):
    created, path = vault_with_recovery
    old_key = created.recovery_key

    session = Vault.open(path, password=PASSWORD)
    new_key = session.regenerate_recovery_key()
    assert isinstance(new_key, str)
    assert new_key != old_key
    assert len(recovery_key_to_bytes(new_key)) == RECOVERY_KEY_BYTES
    session.save()
    session.lock()

    with pytest.raises(WrongRecoveryKeyError):
        Vault.open(path, recovery_key=old_key)

    reopened = Vault.open(path, recovery_key=new_key)
    assert reopened.read("notes.txt") == ENTRIES["notes.txt"]
    reopened.lock()

    # The password path is untouched by regeneration.
    by_password = Vault.open(path, password=PASSWORD)
    assert by_password.read("notes.txt") == ENTRIES["notes.txt"]
    by_password.lock()


# -- recovery module functions (spec-pinned helpers) ---------------------------

def test_recovery_module_roundtrip():
    raw = bytes(range(RECOVERY_KEY_BYTES))  # synthetic, deterministic
    display = format_recovery_key(raw)
    assert recovery_key_to_bytes(display) == raw


def test_generate_recovery_key_decodes_to_32_bytes():
    display = generate_recovery_key()
    assert len(recovery_key_to_bytes(display)) == 32


@pytest.mark.parametrize("bad", ["", "!!!", "abc", "a b c d e"])
def test_recovery_key_to_bytes_malformed_value_error(bad):
    with pytest.raises(ValueError):
        recovery_key_to_bytes(bad)


def test_recovery_keys_unique_per_vault(create_vault):
    first, _ = create_vault(name="one.aegis")
    second, _ = create_vault(name="two.aegis")
    first.session.lock()
    second.session.lock()
    assert first.recovery_key != second.recovery_key
    # Display form is base32 text (RFC 4648 alphabet), not raw key bytes.
    raw = recovery_key_to_bytes(first.recovery_key)
    assert first.recovery_key.encode() != raw
    assert base64.b32encode(raw).decode().rstrip("=") == (
        first.recovery_key.replace("-", "")
    )
