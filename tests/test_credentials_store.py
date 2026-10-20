"""Phase 2 credential store tests: CRUD, persistence, search, safety.

Written against the Phase 2 spec in docs/ROADMAP.md and the import/
export decision in docs/IMPORT-EXPORT-SAFETY.md. All logins are
synthetic and obviously fake — no real credentials anywhere.
"""

import json

import pytest

from aegis import Vault
from aegis.credentials import STORE_ENTRY_NAME, CredentialStore
from aegis.errors import (
    CredentialNotFoundError,
    InvalidCredentialError,
    PasswordStoreDamagedError,
    VaultLockedError,
)
from tests.conftest import NEW_PASSWORD, PASSWORD

FAKE = dict(
    title="Example Mail",
    username="test.person@example.test",
    password="fake-password-for-tests-1",
    url="https://example.test/login",
    notes="Synthetic test login — not a real account.",
)
FAKE2 = dict(
    title="Sample Bank",
    username="sample.user@example.test",
    password="another-fake-password-2",
    url="https://bank.example.test/",
    notes="Also synthetic.",
)


@pytest.fixture
def store(create_vault):
    created, path = create_vault()
    return CredentialStore(created.session), created, path


# -- basics -----------------------------------------------------------------

def test_store_starts_empty(store):
    credential_store, _, _ = store
    assert len(credential_store) == 0
    assert credential_store.summaries() == []


def test_add_and_get_round_trip(store):
    credential_store, _, _ = store
    entry = credential_store.add(**FAKE)
    assert entry.id
    assert entry.created_utc and entry.modified_utc
    got = credential_store.get(entry.id)
    assert got.title == FAKE["title"]
    assert got.username == FAKE["username"]
    assert got.password == FAKE["password"]
    assert got.url == FAKE["url"]
    assert got.notes == FAKE["notes"]
    assert len(credential_store) == 1


def test_ids_are_unique(store):
    credential_store, _, _ = store
    ids = {credential_store.add(**FAKE).id for _ in range(20)}
    assert len(ids) == 20


def test_store_lives_alongside_files(store):
    credential_store, created, _ = store
    created.session.write("a-note.txt", b"synthetic file bytes")
    created.session.save()
    credential_store.add(**FAKE)
    assert created.session.read("a-note.txt") == b"synthetic file bytes"
    assert len(credential_store) == 1


# -- persistence --------------------------------------------------------------

def test_persistence_across_lock_and_reopen(store):
    credential_store, created, path = store
    first = credential_store.add(**FAKE)
    credential_store.add(**FAKE2)
    credential_store.lock()
    assert created.session.is_locked
    reopened = CredentialStore(Vault.open(path, password=PASSWORD))
    assert len(reopened) == 2
    assert reopened.get(first.id).password == FAKE["password"]


def test_persistence_via_recovery_key_open(store):
    credential_store, created, path = store
    entry = credential_store.add(**FAKE)
    credential_store.lock()
    reopened = CredentialStore(
        Vault.open(path, recovery_key=created.recovery_key)
    )
    assert reopened.get(entry.id).username == FAKE["username"]


def test_change_password_keeps_store(store):
    credential_store, created, path = store
    entry = credential_store.add(**FAKE)
    created.session.change_password(NEW_PASSWORD)
    created.session.lock()
    reopened = CredentialStore(Vault.open(path, password=NEW_PASSWORD))
    assert reopened.get(entry.id).password == FAKE["password"]


def test_vault_file_never_contains_plaintext(store):
    credential_store, _, path = store
    credential_store.add(**FAKE)
    data = path.read_bytes()
    assert FAKE["password"].encode() not in data
    assert FAKE["title"].encode() not in data
    assert STORE_ENTRY_NAME.encode() not in data


# -- update / remove --------------------------------------------------------------

def test_update_fields(store):
    credential_store, _, _ = store
    entry = credential_store.add(**FAKE)
    updated = credential_store.update(
        entry.id, title="Example Mail (work)", password="rotated-fake-3"
    )
    assert updated.title == "Example Mail (work)"
    assert updated.password == "rotated-fake-3"
    assert updated.username == FAKE["username"]
    assert updated.modified_utc >= entry.created_utc


def test_update_unknown_field_refused(store):
    credential_store, _, _ = store
    entry = credential_store.add(**FAKE)
    with pytest.raises(InvalidCredentialError):
        credential_store.update(entry.id, nickname="nope")


def test_refused_update_leaves_entry_unchanged(store):
    credential_store, _, path = store
    entry = credential_store.add(**FAKE)
    with pytest.raises(InvalidCredentialError):
        credential_store.update(entry.id, title="", password="changed")
    credential_store.lock()
    reopened = CredentialStore(Vault.open(path, password=PASSWORD))
    assert reopened.get(entry.id).title == FAKE["title"]
    assert reopened.get(entry.id).password == FAKE["password"]


def test_remove(store):
    credential_store, _, _ = store
    entry = credential_store.add(**FAKE)
    credential_store.add(**FAKE2)
    credential_store.remove(entry.id)
    assert len(credential_store) == 1
    with pytest.raises(CredentialNotFoundError):
        credential_store.get(entry.id)
    with pytest.raises(CredentialNotFoundError):
        credential_store.remove(entry.id)


def test_get_missing_raises(store):
    credential_store, _, _ = store
    with pytest.raises(CredentialNotFoundError):
        credential_store.get("no-such-id")
    with pytest.raises(CredentialNotFoundError):
        credential_store.reveal_password("no-such-id")


# -- validation ---------------------------------------------------------------

def test_add_requires_a_title(store):
    credential_store, _, _ = store
    with pytest.raises(InvalidCredentialError):
        credential_store.add("")
    with pytest.raises(InvalidCredentialError):
        credential_store.add("   ")


def test_add_rejects_oversize_fields(store):
    credential_store, _, _ = store
    with pytest.raises(InvalidCredentialError):
        credential_store.add("x" * 201)
    with pytest.raises(InvalidCredentialError):
        credential_store.add("Fine Title", password="x" * 1001)


# -- search ---------------------------------------------------------------------

def test_search_matches_title_username_url(store):
    credential_store, _, _ = store
    credential_store.add(**FAKE)
    credential_store.add(**FAKE2)
    assert [s.title for s in credential_store.search("example mail")] == [
        "Example Mail"
    ]
    assert [s.title for s in credential_store.search("SAMPLE.USER")] == [
        "Sample Bank"
    ]
    assert [s.title for s in credential_store.search("bank.example")] == [
        "Sample Bank"
    ]


def test_search_blank_returns_all(store):
    credential_store, _, _ = store
    credential_store.add(**FAKE)
    credential_store.add(**FAKE2)
    assert len(credential_store.search("")) == 2
    assert len(credential_store.search("   ")) == 2


def test_search_never_matches_password(store):
    credential_store, _, _ = store
    credential_store.add(**FAKE)
    # The exact saved password — and any piece of it — finds nothing.
    assert credential_store.search(FAKE["password"]) == []
    assert credential_store.search("fake-password") == []


def test_search_never_matches_notes(store):
    credential_store, _, _ = store
    credential_store.add(**FAKE)
    assert credential_store.search("Synthetic test login") == []


def test_summaries_carry_no_password(store):
    credential_store, _, _ = store
    credential_store.add(**FAKE)
    (summary,) = credential_store.summaries()
    assert not hasattr(summary, "password")
    assert FAKE["password"] not in repr(summary)
    (found,) = credential_store.search("Example")
    assert not hasattr(found, "password")


# -- leak discipline ------------------------------------------------------------

def test_entry_repr_and_describe_hide_password(store):
    credential_store, _, _ = store
    entry = credential_store.add(**FAKE)
    assert FAKE["password"] not in repr(entry)
    assert FAKE["password"] not in str(entry)
    text = entry.describe()
    assert FAKE["title"] in text
    assert FAKE["password"] not in text


def test_reveal_password_is_the_path(store):
    credential_store, _, _ = store
    entry = credential_store.add(**FAKE)
    assert credential_store.reveal_password(entry.id) == FAKE["password"]


# -- lock discipline --------------------------------------------------------------

def test_store_refuses_when_session_locked(store):
    credential_store, created, _ = store
    credential_store.add(**FAKE)
    created.session.lock()
    with pytest.raises(VaultLockedError):
        credential_store.summaries()
    with pytest.raises(VaultLockedError):
        credential_store.add(**FAKE2)
    with pytest.raises(VaultLockedError):
        credential_store.search("Example")


def test_store_lock_locks_session_and_forgets(store):
    credential_store, created, _ = store
    credential_store.add(**FAKE)
    credential_store.lock()
    assert created.session.is_locked
    assert credential_store._entries is None
    with pytest.raises(VaultLockedError):
        len(credential_store)


# -- damaged store documents -------------------------------------------------------

def _write_raw_store(created, raw_bytes):
    created.session.write(STORE_ENTRY_NAME, raw_bytes)
    created.session.save()
    created.session.lock()


def test_damaged_store_document_refused(create_vault):
    created, path = create_vault()
    _write_raw_store(created, b"this is not the store document")
    reopened = CredentialStore(Vault.open(path, password=PASSWORD))
    with pytest.raises(PasswordStoreDamagedError):
        reopened.summaries()


def test_store_document_wrong_version_refused(create_vault):
    created, path = create_vault()
    doc = json.dumps({"version": 99, "entries": []}).encode()
    _write_raw_store(created, doc)
    reopened = CredentialStore(Vault.open(path, password=PASSWORD))
    with pytest.raises(PasswordStoreDamagedError):
        reopened.summaries()


def test_store_document_duplicate_ids_refused(create_vault):
    created, path = create_vault()
    one = {
        "id": "same-id", "title": "A", "username": "", "password": "x",
        "url": "", "notes": "", "created_utc": "t", "modified_utc": "t",
    }
    doc = json.dumps({"version": 1, "entries": [one, dict(one)]}).encode()
    _write_raw_store(created, doc)
    reopened = CredentialStore(Vault.open(path, password=PASSWORD))
    with pytest.raises(PasswordStoreDamagedError):
        reopened.summaries()
