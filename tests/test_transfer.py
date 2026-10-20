"""Phase 2 transfer tests: sealed export, vault-to-vault import.

Written against the decision in docs/IMPORT-EXPORT-SAFETY.md:
export is a sealed copy and nothing else; import reads another
open Aegis vault. There is no plain-text path to test, and these
tests also pin that the exported file carries no readable logins.
"""

import pytest

from aegis import Vault
from aegis.credentials import CredentialStore
from aegis.errors import VaultExistsError, VaultLockedError
from aegis.transfer import export_sealed_copy, import_from_vault
from tests.conftest import PASSWORD
from tests.test_credentials_store import FAKE, FAKE2


@pytest.fixture
def source(create_vault):
    created, path = create_vault()
    store = CredentialStore(created.session)
    store.add(**FAKE)
    store.add(**FAKE2)
    return created, path, store


def test_export_makes_an_openable_sealed_copy(source, tmp_path):
    created, _, _ = source
    dest = tmp_path / "copy.aegis"
    export_sealed_copy(created.session, dest)
    reopened = CredentialStore(Vault.open(dest, password=PASSWORD))
    assert len(reopened) == 2
    titles = {s.title for s in reopened.summaries()}
    assert titles == {"Example Mail", "Sample Bank"}


def test_export_opens_with_recovery_key(source, tmp_path):
    created, _, _ = source
    dest = tmp_path / "copy.aegis"
    export_sealed_copy(created.session, dest)
    reopened = CredentialStore(
        Vault.open(dest, recovery_key=created.recovery_key)
    )
    assert len(reopened) == 2


def test_exported_copy_carries_no_plaintext(source, tmp_path):
    created, _, _ = source
    dest = tmp_path / "copy.aegis"
    export_sealed_copy(created.session, dest)
    data = dest.read_bytes()
    assert FAKE["password"].encode() not in data
    assert FAKE["title"].encode() not in data


def test_export_refuses_to_overwrite(source, tmp_path):
    created, _, _ = source
    dest = tmp_path / "copy.aegis"
    dest.write_bytes(b"already here")
    with pytest.raises(VaultExistsError):
        export_sealed_copy(created.session, dest)
    assert dest.read_bytes() == b"already here"


def test_export_includes_unsaved_changes(source, tmp_path):
    created, _, _ = source
    created.session.write("loose-note.txt", b"not yet saved")
    dest = tmp_path / "copy.aegis"
    export_sealed_copy(created.session, dest)
    reopened = Vault.open(dest, password=PASSWORD)
    assert reopened.read("loose-note.txt") == b"not yet saved"


def test_export_from_locked_vault_refused(source, tmp_path):
    created, _, _ = source
    created.session.lock()
    with pytest.raises(VaultLockedError):
        export_sealed_copy(created.session, tmp_path / "copy.aegis")


def test_import_merges_logins(source, create_vault):
    _, _, source_store = source
    target_created, _ = create_vault(name="target.aegis")
    target_store = CredentialStore(target_created.session)
    target_store.add(
        title="Target Only", username="t@example.test",
        password="target-fake-pw",
    )
    brought = import_from_vault(target_store, source_store.session)
    assert brought == 2
    assert len(target_store) == 3
    found = target_store.search("Example Mail")
    assert len(found) == 1
    merged = target_store.get(found[0].id)
    assert merged.password == FAKE["password"]
    assert merged.username == FAKE["username"]


def test_import_gives_fresh_ids_and_keeps_first_saved_date(source, create_vault):
    _, _, source_store = source
    original = source_store.summaries()[0]
    target_created, _ = create_vault(name="target.aegis")
    target_store = CredentialStore(target_created.session)
    import_from_vault(target_store, source_store.session)
    merged = target_store.summaries()[0]
    assert merged.id != original.id
    assert merged.created_utc == original.created_utc


def test_import_twice_makes_duplicates_by_design(source, create_vault):
    _, _, source_store = source
    target_created, _ = create_vault(name="target.aegis")
    target_store = CredentialStore(target_created.session)
    assert import_from_vault(target_store, source_store.session) == 2
    assert import_from_vault(target_store, source_store.session) == 2
    assert len(target_store) == 4


def test_import_persists(source, create_vault):
    _, _, source_store = source
    target_created, target_path = create_vault(name="target.aegis")
    target_store = CredentialStore(target_created.session)
    import_from_vault(target_store, source_store.session)
    target_store.lock()
    reopened = CredentialStore(Vault.open(target_path, password=PASSWORD))
    assert len(reopened) == 2


def test_import_from_locked_source_refused(source, create_vault):
    created, _, source_store = source
    target_created, _ = create_vault(name="target.aegis")
    target_store = CredentialStore(target_created.session)
    created.session.lock()
    with pytest.raises(VaultLockedError):
        import_from_vault(target_store, created.session)
