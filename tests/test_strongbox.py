"""Phase 3 — the Strongbox: codes, keys, notes, and document copies.

All fixtures are synthetic: fake codes, fake keys, patterned bytes
standing in for documents. No real credential or document anywhere.
"""

import pytest

from aegis import Strongbox, Vault
from aegis.errors import (
    DocumentTooLargeError,
    InvalidStrongboxEntryError,
    StrongboxDamagedError,
    StrongboxNotFoundError,
    VaultLockedError,
)
from aegis.strongbox import (
    MAX_DOCUMENT_BYTES,
    STRONGBOX_ENTRY_NAME,
)

from tests.conftest import PASSWORD, pattern_bytes


@pytest.fixture
def box(create_vault):
    created, path = create_vault()
    return Strongbox(created.session), created, path


def test_add_and_reveal_each_text_kind(box):
    strongbox, _, _ = box
    code = strongbox.add_text("code", "Mail recovery code", "0000-1111-FAKE")
    key = strongbox.add_text("key", "Game license key", "FAKE-KEY-1234")
    note = strongbox.add_text("note", "Safe combination", "12-34-56 (fake)")
    assert strongbox.reveal(code.id) == "0000-1111-FAKE"
    assert strongbox.reveal(key.id) == "FAKE-KEY-1234"
    assert strongbox.reveal(note.id) == "12-34-56 (fake)"
    assert len(strongbox) == 3


def test_summaries_carry_no_contents(box):
    strongbox, _, _ = box
    secret = "9999-SECRET-CODE"
    strongbox.add_text("code", "Bank code", secret)
    (summary,) = strongbox.summaries()
    assert summary.title == "Bank code"
    assert summary.kind_label == "Recovery code"
    assert not hasattr(summary, "body")
    assert secret not in repr(summary)


def test_repr_and_describe_never_show_contents(box):
    strongbox, _, _ = box
    entry = strongbox.add_text("note", "Diary note", "a very private fake note")
    assert "a very private fake note" not in repr(entry)
    assert "a very private fake note" not in entry.describe()
    assert "Private note" in entry.describe()


def test_items_survive_lock_and_reopen(box, vault_path):
    strongbox, created, path = box
    code = strongbox.add_text("code", "Code", "4242-FAKE")
    doc = strongbox.add_document("Will copy", "will.txt", b"fake will bytes")
    strongbox.lock()

    session = Vault.open(path, password=PASSWORD)
    reopened = Strongbox(session)
    assert reopened.reveal(code.id) == "4242-FAKE"
    assert reopened.read_document(doc.id) == ("will.txt", b"fake will bytes")

    # The recovery key opens the Strongbox at full strength too.
    session2 = Vault.open(path, recovery_key=created.recovery_key)
    assert Strongbox(session2).reveal(code.id) == "4242-FAKE"


def test_document_round_trip_byte_identical(box):
    strongbox, _, _ = box
    data = pattern_bytes(1_500_001, seed=7)
    entry = strongbox.add_document("Big scan", "scan.bin", data)
    filename, back = strongbox.read_document(entry.id)
    assert filename == "scan.bin"
    assert back == data
    assert entry.size == len(data)


def test_document_at_the_cap_is_accepted(box):
    strongbox, _, _ = box
    entry = strongbox.add_document(
        "At cap", "cap.bin", pattern_bytes(MAX_DOCUMENT_BYTES, seed=3)
    )
    _, back = strongbox.read_document(entry.id)
    assert len(back) == MAX_DOCUMENT_BYTES


def test_document_past_the_cap_is_refused(box):
    strongbox, _, _ = box
    with pytest.raises(DocumentTooLargeError):
        strongbox.add_document(
            "Too big", "big.bin", pattern_bytes(MAX_DOCUMENT_BYTES + 1)
        )
    assert len(strongbox) == 0


@pytest.mark.parametrize(
    "bad_name", ["../escape.txt", "a/b.txt", "a\\b.txt", "", ".", "..", "x\x00y"]
)
def test_document_names_must_be_plain_file_names(box, bad_name):
    strongbox, _, _ = box
    with pytest.raises(InvalidStrongboxEntryError):
        strongbox.add_document("Doc", bad_name, b"bytes")


def test_wrong_kind_operations_are_refused(box):
    strongbox, _, _ = box
    doc = strongbox.add_document("Doc", "d.txt", b"data")
    note = strongbox.add_text("note", "Note", "text body")
    with pytest.raises(InvalidStrongboxEntryError):
        strongbox.reveal(doc.id)
    with pytest.raises(InvalidStrongboxEntryError):
        strongbox.read_document(note.id)
    with pytest.raises(InvalidStrongboxEntryError):
        strongbox.add_text("document", "Nope", "body")
    with pytest.raises(InvalidStrongboxEntryError):
        strongbox.replace_document(note.id, b"new bytes")


def test_update_and_replace(box):
    strongbox, _, _ = box
    note = strongbox.add_text("note", "Old title", "old body")
    strongbox.update(note.id, title="New title", body="new body")
    assert strongbox.get(note.id).title == "New title"
    assert strongbox.reveal(note.id) == "new body"

    doc = strongbox.add_document("Doc", "a.txt", b"first")
    with pytest.raises(InvalidStrongboxEntryError):
        strongbox.update(doc.id, body="not how documents change")
    strongbox.replace_document(doc.id, b"second", filename="b.txt")
    assert strongbox.read_document(doc.id) == ("b.txt", b"second")


def test_refused_update_changes_nothing(box):
    strongbox, _, _ = box
    note = strongbox.add_text("note", "Keep me", "original")
    with pytest.raises(InvalidStrongboxEntryError):
        strongbox.update(note.id, title="")
    assert strongbox.get(note.id).title == "Keep me"
    assert strongbox.reveal(note.id) == "original"


def test_remove_deletes_document_bytes_too(box):
    strongbox, created, _ = box
    doc = strongbox.add_document("Doc", "d.txt", b"data")
    note = strongbox.add_text("note", "Note", "body")
    strongbox.remove(doc.id)
    assert len(strongbox) == 1
    assert "strongbox/files/%s" % doc.id not in created.session.names()
    with pytest.raises(StrongboxNotFoundError):
        strongbox.get(doc.id)
    strongbox.remove(note.id)
    assert len(strongbox) == 0
    with pytest.raises(StrongboxNotFoundError):
        strongbox.remove(note.id)


def test_missing_item_is_a_plain_refusal(box):
    strongbox, _, _ = box
    with pytest.raises(StrongboxNotFoundError):
        strongbox.reveal("no-such-id")
    with pytest.raises(StrongboxNotFoundError):
        strongbox.read_document("no-such-id")


def test_summaries_filter_by_kind(box):
    strongbox, _, _ = box
    strongbox.add_text("code", "C1", "1")
    strongbox.add_text("note", "N1", "2")
    strongbox.add_document("D1", "d.txt", b"3")
    assert [s.title for s in strongbox.summaries("code")] == ["C1"]
    assert [s.title for s in strongbox.summaries("document")] == ["D1"]
    assert len(strongbox.summaries()) == 3
    with pytest.raises(InvalidStrongboxEntryError):
        strongbox.summaries("everything")


def test_locked_session_refuses(box):
    strongbox, _, _ = box
    strongbox.add_text("code", "C", "1")
    strongbox.lock()
    with pytest.raises(VaultLockedError):
        strongbox.summaries()


def test_damaged_store_is_refused(box):
    strongbox, created, _ = box
    strongbox.add_text("code", "C", "1")
    created.session.write(STRONGBOX_ENTRY_NAME, b"this is not the store")
    created.session.save()
    fresh = Strongbox(created.session)
    with pytest.raises(StrongboxDamagedError):
        fresh.summaries()


def test_document_bytes_that_no_longer_match_are_refused(box):
    strongbox, created, _ = box
    doc = strongbox.add_document("Doc", "d.txt", b"the real bytes")
    # Something swaps the stored copy for different bytes of the
    # same length: the recorded check value catches it.
    created.session.write(
        "strongbox/files/%s" % doc.id, b"the fake bytes"
    )
    created.session.save()
    fresh = Strongbox(created.session)
    with pytest.raises(StrongboxDamagedError):
        fresh.read_document(doc.id)
    # The rest of the Strongbox still works.
    note = fresh.add_text("note", "Still fine", "yes")
    assert fresh.reveal(note.id) == "yes"


def test_missing_document_bytes_are_refused_at_read(box):
    strongbox, created, _ = box
    doc = strongbox.add_document("Doc", "d.txt", b"bytes")
    created.session.remove("strongbox/files/%s" % doc.id)
    created.session.save()
    fresh = Strongbox(created.session)
    with pytest.raises(StrongboxDamagedError):
        fresh.read_document(doc.id)
    # Listing still works — one lost copy doesn't shut the box.
    assert [s.title for s in fresh.summaries()] == ["Doc"]


def test_empty_title_and_body_are_refused(box):
    strongbox, _, _ = box
    with pytest.raises(InvalidStrongboxEntryError):
        strongbox.add_text("code", "", "1234")
    with pytest.raises(InvalidStrongboxEntryError):
        strongbox.add_text("code", "Title", "")
    with pytest.raises(InvalidStrongboxEntryError):
        strongbox.add_document("", "d.txt", b"x")
