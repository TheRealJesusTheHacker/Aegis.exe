"""Regression tests for Audit #1 fixes (rulings 1-9).

Every scenario here is one the audit demonstrated against the
pre-fix code (or a direct consequence of a ruling).  Synthetic data
only, per the suite rules.
"""

import base64
import copy
import json

import pytest

import aegis.format as fmt
from aegis import Vault
from aegis.errors import (
    AegisError,
    VaultFormatError,
    VaultTamperedError,
)

from conftest import (
    NEW_PASSWORD,
    PASSWORD,
    load_header,
    rewrite_header,
)


# -- 1. salt rotation on credential change ------------------------------------


def test_change_password_rotates_only_password_salt(create_vault):
    created, path = create_vault({"notes.txt": b"x"})
    session = created.session
    _, before, _ = load_header(path)

    session.change_password(NEW_PASSWORD)
    _, after, _ = load_header(path)

    assert after["password_wrap"]["salt"] != before["password_wrap"]["salt"]
    assert after["recovery_wrap"]["salt"] == before["recovery_wrap"]["salt"]
    assert (
        after["recovery_wrap"]["wrapped_key"]
        == before["recovery_wrap"]["wrapped_key"]
    )
    session.lock()


def test_regenerate_recovery_key_rotates_only_recovery_salt(create_vault):
    created, path = create_vault({"notes.txt": b"x"})
    session = created.session
    _, before, _ = load_header(path)

    session.regenerate_recovery_key()
    _, after, _ = load_header(path)

    assert after["recovery_wrap"]["salt"] != before["recovery_wrap"]["salt"]
    assert after["password_wrap"]["salt"] == before["password_wrap"]["salt"]
    assert (
        after["password_wrap"]["wrapped_key"]
        == before["password_wrap"]["wrapped_key"]
    )
    session.lock()


# -- 2. cross-version payload splice ------------------------------------------

def _split_file(path):
    data, header, offset = load_header(path)
    return data, header, data[offset:]


def _splice(path, header, payload):
    """Write *header* (dict) plus *payload* over the vault at *path*."""
    rewrite_header(path, header)
    data, _, offset = load_header(path)
    path.write_bytes(data[:offset] + payload)


def test_splice_old_payload_under_new_password_header_refused(create_vault):
    created, path = create_vault()
    session = created.session
    session.write("notes.txt", b"OLD-VALUE")
    session.save()
    _, first_header, first_payload = _split_file(path)
    first_prefix = first_header["payload"]["nonce_prefix"]

    session.write("notes.txt", b"NEW-VALUE")
    session.save()
    session.change_password(NEW_PASSWORD)

    _, current_header, _ = _split_file(path)
    spliced = copy.deepcopy(current_header)
    spliced["payload"]["nonce_prefix"] = first_prefix
    _splice(path, spliced, first_payload)

    with pytest.raises(VaultTamperedError):
        Vault.open(path, password=NEW_PASSWORD)
    session.lock()


def test_splice_old_payload_after_recovery_regeneration_refused(create_vault):
    created, path = create_vault()
    session = created.session
    session.write("notes.txt", b"OLD-VALUE")
    session.save()
    _, first_header, first_payload = _split_file(path)
    first_prefix = first_header["payload"]["nonce_prefix"]

    session.write("notes.txt", b"NEW-VALUE")
    session.save()
    session.regenerate_recovery_key()

    _, current_header, _ = _split_file(path)
    spliced = copy.deepcopy(current_header)
    spliced["payload"]["nonce_prefix"] = first_prefix
    _splice(path, spliced, first_payload)

    # Even the (unchanged) password path must refuse: the payload is
    # bound to the wrap set that existed when it was sealed.
    with pytest.raises(VaultTamperedError):
        Vault.open(path, password=PASSWORD)
    session.lock()


def test_old_header_with_new_payload_refused(create_vault):
    created, path = create_vault()
    session = created.session
    session.write("notes.txt", b"OLD-VALUE")
    session.save()
    _, old_header, _ = _split_file(path)

    session.write("notes.txt", b"NEW-VALUE")
    session.save()
    session.change_password(NEW_PASSWORD)
    _, _, new_payload = _split_file(path)

    _splice(path, copy.deepcopy(old_header), new_payload)

    with pytest.raises(AegisError):
        Vault.open(path, password=PASSWORD)
    session.lock()


# -- 3. chunk_size tamper / floor ----------------------------------------------

def test_chunk_size_header_tamper_refused(create_vault):
    created, path = create_vault({"notes.txt": b"chunky"})
    created.session.lock()

    _, header, _ = load_header(path)
    header["payload"]["chunk_size"] = 65536  # valid range, wrong value
    rewrite_header(path, header)

    with pytest.raises(AegisError):
        Vault.open(path, password=PASSWORD)


def test_tiny_chunk_size_vault_refused_on_open(tmp_path, monkeypatch):
    """A vault crafted at chunk_size 64 (via a monkeypatched write
    constant) is refused with VaultFormatError once the value is
    below the accepted floor on open."""
    from conftest import FAST_PARAMS

    path = tmp_path / "tiny-chunks.aegis"
    with monkeypatch.context() as m:
        m.setattr(fmt, "CHUNK_SIZE", 64)
        created = Vault.create(path, PASSWORD, params=FAST_PARAMS)
        created.session.write("notes.txt", b"small chunks here")
        created.session.save()
        created.session.lock()

    _, header, _ = load_header(path)
    assert header["payload"]["chunk_size"] == 64

    with pytest.raises(VaultFormatError):
        Vault.open(path, password=PASSWORD)


# -- 4. CreatedVault repr/str must not leak the recovery key --------------------

def test_created_vault_repr_and_str_hide_recovery_key(create_vault):
    created, _ = create_vault()
    try:
        assert created.recovery_key not in repr(created)
        assert created.recovery_key not in str(created)
    finally:
        created.session.lock()


# -- 5. crafted manifests ---------------------------------------------------------

def _seal_crafted_bundle(session, bundle):
    """Seal an arbitrary plaintext bundle through the session's own
    sealing path (same key material, same header) and save it."""
    session._serialize_bundle = lambda: bundle
    try:
        session.save()
    finally:
        del session.__dict__["_serialize_bundle"]


def _bundle_for(manifest, chunks):
    raw = json.dumps(manifest).encode("utf-8")
    return len(raw).to_bytes(4, "big") + raw + b"".join(chunks)


def test_manifest_duplicate_names_refused(create_vault):
    created, path = create_vault({"notes.txt": b"x"})
    session = created.session
    manifest = {
        "version": 1,
        "created_utc": session._created_utc,
        "entries": [
            {"name": "dup.txt", "size": 3},
            {"name": "dup.txt", "size": 4},
        ],
    }
    _seal_crafted_bundle(session, _bundle_for(manifest, [b"abc", b"defg"]))
    session.lock()

    with pytest.raises(VaultTamperedError):
        Vault.open(path, password=PASSWORD)


def test_manifest_path_traversal_name_refused(create_vault):
    created, path = create_vault({"notes.txt": b"x"})
    session = created.session
    manifest = {
        "version": 1,
        "created_utc": session._created_utc,
        "entries": [{"name": "../evil.txt", "size": 4}],
    }
    _seal_crafted_bundle(session, _bundle_for(manifest, [b"evil"]))
    session.lock()

    with pytest.raises(VaultTamperedError):
        Vault.open(path, password=PASSWORD)


# -- 6. deeply nested header JSON ---------------------------------------------------

def test_deeply_nested_header_json_is_format_error(create_vault):
    created, path = create_vault()
    created.session.lock()

    data, _, offset = load_header(path)
    payload = data[offset:]
    nested = b"[" * 30000 + b"]" * 30000  # 60_000 bytes, under the cap
    path.write_bytes(
        data[:10] + len(nested).to_bytes(4, "big") + nested + payload
    )

    with pytest.raises(VaultFormatError):
        Vault.open(path, password=PASSWORD)


# -- 7. missing path / directory open ------------------------------------------------

def test_open_missing_path_is_aegis_error(tmp_path):
    with pytest.raises(AegisError) as excinfo:
        Vault.open(tmp_path / "nope.aegis", password=PASSWORD)
    assert not isinstance(excinfo.value, OSError)


def test_open_directory_is_aegis_error(tmp_path):
    with pytest.raises(AegisError) as excinfo:
        Vault.open(tmp_path, password=PASSWORD)
    assert not isinstance(excinfo.value, OSError)


# -- 8. duplicated header JSON key ------------------------------------------------------

def test_duplicate_header_json_key_is_format_error(create_vault):
    created, path = create_vault()
    created.session.lock()

    data, _, offset = load_header(path)
    header_len = int.from_bytes(data[10:14], "big")
    raw_header = data[14:14 + header_len]
    payload = data[offset:]
    dup = b'{"format":999,' + raw_header[1:]
    path.write_bytes(
        data[:10] + len(dup).to_bytes(4, "big") + dup + payload
    )

    with pytest.raises(VaultFormatError):
        Vault.open(path, password=PASSWORD)


# -- 9. lock() with a failing save keeps the session alive -------------------------------

def test_lock_with_failing_save_keeps_session_unlocked(create_vault):
    created, path = create_vault({"notes.txt": b"keep me"})
    session = created.session
    session.write("draft.txt", b"unsaved work")

    def _boom(data, **kwargs):
        raise RuntimeError("simulated save failure")

    session._atomic_write = _boom
    try:
        with pytest.raises(RuntimeError):
            session.lock()
        assert session.is_locked is False
        assert session.read("draft.txt") == b"unsaved work"
        assert session.read("notes.txt") == b"keep me"
    finally:
        del session.__dict__["_atomic_write"]

    session.lock()  # unpatched: saves and locks for real
    assert session.is_locked is True

    reopened = Vault.open(path, password=PASSWORD)
    assert reopened.read("draft.txt") == b"unsaved work"
    reopened.lock()


# -- 10. vault_id presence and uniqueness --------------------------------------------------

def test_vault_ids_present_and_unique(create_vault):
    first, first_path = create_vault(name="one.aegis")
    second, second_path = create_vault(name="two.aegis")
    first.session.lock()
    second.session.lock()

    _, header_one, _ = load_header(first_path)
    _, header_two, _ = load_header(second_path)
    id_one = base64.b64decode(header_one["vault_id"])
    id_two = base64.b64decode(header_two["vault_id"])
    assert len(id_one) == 16
    assert len(id_two) == 16
    assert id_one != id_two
