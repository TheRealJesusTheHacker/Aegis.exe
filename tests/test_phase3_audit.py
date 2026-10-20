"""Phase 3 audit regressions: the adversarial battery, kept.

These pin the Phase 3 self-audit's probes as permanent tests:
hostile inputs to every opener (only designed, plain-language
errors may escape — never a raw system error), truncation and
splice attacks, derivation-parameter ceilings, crafted Strongbox
lists, and the unseal move's failure behavior.
"""

import base64
import json
import os

import pytest

import aegis.armor as armor
from aegis import Strongbox
from aegis.armor import armor_manifest, seal_tree, unseal_tree
from aegis.errors import (
    AegisError,
    SealedFormatError,
    SealedSaveError,
    SealedTamperedError,
    StrongboxDamagedError,
)
from aegis.locksend import open_sealed_file, read_sealed_file, seal_file
from aegis.strongbox import STRONGBOX_ENTRY_NAME

from tests.conftest import FAST_PARAMS as PARAMS
from tests.conftest import pattern_bytes

SEND_PW = "a phrase shared for sending"


@pytest.fixture
def sealed_send(tmp_path):
    src = tmp_path / "plans.txt"
    src.write_bytes(b"audit marker PLANS-777 " * 30)
    return seal_file(src, SEND_PW, params=PARAMS)


def _rewrite_header(path, mutate):
    raw = path.read_bytes()
    header_len = int.from_bytes(raw[10:14], "big")
    header = json.loads(raw[14 : 14 + header_len])
    mutate(header)
    new_header = json.dumps(header).encode()
    path.write_bytes(
        raw[:10] + len(new_header).to_bytes(4, "big") + new_header
        + raw[14 + header_len:]
    )
    return path


# -- hostile inputs: designed errors only --------------------------------------


@pytest.mark.parametrize("kind", ["garbage", "empty", "missing", "dir"])
def test_openers_refuse_hostile_inputs_with_designed_errors(tmp_path, kind):
    if kind == "garbage":
        target = tmp_path / "g.bin"
        target.write_bytes(pattern_bytes(500, seed=99))
    elif kind == "empty":
        target = tmp_path / "e.bin"
        target.write_bytes(b"")
    elif kind == "missing":
        target = tmp_path / "not-there.bin"
    else:
        target = tmp_path
    openers = (
        lambda: read_sealed_file(target, SEND_PW),
        lambda: armor_manifest(target, SEND_PW),
        lambda: unseal_tree(target, SEND_PW, tmp_path / "out"),
        lambda: open_sealed_file(target, SEND_PW, tmp_path),
    )
    for open_it in openers:
        with pytest.raises(AegisError):
            open_it()


# -- truncation -------------------------------------------------------------------


@pytest.mark.parametrize(
    "cut", ["inside-prefix", "inside-header", "at-payload", "mid-chunk", "tail"]
)
def test_truncated_send_file_is_refused(tmp_path, sealed_send, cut):
    raw = sealed_send.read_bytes()
    header_end = 14 + int.from_bytes(raw[10:14], "big")
    cuts = {
        "inside-prefix": 10,
        "inside-header": header_end - 1,
        "at-payload": header_end,
        "mid-chunk": header_end + 30,
        "tail": len(raw) - 1,
    }
    sealed_send.write_bytes(raw[: cuts[cut]])
    with pytest.raises(AegisError):
        read_sealed_file(sealed_send, SEND_PW)


def test_appended_garbage_is_refused(tmp_path, sealed_send):
    sealed_send.write_bytes(sealed_send.read_bytes() + b"GARBAGEGARBAGE1")
    with pytest.raises(SealedTamperedError):
        read_sealed_file(sealed_send, SEND_PW)


# -- splices and header attacks -----------------------------------------------------


def test_header_payload_splice_is_refused(tmp_path, sealed_send):
    other_src = tmp_path / "other.txt"
    other_src.write_bytes(b"other contents")
    other = seal_file(other_src, SEND_PW, tmp_path / "o.aegis-send", params=PARAMS)
    raw_a, raw_b = sealed_send.read_bytes(), other.read_bytes()
    end_a = 14 + int.from_bytes(raw_a[10:14], "big")
    end_b = 14 + int.from_bytes(raw_b[10:14], "big")
    sealed_send.write_bytes(raw_a[:end_a] + raw_b[end_b:])
    with pytest.raises(SealedTamperedError):
        read_sealed_file(sealed_send, SEND_PW)


@pytest.mark.parametrize(
    "field,value",
    [("memory_kib", 2 * 1024 * 1024), ("time_cost", 999), ("parallelism", 99)],
)
def test_kdf_ceilings_are_refused_before_derivation(
    tmp_path, sealed_send, field, value
):
    _rewrite_header(sealed_send, lambda h: h["kdf"].update({field: value}))
    with pytest.raises(SealedFormatError):
        read_sealed_file(sealed_send, SEND_PW)


def test_header_with_an_extra_key_is_refused(tmp_path, sealed_send):
    _rewrite_header(sealed_send, lambda h: h.update({"extra": 1}))
    with pytest.raises(SealedFormatError):
        read_sealed_file(sealed_send, SEND_PW)


def test_header_with_a_short_salt_is_refused(tmp_path, sealed_send):
    short = base64.b64encode(b"short").decode()
    _rewrite_header(sealed_send, lambda h: h["wrap"].update({"salt": short}))
    with pytest.raises(SealedFormatError):
        read_sealed_file(sealed_send, SEND_PW)


def test_newer_version_gets_the_update_message(tmp_path, sealed_send):
    raw = bytearray(sealed_send.read_bytes())
    raw[8:10] = (2).to_bytes(2, "big")
    sealed_send.write_bytes(bytes(raw))
    with pytest.raises(SealedFormatError) as excinfo:
        read_sealed_file(sealed_send, SEND_PW)
    assert "newer version of Aegis" in str(excinfo.value)


# -- opening onto things that are already there --------------------------------------


def test_open_onto_a_symlink_does_not_follow_it(tmp_path, sealed_send):
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"do not touch")
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    os.symlink(outside, inbox / "plans.txt")
    with pytest.raises(AegisError):
        open_sealed_file(sealed_send, SEND_PW, inbox)
    assert outside.read_bytes() == b"do not touch"


# -- crafted Strongbox lists ----------------------------------------------------------


def _store_with(create_vault, doc):
    created, _ = create_vault()
    created.session.write(STRONGBOX_ENTRY_NAME, json.dumps(doc).encode())
    created.session.save()
    return Strongbox(created.session)


_BASE = {
    "id": "a1", "kind": "note", "title": "T", "body": "b", "filename": "",
    "size": 0, "sha256": "", "created_utc": "x", "modified_utc": "x",
}


@pytest.mark.parametrize(
    "doc",
    [
        {"version": 1, "entries": [_BASE, _BASE]},  # duplicate ids
        {"version": 2, "entries": []},  # unknown version
        {"version": 1, "entries": [dict(_BASE, kind="vault")]},
        {"version": 1, "entries": [dict(_BASE, size=True)]},  # bool size
        {"version": 1, "entries": [dict(_BASE, extra=1)]},  # extra key
        {"version": 1, "entries": [dict(  # a document carrying text
            _BASE, kind="document", body="sneak", filename="f.txt",
            size=1, sha256="0" * 64)]},
        {"version": 1, "entries": [dict(  # traversal document name
            _BASE, kind="document", filename="../evil",
            size=1, sha256="0" * 64)]},
    ],
)
def test_crafted_strongbox_lists_are_refused(create_vault, doc):
    store = _store_with(create_vault, doc)
    with pytest.raises(StrongboxDamagedError):
        store.summaries()


# -- the unseal move -------------------------------------------------------------------


def test_unseal_move_failure_is_designed_and_clean(tmp_path, monkeypatch):
    root = tmp_path / "store"
    root.mkdir()
    (root / "f.txt").write_bytes(b"data")
    sealed = seal_tree(root, SEND_PW, params=PARAMS)

    def _boom(a, b):
        raise OSError("simulated move failure")

    monkeypatch.setattr(armor.os, "rename", _boom)
    with pytest.raises(SealedSaveError):
        unseal_tree(sealed, SEND_PW, tmp_path / "out")
    assert not (tmp_path / "out").exists()
    assert [p for p in tmp_path.iterdir() if "unsealing" in p.name] == []
