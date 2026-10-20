"""Phase 3 — Lock-and-send: one file, its own password, for travel.

Synthetic files only. The attacks here (tampering, splicing,
edited-down derivation settings, crafted inner documents) are the
ones a sealed file in transit actually faces.
"""

import base64
import json
import struct

import pytest

from aegis import Vault
from aegis.errors import (
    SealedExistsError,
    SealedFormatError,
    SealedSourceError,
    SealedTamperedError,
    VaultFormatError,
    WeakPasswordError,
    WrongFilePasswordError,
)
from aegis.locksend import open_sealed_file, read_sealed_file, seal_file
from aegis.sealed import SEND_MAGIC, SealedWriter

from tests.conftest import FAST_PARAMS as PARAMS
from tests.conftest import PASSWORD, pattern_bytes

SEND_PASSWORD = "a phrase shared for sending"


def _make(tmp_path, name="report.txt", data=b"synthetic report contents"):
    src = tmp_path / name
    src.write_bytes(data)
    return src


def test_round_trip_small_file(tmp_path):
    src = _make(tmp_path)
    sealed = seal_file(src, SEND_PASSWORD, params=PARAMS)
    filename, data = read_sealed_file(sealed, SEND_PASSWORD)
    assert filename == "report.txt"
    assert data == b"synthetic report contents"


def test_round_trip_empty_file(tmp_path):
    src = _make(tmp_path, "empty.bin", b"")
    sealed = seal_file(src, SEND_PASSWORD, params=PARAMS)
    assert read_sealed_file(sealed, SEND_PASSWORD) == ("empty.bin", b"")


def test_round_trip_binary_across_chunks(tmp_path):
    data = pattern_bytes(1_300_001, seed=11)
    src = _make(tmp_path, "blob.bin", data)
    sealed = seal_file(src, SEND_PASSWORD, params=PARAMS)
    assert read_sealed_file(sealed, SEND_PASSWORD) == ("blob.bin", data)


def test_unicode_filename_round_trip(tmp_path):
    src = _make(tmp_path, "résumé — final (2).txt", b"contents")
    sealed = seal_file(src, SEND_PASSWORD, params=PARAMS)
    filename, _ = read_sealed_file(sealed, SEND_PASSWORD)
    assert filename == "résumé — final (2).txt"


def test_open_writes_the_file_out(tmp_path):
    src = _make(tmp_path, data=pattern_bytes(5000, seed=5))
    sealed = seal_file(src, SEND_PASSWORD, params=PARAMS)
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    out = open_sealed_file(sealed, SEND_PASSWORD, inbox)
    assert out.parent == inbox
    assert out.read_bytes() == pattern_bytes(5000, seed=5)


def test_sealed_name_gives_nothing_away(tmp_path):
    src = _make(tmp_path, name="salary-review-2026.txt")
    sealed = seal_file(src, SEND_PASSWORD, params=PARAMS)
    assert sealed.name == "sealed-file.aegis-send"
    assert "salary" not in sealed.name


def test_nothing_readable_in_the_sealed_bytes(tmp_path):
    marker = b"TOP-SECRET-MARKER-12345"
    src = _make(tmp_path, name="marker-file.txt", data=marker * 40)
    sealed = seal_file(src, SEND_PASSWORD, params=PARAMS)
    raw = sealed.read_bytes()
    # Neither the contents nor the file's own name appear anywhere
    # in the sealed file — the header included.
    assert marker not in raw
    assert b"marker-file" not in raw
    header_len = int.from_bytes(raw[10:14], "big")
    assert b"marker-file" not in raw[: 14 + header_len]


def test_wrong_password_is_refused(tmp_path):
    sealed = seal_file(_make(tmp_path), SEND_PASSWORD, params=PARAMS)
    with pytest.raises(WrongFilePasswordError):
        read_sealed_file(sealed, "a completely different phrase")


def test_short_password_is_refused(tmp_path):
    with pytest.raises(WeakPasswordError):
        seal_file(_make(tmp_path), "short", params=PARAMS)


def test_tampered_payload_is_refused(tmp_path):
    sealed = seal_file(
        _make(tmp_path, data=pattern_bytes(3000)), SEND_PASSWORD, params=PARAMS
    )
    raw = bytearray(sealed.read_bytes())
    raw[-5] ^= 0xFF
    sealed.write_bytes(bytes(raw))
    with pytest.raises(SealedTamperedError):
        read_sealed_file(sealed, SEND_PASSWORD)


def test_tampered_header_wrap_reads_as_wrong_password(tmp_path):
    sealed = seal_file(_make(tmp_path), SEND_PASSWORD, params=PARAMS)
    raw = sealed.read_bytes()
    header = json.loads(raw[14 : 14 + int.from_bytes(raw[10:14], "big")])
    wrapped = bytearray(base64.b64decode(header["wrap"]["wrapped_key"]))
    wrapped[0] ^= 0xFF
    header["wrap"]["wrapped_key"] = base64.b64encode(bytes(wrapped)).decode()
    new_header = json.dumps(header).encode()
    sealed.write_bytes(
        raw[:10] + len(new_header).to_bytes(4, "big") + new_header
        + raw[14 + int.from_bytes(raw[10:14], "big"):]
    )
    with pytest.raises(WrongFilePasswordError):
        read_sealed_file(sealed, SEND_PASSWORD)


def test_edited_down_kdf_parameters_are_refused(tmp_path):
    sealed = seal_file(_make(tmp_path), SEND_PASSWORD, params=PARAMS)
    raw = sealed.read_bytes()
    header_len = int.from_bytes(raw[10:14], "big")
    header = json.loads(raw[14 : 14 + header_len])
    header["kdf"]["memory_kib"] = 1024  # below the floor
    new_header = json.dumps(header).encode()
    sealed.write_bytes(
        raw[:10] + len(new_header).to_bytes(4, "big") + new_header
        + raw[14 + header_len:]
    )
    with pytest.raises(SealedFormatError):
        read_sealed_file(sealed, SEND_PASSWORD)


def test_edited_kdf_parameters_within_range_still_refuse(tmp_path):
    # Parameters inside the allowed range are not a format error —
    # but they derive a different key, so the file simply doesn't
    # open. Either way: refusal, never a weaker open.
    sealed = seal_file(_make(tmp_path), SEND_PASSWORD, params=PARAMS)
    raw = sealed.read_bytes()
    header_len = int.from_bytes(raw[10:14], "big")
    header = json.loads(raw[14 : 14 + header_len])
    header["kdf"]["time_cost"] = 2
    new_header = json.dumps(header).encode()
    sealed.write_bytes(
        raw[:10] + len(new_header).to_bytes(4, "big") + new_header
        + raw[14 + header_len:]
    )
    with pytest.raises(WrongFilePasswordError):
        read_sealed_file(sealed, SEND_PASSWORD)


def test_truncated_file_is_refused(tmp_path):
    sealed = seal_file(
        _make(tmp_path, data=pattern_bytes(4000)), SEND_PASSWORD, params=PARAMS
    )
    raw = sealed.read_bytes()
    sealed.write_bytes(raw[: len(raw) - 40])
    with pytest.raises((SealedTamperedError, SealedFormatError)):
        read_sealed_file(sealed, SEND_PASSWORD)


def test_spliced_payload_is_refused(tmp_path):
    # Two files sealed with the SAME password; swapping their
    # payloads must not open — contents are bound to their header.
    a = seal_file(_make(tmp_path, "a.txt", b"aaaa"), SEND_PASSWORD,
                  tmp_path / "a.aegis-send", params=PARAMS)
    b = seal_file(_make(tmp_path, "b.txt", b"bbbb"), SEND_PASSWORD,
                  tmp_path / "b.aegis-send", params=PARAMS)
    raw_a, raw_b = a.read_bytes(), b.read_bytes()
    len_a = 14 + int.from_bytes(raw_a[10:14], "big")
    len_b = 14 + int.from_bytes(raw_b[10:14], "big")
    a.write_bytes(raw_a[:len_a] + raw_b[len_b:])
    with pytest.raises(SealedTamperedError):
        read_sealed_file(a, SEND_PASSWORD)


def test_sealing_never_overwrites(tmp_path):
    src = _make(tmp_path)
    seal_file(src, SEND_PASSWORD, params=PARAMS)
    with pytest.raises(SealedExistsError):
        seal_file(src, SEND_PASSWORD, params=PARAMS)


def test_opening_never_overwrites(tmp_path):
    src = _make(tmp_path, data=b"new contents")
    sealed = seal_file(src, SEND_PASSWORD, params=PARAMS)
    existing = tmp_path / "report.txt"
    existing.write_bytes(b"the file that was already here")
    with pytest.raises(SealedExistsError):
        open_sealed_file(sealed, SEND_PASSWORD, tmp_path)
    assert existing.read_bytes() == b"the file that was already here"


def test_seal_a_folder_or_missing_file_is_refused(tmp_path):
    with pytest.raises(SealedSourceError):
        seal_file(tmp_path, SEND_PASSWORD, params=PARAMS)
    with pytest.raises(SealedSourceError):
        seal_file(tmp_path / "not-there.txt", SEND_PASSWORD, params=PARAMS)


def test_format_separation_vault_is_not_a_send_file(tmp_path, create_vault):
    _, vault_file = create_vault()
    with pytest.raises(SealedFormatError):
        read_sealed_file(vault_file, PASSWORD)


def test_format_separation_send_file_is_not_a_vault(tmp_path):
    sealed = seal_file(_make(tmp_path), SEND_PASSWORD, params=PARAMS)
    with pytest.raises(VaultFormatError):
        Vault.open(sealed, password=SEND_PASSWORD)


def test_crafted_inner_name_cannot_escape(tmp_path):
    # An inner "file name" that is really a path must be refused,
    # and nothing may be written outside the target folder.
    path = tmp_path / "crafted.aegis-send"
    manifest = json.dumps(
        {"version": 1, "filename": "../escape.txt"}
    ).encode()
    with open(path, "wb") as handle:
        with SealedWriter(
            handle, magic=SEND_MAGIC, password=SEND_PASSWORD, params=PARAMS
        ) as writer:
            writer.write(struct.pack(">I", len(manifest)))
            writer.write(manifest)
            writer.write(b"payload")
    with pytest.raises(SealedTamperedError):
        open_sealed_file(path, SEND_PASSWORD, tmp_path)
    assert not (tmp_path.parent / "escape.txt").exists()
    assert not (tmp_path / "escape.txt").exists()


def test_open_into_missing_folder_is_a_plain_refusal(tmp_path):
    sealed = seal_file(_make(tmp_path), SEND_PASSWORD, params=PARAMS)
    with pytest.raises(Exception) as excinfo:
        open_sealed_file(sealed, SEND_PASSWORD, tmp_path / "no-such-folder")
    assert "folder isn't there" in str(excinfo.value)
