"""Phase 3 — Lazarus's armor: a whole folder, sealed as one set.

The set under test is a synthetic stand-in for a backup store:
plain files in plain folders, patterned bytes, no real backups.
The attacks are the ones a sealed set actually faces: tampered
bytes, crafted manifests trying to write outside the destination,
and sets that lie about what they hold.
"""

import hashlib
import json
import os
import struct

import pytest

from aegis import Vault
from aegis.armor import armor_manifest, seal_tree, unseal_tree
from aegis.errors import (
    ArmorRefusalError,
    SealedExistsError,
    SealedFormatError,
    SealedTamperedError,
    VaultFormatError,
    WrongFilePasswordError,
)
from aegis.locksend import read_sealed_file
from aegis.sealed import ARMOR_MAGIC, SealedWriter

from tests.conftest import FAST_PARAMS as PARAMS
from tests.conftest import pattern_bytes

ARMOR_PASSWORD = "a phrase for the backup set"


def _tree(tmp_path, name="store"):
    root = tmp_path / name
    (root / "snapshots" / "s1").mkdir(parents=True)
    (root / "empty-dir").mkdir()
    (root / "store.json").write_bytes(b'{"synthetic": true}')
    (root / "snapshots" / "s1" / "blob.bin").write_bytes(
        pattern_bytes(128_000, seed=9)
    )
    (root / "empty.txt").write_bytes(b"")
    return root


def _snapshot(root):
    return {
        p.relative_to(root).as_posix(): (p.read_bytes() if p.is_file() else None)
        for p in sorted(root.rglob("*"))
    }


def _craft(tmp_path, manifest_doc, payload=b"", name="crafted.aegis-armored"):
    """Seal a hand-made manifest + payload with the real engine."""
    path = tmp_path / name
    raw = json.dumps(manifest_doc).encode()
    with open(path, "wb") as handle:
        with SealedWriter(
            handle, magic=ARMOR_MAGIC, password=ARMOR_PASSWORD, params=PARAMS
        ) as writer:
            writer.write(struct.pack(">I", len(raw)))
            writer.write(raw)
            writer.write(payload)
    return path


def _manifest(files, dirs=()):
    return {
        "version": 1,
        "created_utc": "2026-10-20T00:00:00+00:00",
        "dirs": list(dirs),
        "files": files,
    }


def _info(path, data):
    return {
        "path": path,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def test_round_trip_byte_identical(tmp_path):
    root = _tree(tmp_path)
    sealed = seal_tree(root, ARMOR_PASSWORD, params=PARAMS)
    assert sealed.name == "store.aegis-armored"
    back = tmp_path / "restored"
    unseal_tree(sealed, ARMOR_PASSWORD, back)
    assert _snapshot(root) == _snapshot(back)


def test_manifest_lists_the_set(tmp_path):
    root = _tree(tmp_path)
    sealed = seal_tree(root, ARMOR_PASSWORD, params=PARAMS)
    manifest = armor_manifest(sealed, ARMOR_PASSWORD)
    paths = {f.path for f in manifest.files}
    assert paths == {"store.json", "snapshots/s1/blob.bin", "empty.txt"}
    assert set(manifest.dirs) == {"empty-dir", "snapshots", "snapshots/s1"}
    blob = next(f for f in manifest.files if f.path.endswith("blob.bin"))
    assert blob.size == 128_000
    assert blob.sha256 == hashlib.sha256(
        pattern_bytes(128_000, seed=9)
    ).hexdigest()
    assert manifest.total_bytes == sum(f.size for f in manifest.files)


def test_empty_folder_seals_and_unseals(tmp_path):
    root = tmp_path / "bare"
    root.mkdir()
    sealed = seal_tree(root, ARMOR_PASSWORD, params=PARAMS)
    back = tmp_path / "bare-back"
    unseal_tree(sealed, ARMOR_PASSWORD, back)
    assert back.is_dir()
    assert list(back.iterdir()) == []


def test_wrong_password_is_refused(tmp_path):
    sealed = seal_tree(_tree(tmp_path), ARMOR_PASSWORD, params=PARAMS)
    with pytest.raises(WrongFilePasswordError):
        armor_manifest(sealed, "a completely different phrase")
    with pytest.raises(WrongFilePasswordError):
        unseal_tree(sealed, "a completely different phrase", tmp_path / "x")


def test_tampered_bytes_fail_and_leave_nothing(tmp_path):
    sealed = seal_tree(_tree(tmp_path), ARMOR_PASSWORD, params=PARAMS)
    raw = bytearray(sealed.read_bytes())
    raw[-20] ^= 0xFF  # inside the last file's sealed region
    sealed.write_bytes(bytes(raw))
    dest = tmp_path / "restored"
    with pytest.raises((SealedTamperedError,)):
        unseal_tree(sealed, ARMOR_PASSWORD, dest)
    assert not dest.exists()
    leftovers = [p.name for p in tmp_path.iterdir() if "unsealing" in p.name]
    assert leftovers == []


def test_crafted_check_value_mismatch_names_the_file(tmp_path):
    data = b"the bytes that are really inside"
    doc = _manifest([_info("inner.txt", b"different bytes entirely")])
    crafted = _craft(tmp_path, doc, payload=data)
    dest = tmp_path / "out"
    with pytest.raises(SealedTamperedError) as excinfo:
        unseal_tree(crafted, ARMOR_PASSWORD, dest)
    assert "inner.txt" in str(excinfo.value)
    assert not dest.exists()


@pytest.mark.parametrize(
    "bad_path",
    [
        "../escape.txt",
        "a/../../escape.txt",
        "/absolute.txt",
        "a\\b.txt",
        "a//b.txt",
        "./a.txt",
        "a/./b.txt",
        "",
    ],
)
def test_crafted_traversal_paths_are_refused(tmp_path, bad_path):
    doc = _manifest([_info(bad_path, b"x")])
    crafted = _craft(tmp_path, doc, payload=b"x")
    dest = tmp_path / "out"
    with pytest.raises(SealedTamperedError):
        unseal_tree(crafted, ARMOR_PASSWORD, dest)
    assert not dest.exists()
    assert not (tmp_path / "escape.txt").exists()


def test_crafted_case_duplicate_paths_are_refused(tmp_path):
    doc = _manifest([_info("Report.txt", b"a"), _info("report.txt", b"b")])
    crafted = _craft(tmp_path, doc, payload=b"ab")
    with pytest.raises(SealedTamperedError):
        unseal_tree(crafted, ARMOR_PASSWORD, tmp_path / "out")


def test_crafted_file_blocking_a_folder_is_refused(tmp_path):
    doc = _manifest([_info("a", b"x"), _info("a/b.txt", b"y")])
    crafted = _craft(tmp_path, doc, payload=b"xy")
    with pytest.raises(SealedTamperedError):
        unseal_tree(crafted, ARMOR_PASSWORD, tmp_path / "out")


def test_crafted_oversized_size_claim_is_refused(tmp_path):
    doc = _manifest(
        [{"path": "f.txt", "size": 10_000, "sha256": "0" * 64}]
    )
    crafted = _craft(tmp_path, doc, payload=b"short")
    with pytest.raises(SealedTamperedError):
        unseal_tree(crafted, ARMOR_PASSWORD, tmp_path / "out")


def test_crafted_trailing_data_is_refused(tmp_path):
    doc = _manifest([_info("f.txt", b"abc")])
    crafted = _craft(tmp_path, doc, payload=b"abcEXTRA")
    with pytest.raises(SealedTamperedError):
        unseal_tree(crafted, ARMOR_PASSWORD, tmp_path / "out")


def test_unseal_never_overwrites(tmp_path):
    sealed = seal_tree(_tree(tmp_path), ARMOR_PASSWORD, params=PARAMS)
    dest = tmp_path / "restored"
    dest.mkdir()
    (dest / "keep.txt").write_bytes(b"keep me")
    with pytest.raises(SealedExistsError):
        unseal_tree(sealed, ARMOR_PASSWORD, dest)
    assert (dest / "keep.txt").read_bytes() == b"keep me"


def test_seal_never_overwrites(tmp_path):
    root = _tree(tmp_path)
    seal_tree(root, ARMOR_PASSWORD, params=PARAMS)
    with pytest.raises(SealedExistsError):
        seal_tree(root, ARMOR_PASSWORD, params=PARAMS)


def test_seal_destination_inside_the_tree_is_refused(tmp_path):
    root = _tree(tmp_path)
    with pytest.raises(ArmorRefusalError):
        seal_tree(
            root, ARMOR_PASSWORD, root / "inside.aegis-armored", params=PARAMS
        )


def test_seal_refuses_a_linked_file(tmp_path):
    root = _tree(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside the folder")
    os.symlink(outside, root / "linked.txt")
    with pytest.raises(ArmorRefusalError):
        seal_tree(root, ARMOR_PASSWORD, params=PARAMS)


def test_seal_refuses_a_linked_folder(tmp_path):
    root = _tree(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, root / "linked-dir", target_is_directory=True)
    with pytest.raises(ArmorRefusalError):
        seal_tree(root, ARMOR_PASSWORD, params=PARAMS)


def test_seal_refuses_a_missing_folder(tmp_path):
    with pytest.raises(ArmorRefusalError):
        seal_tree(tmp_path / "not-there", ARMOR_PASSWORD, params=PARAMS)


def test_format_separation(tmp_path, create_vault):
    sealed = seal_tree(_tree(tmp_path), ARMOR_PASSWORD, params=PARAMS)
    # An armored set is not a vault, and not a send file.
    with pytest.raises(VaultFormatError):
        Vault.open(sealed, password=ARMOR_PASSWORD)
    with pytest.raises(SealedFormatError):
        read_sealed_file(sealed, ARMOR_PASSWORD)
    # A vault is not an armored set.
    _, vault_file = create_vault()
    with pytest.raises(SealedFormatError):
        armor_manifest(vault_file, ARMOR_PASSWORD)
