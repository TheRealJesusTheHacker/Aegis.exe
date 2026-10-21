"""Kit-hunt regressions (v1.0.2): real-drive and Windows-name behavior.

Every test here pins a defect found by hunting the class a
Linux test process cannot reach on its own — drives without
hard links (the USB sticks a portable copy travels on), files
busy for a moment under Windows, and names that mean something
else under Windows name rules. Each test fails on the v1.0.1
code for the reason stated in its docstring and passes after
the fix. Windows-only probes at the bottom pin the frozen
build's assumptions on the Windows runners instead.
"""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

from aegis import format as _format
from aegis.armor import _validate_rel_path, seal_tree, unseal_tree
from aegis.errors import (
    ArmorRefusalError,
    SealedSaveError,
    SealedSourceError,
    SealedTamperedError,
    VaultSaveError,
)
from aegis.locksend import _parse_inner_manifest, _inner_manifest, seal_file
from aegis.sealed import write_new_file
from aegis.strongbox import _check_filename
from aegis.transfer import export_sealed_copy
from aegis.vault import Vault

from conftest import FAST_PARAMS, PASSWORD

PW = PASSWORD


# -- Windows name rules: the colon and the console's own names ------


@pytest.mark.parametrize(
    "name",
    [
        "evil.txt:payload",
        "notes.txt::$DATA",
        "C:evil.txt",
        "C:",
        "a:b",
        "CONIN$",
        "CONOUT$",
        "conin$.txt",
    ],
)
def test_windows_unsafe_segment_refuses_colons_and_console_names(name):
    """v1.0.1 accepted every one of these: a colon spells a drive
    or a hidden side-stream on Windows, and CONIN$/CONOUT$ are
    the console's own names, so such a name lands somewhere
    other than where it says."""
    assert _format.windows_unsafe_segment(name)


@pytest.mark.parametrize(
    "path", ["evil.txt:payload", "C:/abs.txt", "sub/C:evil.txt", "a.txt::$DATA"]
)
def test_armor_manifest_path_refuses_colons(path):
    """An armored set carrying a colon path used to pass the
    confinement checks textually and then write a side-stream
    (or, for a drive spelling, leave the folder) on Windows."""
    with pytest.raises(SealedTamperedError):
        _validate_rel_path(path)


@pytest.mark.parametrize("name", ["evil.txt:payload", "C:evil.txt"])
def test_locksend_inner_name_refuses_colons(name):
    """A crafted Lock-and-send file's inner name is placed with
    no confinement check at all beyond the name rules — a
    drive-relative spelling used to escape the chosen folder."""
    with pytest.raises(SealedTamperedError):
        _parse_inner_manifest(_inner_manifest(name))


def test_strongbox_filename_refuses_colons():
    with pytest.raises(Exception):
        _check_filename("evil.txt:payload")


# -- Sealing refuses unusable names up front -------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="these names cannot be created as plain files on Windows",
)
def test_seal_tree_refuses_windows_unusable_names(tmp_path):
    """v1.0.1 sealed this folder happily and produced a set its
    own unseal refused as 'changed or damaged' — a set that
    could never be opened, reported as damage."""
    tree = tmp_path / "set"
    tree.mkdir()
    (tree / "CON.txt").write_bytes(b"device name")
    (tree / "a:b.txt").write_bytes(b"colon name")
    with pytest.raises(ArmorRefusalError):
        seal_tree(tree, PASSWORD, params=FAST_PARAMS)
    assert not (tmp_path / "set.aegis-armored").exists()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="these names cannot be created as plain files on Windows",
)
def test_seal_file_refuses_windows_unusable_source_name(tmp_path):
    src = tmp_path / "a:b.txt"
    src.write_bytes(b"colon name")
    with pytest.raises(SealedSourceError):
        seal_file(src, PASSWORD, params=FAST_PARAMS)
    assert not (tmp_path / "sealed-file.aegis-send").exists()


# -- Names Aegis writes to are checked the same way ------------------


def test_vault_create_refuses_device_name(tmp_path):
    """v1.0.1 created a vault at a device name without a word;
    on Windows that name is the device, not a file."""
    target = tmp_path / "CON.aegis"
    with pytest.raises(VaultSaveError):
        Vault.create(target, PASSWORD, params=FAST_PARAMS)
    assert not target.exists()


def test_write_new_file_refuses_device_name(tmp_path):
    target = tmp_path / "nul.bin"
    with pytest.raises(SealedSaveError):
        write_new_file(target, lambda handle: handle.write(b"x"))
    assert not target.exists()


def test_export_refuses_device_name(tmp_path):
    created = Vault.create(tmp_path / "v.aegis", PASSWORD, params=FAST_PARAMS)
    try:
        with pytest.raises(VaultSaveError):
            export_sealed_copy(created.session, tmp_path / "aux.aegis")
    finally:
        created.session.lock()


def test_unseal_refuses_device_named_destination(tmp_path):
    tree = tmp_path / "set"
    tree.mkdir()
    (tree / "plain.txt").write_bytes(b"plain")
    sealed = seal_tree(tree, PASSWORD, params=FAST_PARAMS)
    with pytest.raises(SealedSaveError):
        unseal_tree(sealed, PASSWORD, tmp_path / "opened.")


# -- Drives without links --------------------------------------------


def _no_links(monkeypatch):
    def raise_no_link(src, dst):
        raise OSError(errno.EXDEV, "this drive cannot hold links")

    monkeypatch.setattr(os, "link", raise_no_link)


def test_vault_create_works_on_a_drive_without_links(tmp_path, monkeypatch):
    """Simulates a FAT/exFAT USB stick: v1.0.1 failed vault
    creation outright there, with a message about room on the
    drive that had plenty."""
    _no_links(monkeypatch)
    target = tmp_path / "stick.aegis"
    created = Vault.create(target, PASSWORD, params=FAST_PARAMS)
    created.session.lock()
    assert target.exists()
    reopened = Vault.open(target, password=PW)
    reopened.lock()


def test_write_new_file_works_on_a_drive_without_links(tmp_path, monkeypatch):
    _no_links(monkeypatch)
    target = tmp_path / "out.bin"
    result = write_new_file(target, lambda handle: handle.write(b"finished bytes"))
    assert result == target
    assert target.read_bytes() == b"finished bytes"


def test_export_works_on_a_drive_without_links(tmp_path, monkeypatch):
    created = Vault.create(tmp_path / "v.aegis", PASSWORD, params=FAST_PARAMS)
    try:
        _no_links(monkeypatch)
        dest = export_sealed_copy(created.session, tmp_path / "copy.aegis")
        assert dest.read_bytes() == (tmp_path / "v.aegis").read_bytes()
    finally:
        created.session.lock()


def test_link_fallback_still_refuses_an_existing_name(tmp_path, monkeypatch):
    """The claimed-name copy must keep the never-overwrite rule:
    a name taken after the first check is still refused."""
    _no_links(monkeypatch)
    target = tmp_path / "out.bin"

    def write_and_race(handle):
        handle.write(b"mine")
        target.write_bytes(b"someone else was first")

    with pytest.raises(Exception):
        write_new_file(target, write_and_race)
    assert target.read_bytes() == b"someone else was first"


# -- Files busy for a moment ------------------------------------------


def test_vault_save_waits_out_a_briefly_busy_file(tmp_path, monkeypatch):
    """v1.0.1 gave up on the first refusal: one momentary
    in-use error during the publish failed the whole save."""
    created = Vault.create(tmp_path / "v.aegis", PASSWORD, params=FAST_PARAMS)
    session = created.session
    session.write("note.txt", b"hello")
    real_replace = os.replace
    attempts = {"count": 0}
    vault_file = tmp_path / "v.aegis"

    def flaky_replace(src, dst):
        # Only the vault file's own publish is made flaky (and
        # counted): since v1.0.5 a save also publishes the
        # rollback tripwire's record, a separate file whose
        # publish is not this regression's subject.
        if Path(dst) != vault_file:
            return real_replace(src, dst)
        attempts["count"] += 1
        if attempts["count"] <= 2:
            raise PermissionError(errno.EACCES, "busy for a moment")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)
    session.save()
    assert attempts["count"] == 3
    session.lock()
    reopened = Vault.open(tmp_path / "v.aegis", password=PW)
    assert reopened.read("note.txt") == b"hello"
    reopened.lock()


def test_vault_save_still_reports_a_busy_file_that_stays_busy(
    tmp_path, monkeypatch
):
    """The wait is bounded: a file that stays busy is reported,
    and the session stays open with its changes unsaved."""
    created = Vault.create(tmp_path / "v.aegis", PASSWORD, params=FAST_PARAMS)
    session = created.session
    session.write("note.txt", b"hello")

    def always_busy(src, dst):
        raise PermissionError(errno.EACCES, "still busy")

    monkeypatch.setattr(os, "replace", always_busy)
    with pytest.raises(VaultSaveError):
        session.save()
    assert not session.is_locked
    session._dirty = False  # let the fixture-free session close quietly
    session.lock()


def test_unseal_waits_out_a_briefly_busy_move(tmp_path, monkeypatch):
    """The finished folder's move into place gets the same
    patience: v1.0.1 failed the whole unseal on one refusal."""
    tree = tmp_path / "set"
    tree.mkdir()
    (tree / "plain.txt").write_bytes(b"plain")
    sealed = seal_tree(tree, PASSWORD, params=FAST_PARAMS)
    real_rename = os.rename
    attempts = {"count": 0}

    def flaky_rename(src, dst):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise PermissionError(errno.EACCES, "busy for a moment")
        return real_rename(src, dst)

    monkeypatch.setattr(os, "rename", flaky_rename)
    dest = unseal_tree(sealed, PASSWORD, tmp_path / "opened")
    assert (dest / "plain.txt").read_bytes() == b"plain"
    assert attempts["count"] == 2


def test_install_detection_verbatim_prefix_spelling(tmp_path):
    """Windows CI proved this one live: the installed home
    spelled with the verbatim prefix was NOT recognized as
    installed on Windows, so a copy started through that
    spelling would have been offered an install it did not
    need. The comparison now settles both spellings alike;
    this pin runs on every platform because the settling is
    string-level."""
    from aegis.install_state import running_from_installed_home

    home = tmp_path / "Installed Home"
    home.mkdir()
    assert running_from_installed_home(home, home=home)
    assert running_from_installed_home("\\\\?\\" + str(home), home=home)
    assert not running_from_installed_home(tmp_path / "elsewhere", home=home)


# -- Windows-only probes (run on the Windows CI runners) ---------------


@pytest.mark.skipif(sys.platform != "win32", reason="Windows path rules only")
def test_windows_long_path_vault_roundtrip(tmp_path):
    """A vault path past the classic 260-character limit must
    create, save, and reopen — the packaged build declares
    itself long-path aware, and this pins that it holds."""
    deep = tmp_path
    while len(str(deep)) < 240:
        deep = deep / ("a" * 24)
    deep.mkdir(parents=True)
    target = deep / "vault.aegis"
    assert len(str(target)) > 260
    created = Vault.create(target, PASSWORD, params=FAST_PARAMS)
    created.session.write("note.txt", b"deep down")
    created.session.save()
    created.session.lock()
    reopened = Vault.open(target, password=PW)
    assert reopened.read("note.txt") == b"deep down"
    reopened.lock()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows path rules only")
def test_windows_install_detection_short_and_prefixed_spellings(tmp_path):
    """Install detection must not be fooled by the same folder
    spelled as an 8.3 short name or with the long-path prefix:
    a false 'not installed' nags with the offer, and a false
    'installed' skips it."""
    import ctypes

    from aegis.install_state import running_from_installed_home

    home = tmp_path / "Installed Home Folder"
    home.mkdir()
    (home / "Aegis.exe").write_bytes(b"exe")
    assert running_from_installed_home(home, home=home)
    assert running_from_installed_home(str(home).upper(), home=home)
    assert running_from_installed_home("\\\\?\\" + str(home), home=home)
    buf = ctypes.create_unicode_buffer(1024)
    got = ctypes.windll.kernel32.GetShortPathNameW(str(home), buf, 1024)
    if got:
        assert running_from_installed_home(buf.value, home=home)
