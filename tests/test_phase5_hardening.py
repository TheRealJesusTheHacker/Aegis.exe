"""Phase 5 hardening pins.

- F-1: output work that finishes after a lock places NOTHING.
- F-2: confirmation dialogs run under the tracked-dialog path.
- F-3: Windows-unsafe names refused at string level, everywhere.
- Memory: staged buffers and caches are emptied in place.
- CRT: no raw os.write / text-mode binary paths anywhere.
- KDF: shipped params are the RFC 9106 first profile; ceilings
  are refused before derivation.
- Packaging: version triangulation + portable exclusion rules.
"""

import os, re, time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from conftest import FAST_PARAMS, PASSWORD

ROOT = Path(__file__).parent.parent

# -- F-1 (controller/armor level: deterministic, no threads) ------

def test_unseal_places_nothing_when_guard_withdrawn(tmp_path):
    from aegis.armor import seal_tree, unseal_tree
    from aegis.errors import VaultLockedError

    src = tmp_path / "set"; src.mkdir()
    (src / "note.txt").write_bytes(b"synthetic contents\n" * 100)
    sealed = seal_tree(src, "a shared phrase", tmp_path / "set.aegis-armored")
    dest = tmp_path / "opened"
    with pytest.raises(VaultLockedError):
        unseal_tree(sealed, "a shared phrase", dest, place_guard=lambda: False)
    assert not dest.exists()
    assert not list(tmp_path.glob("*.unsealing-*"))  # staging removed

def test_unseal_places_when_guard_holds(tmp_path):
    from aegis.armor import seal_tree, unseal_tree

    src = tmp_path / "set"; src.mkdir()
    (src / "note.txt").write_bytes(b"synthetic contents")
    sealed = seal_tree(src, "a shared phrase", tmp_path / "set.aegis-armored")
    dest = tmp_path / "opened"
    unseal_tree(sealed, "a shared phrase", dest, place_guard=lambda: True)
    assert (dest / "note.txt").read_bytes() == b"synthetic contents"

def test_locksend_open_places_nothing_when_guard_withdrawn(tmp_path):
    from aegis.clipboard import MemoryClipboard
    from aegis.errors import VaultLockedError
    from aegis.locksend import seal_file
    from aegis.ui.controllers import VaultController

    plain = tmp_path / "plain.txt"; plain.write_bytes(b"synthetic secret text")
    sealed = seal_file(plain, "a shared phrase")
    out_dir = tmp_path / "out"; out_dir.mkdir()
    controller = VaultController(MemoryClipboard())
    with pytest.raises(VaultLockedError):
        controller.open_a_sealed_file(sealed, "a shared phrase", out_dir,
                                      place_guard=lambda: False)
    assert list(out_dir.iterdir()) == []

def test_locksend_open_places_when_guard_holds(tmp_path):
    from aegis.clipboard import MemoryClipboard
    from aegis.locksend import seal_file
    from aegis.ui.controllers import VaultController

    plain = tmp_path / "plain.txt"; plain.write_bytes(b"synthetic secret text")
    sealed = seal_file(plain, "a shared phrase")
    out_dir = tmp_path / "out"; out_dir.mkdir()
    controller = VaultController(MemoryClipboard())
    placed = controller.open_a_sealed_file(sealed, "a shared phrase", out_dir,
                                           place_guard=lambda: True)
    assert placed.read_bytes() == b"synthetic secret text"

# -- F-3 -----------------------------------------------------------

@pytest.mark.parametrize("name", ["NUL", "nul.txt", "CON", "com1.log", "LPT9",
                                  "notes.", "notes ", "file."])
def test_locksend_refuses_windows_unsafe_names(name):
    import json
    from aegis.errors import SealedTamperedError
    from aegis.locksend import _parse_inner_manifest

    raw = json.dumps({"version": 1, "filename": name}).encode()
    with pytest.raises(SealedTamperedError):
        _parse_inner_manifest(raw)

@pytest.mark.parametrize("path", ["docs/NUL.txt", "docs/notes./x.txt",
                                  "aux/file.txt", "docs/file "])
def test_armor_refuses_windows_unsafe_paths(path):
    from aegis.armor import _validate_rel_path
    from aegis.errors import SealedTamperedError

    with pytest.raises(SealedTamperedError):
        _validate_rel_path(path)

@pytest.mark.parametrize("name", ["NUL", "con.txt", "name.", "name "])
def test_strongbox_refuses_windows_unsafe_names(name):
    from aegis.errors import InvalidStrongboxEntryError
    from aegis.strongbox import _check_filename

    with pytest.raises(InvalidStrongboxEntryError):
        _check_filename(name)

def test_plain_names_still_accepted():
    from aegis.armor import _validate_rel_path
    from aegis.strongbox import _check_filename

    assert _validate_rel_path("docs/notes.txt") == "docs/notes.txt"
    assert _check_filename("notes.txt") == "notes.txt"

# -- memory --------------------------------------------------------

def test_sealed_writer_close_zeroes_staging_buffer():
    import io
    from aegis.sealed import SEND_MAGIC, SealedWriter

    buf = io.BytesIO()
    writer = SealedWriter(buf, magic=SEND_MAGIC, password="a shared phrase",
                          params=FAST_PARAMS)
    writer.write(b"partial synthetic chunk")
    staged = writer._buffer
    writer.close()
    assert bytes(staged) == b"\x00" * len(staged)
    assert bytes(writer._file_key) == b"\x00" * len(writer._file_key)

def test_credential_store_forget_empties_the_list_itself(tmp_path):
    from aegis.credentials import CredentialStore
    from aegis.vault import Vault

    path = tmp_path / "v.aegis"
    created = Vault.create(path, PASSWORD, params=FAST_PARAMS)
    store = CredentialStore(created.session)
    store.add("Example", password="synthetic-password")
    held = store._entries
    assert held
    store.forget()
    assert held == [] and store._entries is None
    created.session.lock()

def test_session_lock_empties_held_contents(tmp_path):
    from aegis.vault import Vault

    path = tmp_path / "v.aegis"
    created = Vault.create(path, PASSWORD, params=FAST_PARAMS)
    session = created.session
    session.write("note.txt", b"synthetic contents")
    held = session._entries
    key = session._vault_key
    session.lock()
    assert held == {}
    assert bytes(key) == b"\x00" * len(key)

# -- CRT / binary-write sweep --------------------------------------

def test_no_raw_os_write_or_text_mode_binary_paths():
    offenders = []
    for py in (ROOT / "aegis").rglob("*.py"):
        text = py.read_text(encoding="utf-8", errors="replace")
        if "os.write(" in text:
            offenders.append(f"{py}: raw os.write")
        for m in re.finditer(r'open\([^)]*"(w|a|x)[^b"]*"\)', text):
            offenders.append(f"{py}: text-mode write open: {m.group(0)}")
    for py in (ROOT / "packaging").glob("*.py"):
        text = py.read_text(encoding="utf-8", errors="replace")
        if "os.write(" in text:
            offenders.append(f"{py}: raw os.write")
    assert offenders == []

def test_binary_payload_roundtrip_keeps_crlf_bytes(tmp_path):
    # The fleet hazard in one payload: bytes that text mode on
    # Windows would rewrite must survive seal/open byte-for-byte.
    from aegis.locksend import open_sealed_file, seal_file

    payload = b"line one\r\nline two\n\x00\xff\r\n"
    plain = tmp_path / "p.bin"; plain.write_bytes(payload)
    sealed = seal_file(plain, "a shared phrase")
    out = tmp_path / "out"; out.mkdir()
    placed = open_sealed_file(sealed, "a shared phrase", out)
    assert placed.read_bytes() == payload

# -- KDF -----------------------------------------------------------

def test_shipped_params_are_rfc9106_first_profile():
    from aegis.kdf import DEFAULT_PARAMS

    assert (DEFAULT_PARAMS.memory_kib, DEFAULT_PARAMS.time_cost,
            DEFAULT_PARAMS.parallelism) == (65536, 3, 4)

def test_ceiling_header_refused_before_derivation():
    from aegis.errors import VaultFormatError
    from aegis.kdf import KdfParams, validate_params

    start = time.perf_counter()
    with pytest.raises(VaultFormatError):
        validate_params(KdfParams(memory_kib=2 * 1024 * 1024, time_cost=3,
                                  parallelism=4))
    assert time.perf_counter() - start < 0.05  # refused, not derived

# -- packaging -----------------------------------------------------

def test_version_triangulation():
    import aegis

    spec = (ROOT / "packaging" / "Aegis.spec").read_text()
    assert aegis.__version__ == "1.0.6"
    assert '"1.0.6"' in spec and "(1, 0, 6, 0)" in spec

def test_portable_builder_refuses_vaults_and_tests(tmp_path):
    import sys
    sys.path.insert(0, str(ROOT / "tools"))
    from build_portable import build

    src = tmp_path / "Aegis"; src.mkdir()
    (src / "Aegis.exe").write_bytes(b"synthetic exe")
    (src / "secret.aegis").write_bytes(b"synthetic vault")
    with pytest.raises(AssertionError):
        build(src, tmp_path / "out.zip", ROOT / "packaging" / "README-PORTABLE.txt")

def test_portable_zip_opens_to_one_folder(tmp_path):
    import sys, zipfile
    sys.path.insert(0, str(ROOT / "tools"))
    from build_portable import build

    src = tmp_path / "Aegis"; src.mkdir()
    (src / "Aegis.exe").write_bytes(b"synthetic exe")
    out = tmp_path / "AegisPortable.zip"
    build(src, out, ROOT / "packaging" / "README-PORTABLE.txt")
    names = zipfile.ZipFile(out).namelist()
    assert names and all(n.startswith("Aegis/") for n in names)
    assert "Aegis/README-PORTABLE.txt" in names

# -- F-2 (Qt; runs where a QApplication can start) ------------------

@pytest.fixture(scope="session")
def qapp():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])

def test_confirm_dialog_is_closed_by_lock(qapp, tmp_path):
    # The confirmation is built as a tracked dialog: starting one
    # and locking must leave no dialog standing and answer "no".
    from aegis.clipboard import MemoryClipboard
    from aegis.ui import app as app_module
    from aegis.ui.app import MainWindow
    from aegis.ui.controllers import VaultController
    from aegis.vault import Vault

    path = tmp_path / "vault.aegis"
    created = Vault.create(path, PASSWORD, params=FAST_PARAMS)
    created.session.lock()
    window = MainWindow(VaultController(MemoryClipboard()))
    window.show()
    try:
        seen = {}

        def answer_later():
            from PySide6.QtWidgets import QMessageBox
            boxes = [w for w in window.findChildren(QMessageBox) if w.isVisible()]
            seen["boxes"] = boxes
            window._lock_now()

        from PySide6.QtCore import QTimer
        QTimer.singleShot(200, answer_later)
        result = app_module._confirm(window, "Delete this login?")
        assert result is False
        assert seen.get("boxes")  # a real dialog was standing
    finally:
        window.close()
        window.deleteLater()
        qapp.processEvents()

# -- self-install (launcher layer; mechanism proven offscreen) -----

def test_install_places_a_verified_copy_and_uninstall_removes_it(tmp_path, monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "aegis_install", ROOT / "packaging" / "install.py")
    install = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(install)
    monkeypatch.setenv("AEGIS_INSTALL_ROOT", str(tmp_path / "root"))
    source = tmp_path / "build"; source.mkdir()
    (source / "Aegis.exe").write_bytes(b"synthetic exe bytes")
    (source / "lib.bin").write_bytes(b"synthetic lib")
    ok, message = install.install(source)
    assert ok, message
    placed = tmp_path / "root" / "Aegis" / "Aegis.exe"
    assert placed.read_bytes() == b"synthetic exe bytes"
    ok, message = install.install(source)  # already home: heals/no-ops cleanly
    assert ok
    ok, message = install.uninstall()
    assert ok and not (tmp_path / "root" / "Aegis").exists()
    assert "vault" in message.lower()  # the promise: vaults untouched
