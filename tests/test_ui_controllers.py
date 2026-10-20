"""Phase 4 controller tests: the interface's behavior, headless.

The controller layer is Qt-free on purpose, so everything the
window does — open, lock, copy, idle, every flow — is proven here
without a screen. All data is synthetic, per the house rules.
"""

from pathlib import Path

import pytest

from aegis.clipboard import MemoryClipboard
from aegis.errors import (
    DocumentTooLargeError,
    InvalidStrongboxEntryError,
    SealedExistsError,
    VaultLockedError,
    WrongFilePasswordError,
    WrongPasswordError,
)
from aegis.ui.controllers import VaultController, user_text

from conftest import FAST_PARAMS, PASSWORD, WRONG_PASSWORD, pattern_bytes


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def port():
    return MemoryClipboard()


@pytest.fixture
def controller(port, clock):
    return VaultController(port, clock=clock)


@pytest.fixture
def open_controller(controller, tmp_path):
    recovery = controller.create_vault(
        tmp_path / "vault.aegis", PASSWORD, params=FAST_PARAMS
    )
    return controller, recovery


# -- open / lock ------------------------------------------------------


def test_create_open_lock_roundtrip(controller, tmp_path):
    path = tmp_path / "vault.aegis"
    recovery = controller.create_vault(path, PASSWORD, params=FAST_PARAMS)
    assert recovery  # shown once, at setup
    assert controller.is_open
    controller.lock()
    assert not controller.is_open

    controller.open_vault(path, password=PASSWORD)
    assert controller.is_open
    controller.lock()

    controller.open_vault(path, recovery_key=recovery)
    assert controller.is_open
    controller.lock()

    with pytest.raises(WrongPasswordError):
        controller.open_vault(path, password=WRONG_PASSWORD)


def test_lock_wipes_session_key_and_blocks_use(open_controller):
    controller, _recovery = open_controller
    session = controller.session
    controller.lock()
    assert session.is_locked
    assert session._vault_key is None  # the Phase 1 wipe, reached
    with pytest.raises(VaultLockedError):
        controller.store
    with pytest.raises(VaultLockedError):
        controller.search_logins("")


def test_user_text_uses_core_words_and_hides_raw_errors():
    assert "doesn't open this vault" in user_text(WrongPasswordError())
    raw = RuntimeError("boom at /home/person/secret/path")
    text = user_text(raw)
    assert "/home" not in text and "boom" not in text


def test_replacing_a_session_locks_the_old_one(controller, tmp_path):
    # Defense in depth behind the window's one-at-a-time gate:
    # adopting a new session never orphans the old one unlocked.
    first = tmp_path / "first.aegis"
    second = tmp_path / "second.aegis"
    controller.create_vault(first, PASSWORD, params=FAST_PARAMS)
    old_session = controller.session
    controller.create_vault(second, PASSWORD, params=FAST_PARAMS)
    assert old_session.is_locked
    assert old_session._vault_key is None
    assert controller.session is not old_session


# -- passwords ----------------------------------------------------------


def test_login_crud_and_search(open_controller):
    controller, _ = open_controller
    entry = controller.add_login(
        "Example Mail", username="test.person@example.test",
        password="fake-password-1", url="https://example.test",
    )
    assert [s.id for s in controller.search_logins("example")] == [entry.id]
    assert controller.search_logins("fake-password") == []  # never searched
    controller.update_login(entry.id, username="other@example.test")
    assert controller.get_login(entry.id).username == "other@example.test"
    controller.delete_login(entry.id)
    assert controller.search_logins("") == []


def test_copy_and_auto_clear(controller, port, clock, tmp_path):
    controller.create_vault(tmp_path / "v.aegis", PASSWORD, params=FAST_PARAMS)
    entry = controller.add_login("Example", password="fake-password-2")
    controller.copy_login_password(entry.id)
    assert port.get_text() == "fake-password-2"
    clock.advance(29)
    controller.tick()
    assert port.get_text() == "fake-password-2"
    clock.advance(2)
    controller.tick()
    assert port.get_text() == ""


def test_auto_clear_never_takes_a_newer_copy(controller, port, clock, tmp_path):
    controller.create_vault(tmp_path / "v.aegis", PASSWORD, params=FAST_PARAMS)
    entry = controller.add_login("Example", password="fake-password-3")
    controller.copy_login_password(entry.id)
    port.set_text("something the person copied next")
    clock.advance(60)
    controller.tick()
    assert port.get_text() == "something the person copied next"


def test_lock_clears_the_clipboard_right_away(controller, port, tmp_path):
    controller.create_vault(tmp_path / "v.aegis", PASSWORD, params=FAST_PARAMS)
    entry = controller.add_login("Example", password="fake-password-4")
    controller.copy_login_password(entry.id)
    controller.lock()
    assert port.get_text() == ""


# -- idle -----------------------------------------------------------------


def test_idle_locks_and_tells_the_window(controller, clock, tmp_path):
    fired = []
    controller.on_lock = lambda: fired.append(True)
    controller.create_vault(tmp_path / "v.aegis", PASSWORD, params=FAST_PARAMS)
    controller.apply_settings(idle_seconds=120)
    clock.advance(119)
    controller.tick()
    assert controller.is_open
    clock.advance(2)
    controller.tick()
    assert not controller.is_open
    assert fired == [True]


def test_idle_lock_failure_is_reported_and_retried(controller, clock, tmp_path):
    errors = []
    controller.on_error = errors.append
    path = tmp_path / "v.aegis"
    controller.create_vault(path, PASSWORD, params=FAST_PARAMS)
    controller.add_login("Example", password="fake-password-5")
    # An unsaved change makes the lock save first — and someone
    # swaps the vault file on disk meanwhile: the core refuses to
    # save over it, so the lock must fail loudly and stay open.
    controller.session.write("scratch", b"unsaved")
    path.write_bytes(b"not the vault that was there")
    controller.apply_settings(idle_seconds=60)
    clock.advance(61)
    controller.tick()
    assert errors, "the failed idle lock was hidden"
    assert controller.is_open, "a failed lock must stay open and retry"
    # The M3 pin: the failure is retried underneath, but the
    # report happens once per episode — not on every tick.
    for _ in range(5):
        controller.tick()
    assert len(errors) == 1


def test_apply_settings_unchanged_values_keep_the_clipboard(
    controller, port, clock, tmp_path
):
    # The L7 pin: re-applying the SAME clear time must not clear
    # a pending copied secret early.
    controller.create_vault(tmp_path / "v.aegis", PASSWORD, params=FAST_PARAMS)
    entry = controller.add_login("Example", password="fake-password-7")
    controller.copy_login_password(entry.id)
    controller.apply_settings(clear_after_seconds=30)
    assert port.get_text() == "fake-password-7"
    controller.apply_settings(clear_after_seconds=10)
    assert port.get_text() == ""


def test_intake_read_is_capped_even_if_size_lies(
    open_controller, tmp_path, monkeypatch
):
    # The L3 pin: getsize says small; the file is really past the
    # cap. The streaming read must refuse at the cap, not load it.
    import aegis.ui.controllers as controllers_module

    controller, _ = open_controller
    big = tmp_path / "liar.bin"
    with open(big, "wb") as handle:
        handle.truncate(10 * 1024 * 1024 + 4096)  # sparse
    real_getsize = controllers_module.os.path.getsize
    monkeypatch.setattr(
        controllers_module.os.path, "getsize",
        lambda p: 42 if Path(p) == big else real_getsize(p),
    )
    with pytest.raises(DocumentTooLargeError):
        controller.add_document_from_path("Liar", big)
    assert controller.list_items() == []


def test_generator_through_controller(open_controller):
    controller, _ = open_controller
    made = controller.make_password(24)
    assert len(made) == 24


def test_user_text_never_passes_a_bare_value_error():
    # The M4 pin: a bare ValueError can carry codec complaints and
    # file paths — it becomes the generic line, always.
    text = user_text(ValueError("/home/person/secret/file is broken"))
    assert "/home" not in text
    assert "Something went wrong" in text
    codec = UnicodeEncodeError("utf-8", "x", 0, 1, "surrogates not allowed")
    assert "codec" not in user_text(codec)
    assert "Something went wrong" in user_text(codec)


# -- Strongbox -------------------------------------------------------------


def test_strongbox_flow(open_controller, tmp_path):
    controller, _ = open_controller
    item = controller.add_text_item("code", "Example code", "0000-FAKE-CODE")
    assert controller.reveal_item(item.id) == "0000-FAKE-CODE"
    doc = tmp_path / "letter.txt"
    doc.write_bytes(pattern_bytes(2048, seed=3))
    saved = controller.add_document_from_path("A letter", doc)
    out = tmp_path / "copy.txt"
    controller.save_document_copy(saved.id, out)
    assert out.read_bytes() == pattern_bytes(2048, seed=3)
    with pytest.raises(SealedExistsError):
        controller.save_document_copy(saved.id, out)


def test_strongbox_intake_refuses_oversize_without_reading(open_controller, tmp_path):
    controller, _ = open_controller
    big = tmp_path / "big.bin"
    with open(big, "wb") as handle:
        handle.truncate(10 * 1024 * 1024 + 1)  # sparse: costs nothing
    with pytest.raises(DocumentTooLargeError):
        controller.add_document_from_path("Big", big)
    assert controller.list_items() == []


def test_strongbox_intake_refuses_hostile_names_and_folders(open_controller, tmp_path):
    controller, _ = open_controller
    sneaky = tmp_path / "evil\\name.txt"  # a backslash in the name
    sneaky.write_bytes(b"x")
    with pytest.raises(InvalidStrongboxEntryError):
        controller.add_document_from_path("Sneaky", sneaky)
    with pytest.raises(Exception) as caught:
        controller.add_document_from_path("A folder", tmp_path)
    assert "isn't a plain file" in user_text(caught.value)


# -- Lock-and-send / armor ----------------------------------------------------


def test_lock_and_send_flow(open_controller, tmp_path):
    controller, _ = open_controller
    source = tmp_path / "note.txt"
    source.write_bytes(b"synthetic contents for sending")
    sealed = controller.seal_a_file(source, "a shared phrase")
    assert sealed.name == "sealed-file.aegis-send"
    assert b"synthetic contents" not in sealed.read_bytes()
    out_dir = tmp_path / "received"
    out_dir.mkdir()
    with pytest.raises(WrongFilePasswordError):
        controller.open_a_sealed_file(sealed, "the wrong phrase", out_dir)
    opened = controller.open_a_sealed_file(sealed, "a shared phrase", out_dir)
    assert opened.read_bytes() == b"synthetic contents for sending"


def test_armor_flow(open_controller, tmp_path):
    controller, _ = open_controller
    tree = tmp_path / "backup"
    (tree / "sub").mkdir(parents=True)
    (tree / "a.txt").write_bytes(b"first synthetic file")
    (tree / "sub" / "b.txt").write_bytes(pattern_bytes(5000, seed=9))
    sealed = controller.seal_a_folder(tree, "a set phrase")
    assert sealed.name == "backup.aegis-armored"
    manifest = controller.look_inside_set(sealed, "a set phrase")
    assert sorted(i.path for i in manifest.files) == ["a.txt", "sub/b.txt"]
    dest = tmp_path / "restored"
    with pytest.raises(WrongFilePasswordError):
        controller.unseal_a_set(sealed, "nope", dest)
    controller.unseal_a_set(sealed, "a set phrase", dest)
    assert (dest / "a.txt").read_bytes() == b"first synthetic file"
    assert (dest / "sub" / "b.txt").read_bytes() == pattern_bytes(5000, seed=9)
    with pytest.raises(SealedExistsError):
        controller.unseal_a_set(sealed, "a set phrase", dest)


# -- Vault care -----------------------------------------------------------------


def test_change_password_and_new_recovery_key(controller, tmp_path):
    path = tmp_path / "v.aegis"
    old_recovery = controller.create_vault(path, PASSWORD, params=FAST_PARAMS)
    controller.change_password("a brand new phrase")
    new_recovery = controller.new_recovery_key()
    assert new_recovery != old_recovery
    controller.lock()
    with pytest.raises(WrongPasswordError):
        controller.open_vault(path, password=PASSWORD)
    with pytest.raises(Exception):
        controller.open_vault(path, recovery_key=old_recovery)
    controller.open_vault(path, recovery_key=new_recovery)
    assert controller.is_open


def test_export_and_import(controller, tmp_path):
    source_path = tmp_path / "source.aegis"
    controller.create_vault(source_path, PASSWORD, params=FAST_PARAMS)
    controller.add_login("Example Mail", password="fake-password-6")
    copy_path = tmp_path / "copy.aegis"
    controller.export_copy(copy_path)
    controller.lock()

    other = VaultController(MemoryClipboard())
    other.create_vault(tmp_path / "other.aegis", PASSWORD, params=FAST_PARAMS)
    count = other.import_logins(copy_path, PASSWORD)
    assert count == 1
    assert other.search_logins("Example")[0].title == "Example Mail"
    other.lock()
    # The imported-from vault was locked again by the import itself.
    with pytest.raises(WrongPasswordError):
        controller.open_vault(source_path, password=WRONG_PASSWORD)
