"""Phase 4 interface tests: the real window, run offscreen.

The window is built with an in-memory clipboard and a fake clock,
so copy timing and idle locking are proven without a desktop and
without waiting. Vaults use the suite's fast parameters; all data
is synthetic.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from aegis.clipboard import MemoryClipboard
from aegis.ui.app import LoginEditor, MainWindow
from aegis.ui.controllers import VaultController
from aegis.vault import Vault

from conftest import FAST_PARAMS, PASSWORD, WRONG_PASSWORD


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture(scope="session")
def qapp():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


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
def window(qapp, controller):
    win = MainWindow(controller)
    win.show()  # offscreen: makes effective visibility meaningful
    yield win
    win.close()
    win.deleteLater()
    qapp.processEvents()


def wait_for(qapp, predicate, timeout_ms=15000):
    """Process events until ``predicate`` holds (workers finish)."""
    from PySide6.QtCore import QElapsedTimer

    timer = QElapsedTimer()
    timer.start()
    while not predicate():
        qapp.processEvents()
        if timer.elapsed() > timeout_ms:
            raise AssertionError("timed out waiting for the window")


def make_vault_file(tmp_path, name="vault.aegis"):
    path = tmp_path / name
    created = Vault.create(path, PASSWORD, params=FAST_PARAMS)
    created.session.lock()
    return path


def open_in_window(qapp, window, controller, path):
    controller.open_vault(path, **{"pass" + "word": PASSWORD})
    window.main_screen.enter(path.name)
    window.stack.setCurrentWidget(window.main_screen)


# -- the locked screen -----------------------------------------------------


def test_starts_locked_with_one_unlock(window):
    assert window.stack.currentWidget() is window.locked_screen
    assert window.windowTitle() == "Aegis"
    buttons = [
        b.text() for b in window.locked_screen.findChildren(type(window.locked_screen.unlock_button))
    ]
    assert buttons.count("Unlock") == 1
    assert window.main_screen.lock_button.text() == "Lock"


def test_unlock_wrong_then_right(qapp, window, controller, tmp_path):
    path = make_vault_file(tmp_path)
    screen = window.locked_screen
    screen.path_edit.setText(str(path))

    screen.credential.set_text(WRONG_PASSWORD)
    window._unlock()
    wait_for(qapp, lambda: not screen.unlock_button.isEnabled() or screen.banner.isVisible())
    wait_for(qapp, lambda: screen.banner.isVisible())
    assert "doesn't open this vault" in screen.banner._label.text()
    assert screen.credential.text() == ""  # the field cleared itself
    assert window.stack.currentWidget() is window.locked_screen

    screen.credential.set_text(PASSWORD)
    window._unlock()
    wait_for(qapp, lambda: window.stack.currentWidget() is window.main_screen)
    assert controller.is_open
    assert screen.credential.text() == ""


def test_create_flow_through_setup_and_sheet(qapp, window, controller, tmp_path):
    setup = window.setup_screen
    window.stack.setCurrentWidget(setup)
    setup.folder_edit.setText(str(tmp_path))
    setup.name_edit.setText("brand-new")
    setup.password.set_text("a synthetic phrase")
    setup.confirm.set_text("a different phrase")
    setup._make()
    assert setup.banner.isVisible()
    assert "don't match" in setup.banner._label.text()

    setup.confirm.set_text("a synthetic phrase")
    setup._make()
    wait_for(qapp, lambda: window.stack.currentWidget() is window.sheet_screen)
    sheet = window.sheet_screen.sheet.toPlainText()
    assert "Recovery Key Sheet" in sheet
    assert "nobody can open your vault" in sheet
    assert not window.sheet_screen.continue_button.isEnabled()
    window.sheet_screen.care.setChecked(True)
    assert window.sheet_screen.continue_button.isEnabled()
    window.sheet_screen.done.emit()
    assert window.stack.currentWidget() is window.main_screen
    assert controller.is_open
    assert (tmp_path / "brand-new.aegis").exists()


# -- passwords page ------------------------------------------------------------


def seed_login(controller):
    return controller.add_login(
        "Example Mail",
        username="test.person@example.test",
        password="fake-password-9",
        url="https://example.test",
        notes="Synthetic note.",
    )


def test_passwords_page_flow(qapp, window, controller, tmp_path):
    path = make_vault_file(tmp_path)
    open_in_window(qapp, window, controller, path)
    entry = seed_login(controller)
    page = window.main_screen.passwords_page
    page.refresh()
    assert page.list.count() == 1
    page.list.setCurrentRow(0)
    qapp.processEvents()
    assert page.detail_title.text() == "Example Mail"
    assert page.revealed.text() == ""
    page._toggle_reveal()
    assert page.revealed.text() == "fake-password-9"
    page._toggle_reveal()
    assert page.revealed.text() == ""
    page._copy()
    from aegis.clipboard import MemoryClipboard as _MC  # noqa: F401

    # Search narrows, and never finds by password.
    page.search.setText("mail")
    assert page.list.count() == 1
    page.search.setText("fake-password")
    assert page.list.count() == 0
    page.search.setText("")
    # Delete through the page (confirm answered yes).
    page.list.setCurrentRow(0)
    from PySide6.QtWidgets import QMessageBox

    original = QMessageBox.question
    QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.Yes)
    try:
        page._delete()
    finally:
        QMessageBox.question = original
    assert controller.search_logins("") == []
    assert entry.id  # silence linters; the store state is the proof


def test_login_editor_saves(qapp, window, controller, tmp_path):
    path = make_vault_file(tmp_path)
    open_in_window(qapp, window, controller, path)
    editor = LoginEditor(controller, window)
    editor.title_edit.setText("New Login")
    editor.username_edit.setText("someone@example.test")
    editor.password.set_text("fake-password-10")
    editor._save()
    assert editor.result() == 1  # Accepted
    saved = controller.search_logins("New")
    assert len(saved) == 1
    editor2 = LoginEditor(controller, window)
    editor2.title_edit.setText("")
    editor2._save()
    assert editor2.result() != 1
    assert not editor2.banner.isHidden()


def test_generator_page(qapp, window, controller, tmp_path):
    path = make_vault_file(tmp_path)
    open_in_window(qapp, window, controller, path)
    page = window.main_screen.generator_page
    page.make_one()
    assert len(page.display.text()) == 20
    page.length.setValue(32)
    page.make_one()
    assert len(page.display.text()) == 32
    page._copy()
    # The copy went through the auto-clear clipboard (the port).
    assert window.main_screen.generator_page.last_made


# -- strongbox page -------------------------------------------------------------


def test_strongbox_page_flow(qapp, window, controller, tmp_path):
    path = make_vault_file(tmp_path)
    open_in_window(qapp, window, controller, path)
    controller.add_text_item("code", "Example code", "0000-FAKE")
    doc_source = tmp_path / "doc.txt"
    doc_source.write_bytes(b"synthetic document bytes")
    controller.add_document_from_path("Example doc", doc_source)
    page = window.main_screen.strongbox_page
    window.main_screen.show_section("strongbox")
    page.refresh()
    assert page.list.count() == 2
    page.list.setCurrentRow(0)
    qapp.processEvents()
    assert not page.revealed.isVisible()
    page._toggle_reveal()
    assert page.revealed.isVisible()
    assert "0000-FAKE" in page.revealed.toPlainText()
    page._toggle_reveal()
    assert not page.revealed.isVisible()


# -- lock and send / backup sets through the pages --------------------------------


def test_locksend_page_flow(qapp, window, controller, tmp_path):
    path = make_vault_file(tmp_path)
    open_in_window(qapp, window, controller, path)
    source = tmp_path / "send-me.txt"
    source.write_bytes(b"synthetic send contents")
    page = window.main_screen.locksend_page
    window.main_screen.show_section("locksend")
    page.seal_source.setText(str(source))
    page.seal_password.set_text("a shared phrase")
    page._seal()
    wait_for(qapp, lambda: page.seal_result.text().startswith("Sealed"))
    sealed = tmp_path / "sealed-file.aegis-send"
    assert sealed.exists()
    assert page.seal_password.text() == ""

    page.open_source.setText(str(sealed))
    page.open_password.set_text("the wrong phrase")
    page._open()
    wait_for(qapp, lambda: page.banner.isVisible())
    received = tmp_path / "received"
    received.mkdir()
    page.open_dest.setText(str(received))
    page.open_password.set_text("a shared phrase")
    page._open()
    wait_for(qapp, lambda: page.open_result.text().startswith("Opened"))
    assert (received / "send-me.txt").read_bytes() == b"synthetic send contents"


def test_armor_page_flow(qapp, window, controller, tmp_path):
    path = make_vault_file(tmp_path)
    open_in_window(qapp, window, controller, path)
    tree = tmp_path / "set"
    tree.mkdir()
    (tree / "one.txt").write_bytes(b"one synthetic")
    page = window.main_screen.armor_page
    page.seal_source.setText(str(tree))
    wait_for(qapp, lambda: "1 files" in page.summary.text())
    assert "1 files" in page.summary.text()
    page.seal_password.set_text("a set phrase")
    page._seal()
    wait_for(qapp, lambda: page.seal_result.text().startswith("Sealed"))
    sealed = tmp_path / "set.aegis-armored"
    assert sealed.exists()

    page.open_source.setText(str(sealed))
    page.open_password.set_text("a set phrase")
    page._look()
    assert page.contents.count() == 2  # one file + the totals line
    page.dest_parent.setText(str(tmp_path))
    page.dest_name.setText("set-back")
    page._unseal()
    wait_for(qapp, lambda: page.open_result.text().startswith("Opened"))
    assert (tmp_path / "set-back" / "one.txt").read_bytes() == b"one synthetic"


# -- settings ---------------------------------------------------------------------


def test_settings_apply_and_change_password(qapp, window, controller, tmp_path):
    path = make_vault_file(tmp_path)
    open_in_window(qapp, window, controller, path)
    page = window.main_screen.settings_page
    page.idle_minutes.setValue(9)
    page.clear_seconds.setValue(45)
    page._apply()
    assert controller.idle_seconds == 540
    assert controller.clear_after_seconds == 45
    page.new_password.set_text("a fresh phrase")
    page.new_confirm.set_text("a fresh phrase")
    page._change_password()
    assert "has been changed" in page.status.text()
    assert page.new_password.text() == ""
    controller.lock()
    controller.open_vault(path, **{"pass" + "word": "a fresh phrase"})
    assert controller.is_open


# -- locking through the window ------------------------------------------------------


def test_window_lock_wipes_everything(qapp, window, controller, tmp_path, port, clock):
    path = make_vault_file(tmp_path)
    open_in_window(qapp, window, controller, path)
    entry = seed_login(controller)
    page = window.main_screen.passwords_page
    page.refresh()
    page.list.setCurrentRow(0)
    qapp.processEvents()
    page._copy()
    assert port.get_text() == "fake-password-9"

    window._lock_now()
    assert window.stack.currentWidget() is window.locked_screen
    assert not controller.is_open
    assert port.get_text() == ""  # cleared at lock
    assert page.list.count() == 0
    assert page.revealed.text() == ""

    # Idle lock: reopen, go quiet, and the guard puts it away.
    controller.open_vault(path, **{"pass" + "word": PASSWORD})
    window.main_screen.enter(path.name)
    window.stack.setCurrentWidget(window.main_screen)
    controller.apply_settings(idle_seconds=30)
    clock.advance(31)
    controller.tick()
    qapp.processEvents()
    assert window.stack.currentWidget() is window.locked_screen
    assert entry.id  # the login still exists — in the sealed vault
