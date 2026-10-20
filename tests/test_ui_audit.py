"""Phase 4 audit pins: the interface as an attack surface.

Each test here is a regression pin for something the Phase 4
self-audit checked: secrets must not linger in titles, fields, or
lists after a lock; the clipboard's lifetime is bounded by the
seam's rules at the window level too; opening a vault must take
the credentials off the screen; and hostile file intake is refused
by designed errors, never raw ones.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from aegis.clipboard import MemoryClipboard
from aegis.errors import VaultLockedError
from aegis.ui.controllers import VaultController, user_text
from aegis.vault import Vault

from conftest import FAST_PARAMS, PASSWORD


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

    return QApplication.instance() or QApplication([])


@pytest.fixture
def rig(qapp, tmp_path):
    from aegis.ui.app import MainWindow

    port = MemoryClipboard()
    clock = FakeClock()
    controller = VaultController(port, clock=clock)
    path = tmp_path / "vault.aegis"
    created = Vault.create(path, PASSWORD, params=FAST_PARAMS)
    created.session.lock()
    window = MainWindow(controller)
    window.show()  # offscreen: makes effective visibility meaningful
    yield window, controller, port, clock, path
    window.close()
    window.deleteLater()
    qapp.processEvents()


def _open(rig):
    window, controller, _port, _clock, path = rig
    controller.open_vault(path, **{"pass" + "word": PASSWORD})
    window.main_screen.enter(path.name)
    window.stack.setCurrentWidget(window.main_screen)
    return window, controller


def test_window_title_never_carries_content(rig):
    window, controller = _open(rig)
    controller.add_login("Zebra Secrets Club", password="fake-password-1")
    window.main_screen.passwords_page.refresh()
    assert window.windowTitle() == "Aegis"
    window._lock_now()
    assert window.windowTitle() == "Aegis"


def test_lock_leaves_no_trace_of_contents(rig, qapp):
    window, controller = _open(rig)
    controller.add_login("Zebra Secrets Club", password="fake-password-2")
    controller.add_text_item("note", "Hidden diary title", "the body text")
    page = window.main_screen.passwords_page
    page.refresh()
    page.list.setCurrentRow(0)
    qapp.processEvents()
    page._toggle_reveal()
    assert page.revealed.text() == "fake-password-2"

    window._lock_now()
    assert window.stack.currentWidget() is window.locked_screen
    assert page.list.count() == 0
    assert page.revealed.text() == ""
    # Nothing from inside the vault is anywhere on the locked screen.
    from PySide6.QtWidgets import QLabel

    shown = "\n".join(
        label.text() for label in window.locked_screen.findChildren(QLabel)
    )
    assert "Zebra" not in shown
    assert "fake-password" not in shown
    assert "Hidden diary" not in shown
    # And the controller holds nothing to use.
    with pytest.raises(VaultLockedError):
        controller.search_logins("")


def test_session_key_is_wiped_on_window_lock(rig):
    window, controller = _open(rig)
    session = controller.session
    window._lock_now()
    assert session.is_locked
    assert session._vault_key is None


def test_credentials_leave_the_screen_on_unlock(rig, qapp):
    window, controller, _port, _clock, path = rig
    screen = window.locked_screen
    screen.path_edit.setText(str(path))
    screen.credential.set_text("the wrong phrase")
    window._unlock()

    from PySide6.QtCore import QElapsedTimer

    timer = QElapsedTimer()
    timer.start()
    while not screen.banner.isVisible() and timer.elapsed() < 15000:
        qapp.processEvents()
    assert screen.banner.isVisible()
    assert screen.credential.text() == ""


def test_clipboard_lifetime_at_the_window(rig, qapp):
    window, controller = _open(rig)
    port, clock = rig[2], rig[3]
    entry = controller.add_login("Example", password="fake-password-3")
    page = window.main_screen.passwords_page
    page.refresh()
    page.list.setCurrentRow(0)
    qapp.processEvents()
    page._copy()
    assert port.get_text() == "fake-password-3"
    clock.advance(31)
    controller.tick()
    assert port.get_text() == ""


def test_recovery_key_screen_wipes_on_leave(rig):
    window, controller = _open(rig)
    key = controller.new_recovery_key()
    window._show_new_key_sheet(key)
    assert key in window.sheet_screen.sheet.toPlainText()
    window.sheet_screen.wipe()
    assert key not in window.sheet_screen.sheet.toPlainText()
    assert window.sheet_screen.sheet.toPlainText() == ""


# -- the audit-fix pins (H1, H2, M1, M2, M5, M6) -----------------------------


def test_lock_wipes_the_recovery_sheet_too(rig):
    # M6: the key sheet is part of the lock's funnel, not an
    # exception to it.
    window, controller = _open(rig)
    key = controller.new_recovery_key()
    window._show_new_key_sheet(key)
    assert key in window.sheet_screen.sheet.toPlainText()
    window._lock_now()
    assert window.sheet_screen.sheet.toPlainText() == ""


def test_secret_surfaces_refuse_native_copy(rig):
    # H1: what Aegis shows is not selectable/copyable natively;
    # the tracked Copy buttons are the only road out.
    from PySide6.QtCore import Qt

    window, controller = _open(rig)
    controller.add_login("Example", password="fake-password-4")
    controller.add_text_item("code", "Example code", "0000-FAKE")
    passwords = window.main_screen.passwords_page
    passwords.refresh()
    assert not (
        passwords.revealed.textInteractionFlags() & Qt.TextSelectableByMouse
    )
    strongbox = window.main_screen.strongbox_page
    strongbox.refresh()
    assert (
        strongbox.revealed.textInteractionFlags() == Qt.NoTextInteraction
    )
    assert (
        window.sheet_screen.sheet.textInteractionFlags()
        == Qt.NoTextInteraction
    )


def test_generator_copy_gesture_uses_the_tracked_copy(rig, qapp):
    # H1, the generator road: Ctrl+C in the display runs Aegis's
    # own copy — the one the clock watches — so a lock still
    # bounds its lifetime. Uses the REAL Qt clipboard seam.
    from PySide6.QtCore import QEvent, Qt
    from PySide6.QtGui import QKeyEvent
    from PySide6.QtWidgets import QApplication

    from aegis.ui.app import MainWindow
    from aegis.ui.clipboard_qt import QtClipboard
    from aegis.ui.controllers import VaultController

    controller = VaultController(QtClipboard())
    window = MainWindow(controller)
    window.show()
    try:
        path = rig[4]
        controller.open_vault(path, **{"pass" + "word": PASSWORD})
        window.main_screen.enter(path.name)
        window.stack.setCurrentWidget(window.main_screen)
        window.main_screen.show_section("generator")
        page = window.main_screen.generator_page
        page.make_one()
        made = page.display.text()
        assert made
        page.display.selectAll()
        event = QKeyEvent(
            QEvent.KeyPress, Qt.Key_C, Qt.ControlModifier, "c"
        )
        QApplication.sendEvent(page.display, event)
        clipboard = QApplication.clipboard()
        assert clipboard.text() == made  # copied — through the seam
        window._lock_now()
        assert clipboard.text() == ""  # and the lock still bounds it
    finally:
        window.close()
        window.deleteLater()
        qapp.processEvents()


def test_open_dialog_is_closed_and_emptied_by_a_lock(rig, qapp):
    # H2: a modal editor must not survive a lock with its
    # contents on screen.
    from aegis.ui.app import LoginEditor

    window, controller = _open(rig)
    entry = controller.add_login("Example", password="fake-password-5")
    dialog = LoginEditor(controller, window.main_screen, entry=entry)
    window._track_dialog(dialog)
    dialog.show()
    qapp.processEvents()
    assert dialog.isVisible()
    assert dialog.password.text() == "fake-password-5"
    window._lock_now()
    qapp.processEvents()
    assert not dialog.isVisible()
    assert dialog.password.text() == ""
    assert dialog.title_edit.text() == ""
    window._release_dialog(dialog)
    dialog.deleteLater()


def test_double_unlock_is_single_flight(rig, qapp):
    # M2: a second unlock while one is running starts nothing.
    window, controller, _port, _clock, path = rig
    screen = window.locked_screen
    screen.path_edit.setText(str(path))
    screen.credential.set_text(PASSWORD)
    window._unlock()
    assert window._auth_busy
    sessions = []
    original_adopt = controller._adopt

    def counting_adopt(session, p):
        sessions.append(session)
        return original_adopt(session, p)

    controller._adopt = counting_adopt
    window._unlock()  # the re-entrant second attempt
    from PySide6.QtCore import QElapsedTimer

    timer = QElapsedTimer()
    timer.start()
    while not controller.is_open and timer.elapsed() < 15000:
        qapp.processEvents()
    assert controller.is_open
    assert len(sessions) == 1


def test_setup_failure_clears_the_password_fields(rig):
    # M5: a failed create leaves no master password typed.
    window, _controller = rig[0], rig[1]
    setup = window.setup_screen
    setup.password.set_text("brand-new-master-phrase")
    setup.confirm.set_text("brand-new-master-phrase")
    setup._failed(RuntimeError("synthetic failure"))
    assert setup.password.text() == ""
    assert setup.confirm.text() == ""


def _send_key(widget, key, modifiers, text=""):
    from PySide6.QtCore import QEvent
    from PySide6.QtGui import QKeyEvent
    from PySide6.QtWidgets import QApplication

    event = QKeyEvent(QEvent.KeyPress, key, modifiers, text)
    QApplication.sendEvent(widget, event)


def test_cut_gesture_is_swallowed_on_secret_editors(rig, qapp):
    # NEW-1: Cut is a copy that also erases — it takes the same
    # lockdown as Copy on the Strongbox editor and on a peeked
    # password field. Sentinel method: an unrelated clipboard
    # value must survive both gestures untouched.
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication

    from aegis.ui.app import ItemEditor, PasswordEdit

    clipboard = QApplication.clipboard()
    clipboard.setText("sentinel-value")

    window, controller = _open(rig)
    item = controller.add_text_item("code", "Example", "0000-FAKE-CUT")
    dialog = ItemEditor(controller, window.main_screen, item=item)
    dialog.body_edit.selectAll()
    _send_key(dialog.body_edit, Qt.Key_X, Qt.ControlModifier, "x")
    assert clipboard.text() == "sentinel-value"
    assert dialog.body_edit.toPlainText() == "0000-FAKE-CUT"
    dialog.deleteLater()

    field = PasswordEdit()
    field.set_text("fake-peeked-secret")
    field._peek_on()  # the Show button held: echo is Normal
    field.edit.selectAll()
    _send_key(field.edit, Qt.Key_X, Qt.ControlModifier, "x")
    assert clipboard.text() == "sentinel-value"
    assert field.text() == "fake-peeked-secret"
    field.deleteLater()


def test_login_notes_editor_is_locked_down(rig):
    # NEW-2: the login editor's notes get the same lockdown —
    # a copied note must not outlive the lock.
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication

    from aegis.ui.app import LoginEditor

    clipboard = QApplication.clipboard()
    clipboard.setText("sentinel-value")
    window, controller = _open(rig)
    entry = controller.add_login(
        "Example", password="fake-password-6", notes="a private note"
    )
    dialog = LoginEditor(controller, window.main_screen, entry=entry)
    dialog.notes_edit.selectAll()
    _send_key(dialog.notes_edit, Qt.Key_C, Qt.ControlModifier, "c")
    assert clipboard.text() == "sentinel-value"
    dialog.deleteLater()


def test_recovery_field_clear_keeps_its_open_echo(rig):
    # NEW-3: clearing a peek-disallowed (recovery-key) field must
    # not flip it back to bullets behind the hidden Show button.
    from PySide6.QtWidgets import QLineEdit

    from aegis.ui.app import PasswordEdit

    field = PasswordEdit()
    field.set_peek_allowed(False)
    field.set_text("SOME-KEY-0000")
    field.clear()
    assert field.edit.echoMode() == QLineEdit.Normal
    field.set_peek_allowed(True)
    field.set_text("a phrase")
    field.clear()
    assert field.edit.echoMode() == QLineEdit.Password
    field.deleteLater()


def test_worker_result_after_lock_lands_nowhere(rig, qapp, tmp_path):
    # M1: a seal that finishes after a lock may finish its file,
    # but its result never repopulates the wiped page.
    import threading

    window, controller = _open(rig)
    page = window.main_screen.locksend_page
    window.main_screen.show_section("locksend")
    source = tmp_path / "seal-me.txt"
    source.write_bytes(b"synthetic seal contents")
    release = threading.Event()
    real_seal = controller.seal_a_file

    def slow_seal(src, pw):
        release.wait(10)
        return real_seal(src, pw)

    controller.seal_a_file = slow_seal
    page.seal_source.setText(str(source))
    page.seal_password.set_text("a shared phrase")
    page._seal()
    window._lock_now()
    release.set()
    from PySide6.QtCore import QElapsedTimer

    timer = QElapsedTimer()
    timer.start()
    while timer.elapsed() < 3000:
        qapp.processEvents()
    assert page.seal_result.text() == ""
    controller.seal_a_file = real_seal
