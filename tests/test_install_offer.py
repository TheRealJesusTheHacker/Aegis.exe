"""v1.0.1: the first-run install offer and truthful install words.

- Detection agrees with the launcher's install code in every
  environment combination, in both directions.
- Accepting runs the real mechanism, by its own read-back, and
  leaves everything outside the app folder alone.
- The dialog stands modeless over the locked screen, is gone at
  a lock, on navigation, and at an unlock attempt — and a result
  that lands after it has gone lands nowhere.
- A failed install says what actually happened: an earlier copy
  taken out, a partial copy removed, or a partial copy still at
  the place the message names.
- The offer's own words pass the plain-language sweep.

All data is synthetic; installs happen inside ``tmp_path``.
"""

import os
import threading
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from aegis import install_state
from aegis.clipboard import MemoryClipboard
from aegis.ui.app import MainWindow
from aegis.ui.controllers import VaultController

from conftest import FAST_PARAMS, PASSWORD
from test_ui_copy import BANNED_JARGON, _harvest_texts

ROOT = Path(__file__).parent.parent


def load_install_module():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "aegis_install_for_offer_tests", ROOT / "packaging" / "install.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wait_for(qapp, predicate, timeout_ms=15000):
    """Process events until ``predicate`` holds (workers finish)."""
    from PySide6.QtCore import QElapsedTimer

    timer = QElapsedTimer()
    timer.start()
    while not predicate():
        qapp.processEvents()
        if timer.elapsed() > timeout_ms:
            raise AssertionError("timed out waiting for the window")


class FakeOffer:
    """The window's seam, faked: needed()/run(), nothing more."""

    def __init__(self, needed=True, result=None, run_fn=None):
        self._needed = needed
        self._result = result or (
            True, "Aegis is installed and checked."
        )
        self._run_fn = run_fn
        self.run_calls = 0

    def needed(self):
        return self._needed

    def run(self):
        self.run_calls += 1
        if self._run_fn is not None:
            return self._run_fn()
        return self._result


@pytest.fixture(scope="session")
def qapp():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


@pytest.fixture
def make_window(qapp):
    windows = []

    def _make(offer=None):
        controller = VaultController(MemoryClipboard())
        if offer is None:
            window = MainWindow(controller)
        else:
            window = MainWindow(controller, install_offer=offer)
        window.show()
        windows.append(window)
        return window, controller

    yield _make
    for window in windows:
        window.close()
        window.deleteLater()
    qapp.processEvents()


def visible_dialogs(window):
    from PySide6.QtWidgets import QDialog

    return [d for d in window.findChildren(QDialog) if d.isVisible()]


# -- detection -------------------------------------------------------


def test_offer_needed_both_directions(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_INSTALL_ROOT", str(tmp_path / "root"))
    home = install_state.installed_home()
    assert home == tmp_path / "root" / "Aegis"
    assert install_state.running_from_installed_home(home) is True
    assert install_state.offer_needed(home) is False
    elsewhere = tmp_path / "usb" / "Aegis"
    assert install_state.running_from_installed_home(elsewhere) is False
    assert install_state.offer_needed(elsewhere) is True


def test_offer_needed_false_for_a_source_run(monkeypatch):
    monkeypatch.setattr(install_state.sys, "frozen", False, raising=False)
    assert install_state.app_home() is None
    assert install_state.offer_needed() is False


def test_install_root_agrees_with_the_launcher_install_code(
    tmp_path, monkeypatch
):
    launcher = load_install_module()
    # The override wins over everything, in both modules.
    monkeypatch.setenv("AEGIS_INSTALL_ROOT", str(tmp_path / "override"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    assert install_state.install_root() == launcher.install_root()
    assert install_state.install_root() == tmp_path / "override"
    # Without the override, the per-person Programs folder.
    monkeypatch.delenv("AEGIS_INSTALL_ROOT")
    assert install_state.install_root() == launcher.install_root()
    assert install_state.install_root() == tmp_path / "appdata" / "Programs"
    # With neither, a Programs folder in the person's home.
    monkeypatch.delenv("LOCALAPPDATA")
    monkeypatch.setattr(
        Path, "home", classmethod(lambda cls: tmp_path / "home")
    )
    assert install_state.install_root() == launcher.install_root()
    assert install_state.install_root() == tmp_path / "home" / "Programs"


# -- the real mechanism, through perform_install -----------------------


def test_perform_install_places_a_verified_copy_and_leaves_the_rest_alone(
    tmp_path, monkeypatch
):
    app_dir = tmp_path / "portable" / "Aegis"
    app_dir.mkdir(parents=True)
    (app_dir / "Aegis.exe").write_bytes(b"synthetic exe bytes v101")
    (app_dir / "lib.bin").write_bytes(b"synthetic lib bytes")
    vault = tmp_path / "elsewhere" / "keep.aegis"
    vault.parent.mkdir()
    vault.write_bytes(b"synthetic vault bytes, untouched")
    root = tmp_path / "installed-root"
    monkeypatch.setenv("AEGIS_INSTALL_ROOT", str(root))
    monkeypatch.setattr(install_state.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        install_state.sys, "executable", str(app_dir / "Aegis.exe")
    )
    assert install_state.app_home() == app_dir.resolve()
    assert install_state.offer_needed() is True

    ok, message = install_state.perform_install(app_dir)
    assert ok, message
    assert "installed" in message.lower()
    placed = root / "Aegis"
    assert (placed / "Aegis.exe").read_bytes() == b"synthetic exe bytes v101"
    assert (placed / "lib.bin").read_bytes() == b"synthetic lib bytes"
    assert vault.read_bytes() == b"synthetic vault bytes, untouched"

    # Running from the placed copy, the offer no longer applies.
    monkeypatch.setattr(
        install_state.sys, "executable", str(placed / "Aegis.exe")
    )
    assert install_state.app_home() == placed.resolve()
    assert install_state.offer_needed() is False


# -- the dialog, through the window -------------------------------------


def test_offer_shows_over_locked_screen_and_a_lock_closes_it_once(
    qapp, make_window
):
    window, _controller = make_window(FakeOffer(needed=True))
    window.maybe_offer_install()
    qapp.processEvents()
    dialog = window._install_dialog
    assert dialog is not None and dialog.isVisible()
    assert window.stack.currentWidget() is window.locked_screen
    assert dialog in window._open_dialogs

    window._lock_now()
    qapp.processEvents()
    assert visible_dialogs(window) == []
    assert window._open_dialogs == []
    assert window._install_dialog is None

    # Once per run: a second call shows nothing.
    window.maybe_offer_install()
    qapp.processEvents()
    assert window._install_dialog is None
    assert visible_dialogs(window) == []


def test_offer_decline_leaves_the_unlock_path_working(
    qapp, make_window, tmp_path
):
    window, controller = make_window(FakeOffer(needed=True))
    window.maybe_offer_install()
    qapp.processEvents()
    dialog = window._install_dialog
    assert dialog is not None
    dialog.not_now_button.click()
    qapp.processEvents()
    assert window._install_dialog is None
    assert visible_dialogs(window) == []

    # The vault flow the offer stood over works end to end.
    path = tmp_path / "vault.aegis"
    controller.create_vault(path, PASSWORD, params=FAST_PARAMS)
    controller.lock()
    qapp.processEvents()
    screen = window.locked_screen
    screen.path_edit.setText(str(path))
    screen.credential.set_text(PASSWORD)
    window._unlock()
    wait_for(
        qapp, lambda: window.stack.currentWidget() is window.main_screen
    )
    assert controller.is_open


def test_offer_accept_shows_the_mechanisms_words_and_a_close_button(
    qapp, make_window
):
    offer = FakeOffer(
        needed=True, result=(True, "Aegis is installed and checked.")
    )
    window, _controller = make_window(offer)
    window.maybe_offer_install()
    qapp.processEvents()
    dialog = window._install_dialog
    dialog.install_button.click()
    wait_for(
        qapp,
        lambda: dialog.status_label.text()
        == "Aegis is installed and checked.",
    )
    assert offer.run_calls == 1
    assert dialog.close_button.isVisible()
    assert not dialog.install_button.isVisible()
    assert not dialog.not_now_button.isVisible()
    dialog.close_button.click()
    qapp.processEvents()
    assert window._install_dialog is None
    assert visible_dialogs(window) == []


def test_offer_double_accept_runs_the_install_once(qapp, make_window):
    started = threading.Event()
    release = threading.Event()

    def blocking_run():
        started.set()
        release.wait(10)
        return True, "Aegis is installed and checked."

    offer = FakeOffer(needed=True, run_fn=blocking_run)
    window, _controller = make_window(offer)
    window.maybe_offer_install()
    qapp.processEvents()
    dialog = window._install_dialog
    assert dialog is not None
    window._accept_install_offer(dialog)
    wait_for(qapp, lambda: started.is_set(), timeout_ms=5000)

    # A second programmatic accept while the first install is
    # still running must not spawn another worker or run again.
    window._accept_install_offer(dialog)

    release.set()
    wait_for(
        qapp,
        lambda: dialog.status_label.text()
        == "Aegis is installed and checked.",
    )
    assert offer.run_calls == 1
    assert dialog.close_button.isVisible()
    assert not dialog.install_button.isVisible()
    assert not dialog.not_now_button.isVisible()
    dialog.close_button.click()
    qapp.processEvents()
    assert window._install_dialog is None
    assert visible_dialogs(window) == []


def test_offer_result_landing_after_a_lock_is_dropped(qapp, make_window):
    started = threading.Event()
    release = threading.Event()

    def blocking_run():
        started.set()
        release.wait(10)
        return True, "Aegis is installed and checked."

    window, _controller = make_window(
        FakeOffer(needed=True, run_fn=blocking_run)
    )
    window.maybe_offer_install()
    qapp.processEvents()
    dialog = window._install_dialog
    dialog.install_button.click()
    wait_for(qapp, lambda: started.is_set(), timeout_ms=5000)

    window._lock_now()
    qapp.processEvents()
    assert window._install_dialog is None
    assert visible_dialogs(window) == []

    release.set()
    wait_for(
        qapp,
        lambda: window._install_worker is not None
        and not window._install_worker.isRunning(),
    )
    qapp.processEvents()
    # The late result surfaced nowhere: no dialog, no exception.
    assert window._install_dialog is None
    assert visible_dialogs(window) == []
    assert window.stack.currentWidget() is window.locked_screen


def test_offer_is_dismissed_by_navigation(qapp, make_window):
    window, _controller = make_window(FakeOffer(needed=True))
    window.maybe_offer_install()
    qapp.processEvents()
    assert window._install_dialog is not None
    window._go(window.setup_screen)
    qapp.processEvents()
    assert window._install_dialog is None
    assert visible_dialogs(window) == []


def test_offer_not_needed_creates_nothing(qapp, make_window):
    window, _controller = make_window(FakeOffer(needed=False))
    window.maybe_offer_install()
    qapp.processEvents()
    assert window._install_dialog is None
    assert visible_dialogs(window) == []


# -- the copy fix: failed installs tell the truth ------------------------


def _synthetic_source(tmp_path):
    source = tmp_path / "build"
    source.mkdir()
    (source / "Aegis.exe").write_bytes(b"synthetic exe bytes")
    return source


def _failing_copytree(_src, dest):
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "part.bin").write_bytes(b"partial synthetic copy")
    raise OSError("simulated copy failure")


def test_copy_failure_without_an_earlier_copy_removes_the_partial(
    tmp_path, monkeypatch
):
    install = load_install_module()
    monkeypatch.setenv("AEGIS_INSTALL_ROOT", str(tmp_path / "root"))
    monkeypatch.setattr(install.shutil, "copytree", _failing_copytree)
    ok, message = install.install(_synthetic_source(tmp_path))
    assert not ok
    assert "Nothing was changed" not in message
    assert "partial copy was removed" in message.lower()
    assert "nothing is installed" in message.lower()
    assert not (tmp_path / "root" / "Aegis").exists()


def test_copy_failure_after_an_earlier_copy_says_it_was_taken_out(
    tmp_path, monkeypatch
):
    install = load_install_module()
    monkeypatch.setenv("AEGIS_INSTALL_ROOT", str(tmp_path / "root"))
    dest = tmp_path / "root" / "Aegis"
    dest.mkdir(parents=True)
    (dest / "old.bin").write_bytes(b"the earlier copy")
    monkeypatch.setattr(install.shutil, "copytree", _failing_copytree)
    ok, message = install.install(_synthetic_source(tmp_path))
    assert not ok
    assert "Nothing was changed" not in message
    assert "earlier installed copy was taken out" in message
    assert "not installed" in message
    assert not dest.exists()


def test_heal_failure_says_the_earlier_copy_could_not_be_cleared(
    tmp_path, monkeypatch
):
    install = load_install_module()
    monkeypatch.setenv("AEGIS_INSTALL_ROOT", str(tmp_path / "root"))
    dest = tmp_path / "root" / "Aegis"
    dest.mkdir(parents=True)
    (dest / "old.bin").write_bytes(b"the earlier copy")

    def stuck_rmtree(*_args, **_kwargs):
        raise OSError("simulated stuck folder")

    monkeypatch.setattr(install.shutil, "rmtree", stuck_rmtree)
    ok, message = install.install(_synthetic_source(tmp_path))
    assert not ok
    assert "Nothing was changed" not in message
    assert "could not be cleared away" in message
    assert "not newly installed" in message


def test_copy_failure_with_a_stuck_partial_names_its_place(
    tmp_path, monkeypatch
):
    install = load_install_module()
    monkeypatch.setenv("AEGIS_INSTALL_ROOT", str(tmp_path / "root"))
    dest = tmp_path / "root" / "Aegis"

    def stuck_rmtree(*_args, **_kwargs):
        raise OSError("simulated stuck folder")

    monkeypatch.setattr(install.shutil, "copytree", _failing_copytree)
    monkeypatch.setattr(install.shutil, "rmtree", stuck_rmtree)
    ok, message = install.install(_synthetic_source(tmp_path))
    assert not ok
    assert "Nothing was changed" not in message
    assert str(dest) in message
    assert "still at" in message
    assert dest.exists()


def test_verify_failure_with_the_copy_gone_keeps_the_settled_words(
    tmp_path, monkeypatch
):
    install = load_install_module()
    monkeypatch.setenv("AEGIS_INSTALL_ROOT", str(tmp_path / "root"))
    answers = iter([{"Aegis.exe": "one"}, {"Aegis.exe": "two"}])
    monkeypatch.setattr(
        install, "_tree_digests", lambda _root: next(answers)
    )
    ok, message = install.install(_synthetic_source(tmp_path))
    assert not ok
    assert "did not check out" in message
    assert "Nothing was left half-installed." in message
    assert not (tmp_path / "root" / "Aegis").exists()


def test_verify_failure_with_a_partial_left_names_its_place(
    tmp_path, monkeypatch
):
    install = load_install_module()
    monkeypatch.setenv("AEGIS_INSTALL_ROOT", str(tmp_path / "root"))
    dest = tmp_path / "root" / "Aegis"
    answers = iter([{"Aegis.exe": "one"}, {"Aegis.exe": "two"}])
    monkeypatch.setattr(
        install, "_tree_digests", lambda _root: next(answers)
    )
    monkeypatch.setattr(
        install.shutil, "rmtree", lambda *_a, **_k: None
    )
    ok, message = install.install(_synthetic_source(tmp_path))
    assert not ok
    assert "did not check out" in message
    assert str(dest) in message
    assert "not ready to use" in message
    assert dest.exists()


# -- the offer's words ----------------------------------------------------


def test_offer_dialog_words_have_no_banned_jargon(qapp, make_window):
    texts = []
    for result in (
        (True, "Aegis is installed and checked."),
        (False, "Aegis could not be put in place. "
                "You can keep running it from here."),
    ):
        window, _controller = make_window(
            FakeOffer(needed=True, result=result)
        )
        window.maybe_offer_install()
        qapp.processEvents()
        dialog = window._install_dialog
        texts += _harvest_texts(dialog)
        dialog.install_button.click()
        wait_for(
            qapp, lambda d=dialog, r=result: d.status_label.text() == r[1]
        )
        texts += _harvest_texts(dialog)
        dialog.close_button.click()
        qapp.processEvents()
    joined = "\n".join(texts).lower()
    assert joined  # the harvest found the dialog's words at all
    for word in BANNED_JARGON:
        assert word not in joined, f"banned word {word!r} in the offer"
