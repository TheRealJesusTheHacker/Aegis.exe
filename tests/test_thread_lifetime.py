"""Window-close thread lifetime: a worker still running must
never be closed over.

Regression battery for the sweep-3 finding. Workers are the
window's own children (a seal, an unlock, an install), and a
QThread destroyed while it is still running aborts the whole
process — proven against the pre-fix window, which waited a
bounded five seconds per thread and then closed anyway, so
closing Aegis during a long seal (a very large file can run for
minutes) tore the process down. The window now refuses the
close while any worker is still running after its bounded wait,
and the final lock never races work in flight either: it runs
only once no worker is running.
"""

import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from aegis.clipboard import MemoryClipboard
from aegis.ui.app import MainWindow, Worker
from aegis.ui.controllers import VaultController


@pytest.fixture(scope="session")
def qapp():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def window(qapp):
    win = MainWindow(VaultController(MemoryClipboard()))
    win.show()
    yield win
    win.deleteLater()
    qapp.processEvents()


def _close_event():
    from PySide6.QtGui import QCloseEvent

    return QCloseEvent()


def test_close_is_refused_while_a_worker_runs(window, qapp):
    gate = threading.Event()
    worker = Worker(lambda: gate.wait(30), window)
    worker.start()
    try:
        event = _close_event()
        window.closeEvent(event)
        assert not event.isAccepted()
        assert window.isVisible()
    finally:
        gate.set()
        assert worker.wait(5000)


def test_close_proceeds_once_the_worker_finishes(window, qapp):
    worker = Worker(lambda: time.sleep(0.2), window)
    worker.start()
    event = _close_event()
    window.closeEvent(event)
    assert event.isAccepted()
    assert worker.wait(5000)


def test_the_final_lock_never_races_a_running_worker(window, qapp):
    gate = threading.Event()
    locks = []
    original_lock = window._controller.lock
    window._controller.lock = lambda: locks.append(1)
    worker = Worker(lambda: gate.wait(30), window)
    worker.start()
    try:
        event = _close_event()
        window.closeEvent(event)
        assert not event.isAccepted()
        assert locks == []  # no lock was attempted mid-work
    finally:
        gate.set()
        assert worker.wait(5000)
        window._controller.lock = original_lock
