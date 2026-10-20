"""Phase 2 clipboard tests: the auto-clear promise, driven by a fake clock.

The promise under test: a copied password is taken back off the
clipboard after a short window — but only if the clipboard still
holds exactly what Aegis put there. A newer thing the person copied
is never erased.
"""

import pytest

from aegis.clipboard import AutoClearClipboard, MemoryClipboard

SECRET = "fake-password-for-tests-1"


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def rig():
    clock = FakeClock()
    board = MemoryClipboard()
    auto = AutoClearClipboard(board, clear_after_seconds=30.0, clock=clock)
    return auto, board, clock


def test_copy_puts_secret_on_clipboard(rig):
    auto, board, _ = rig
    auto.copy_secret(SECRET)
    assert board.get_text() == SECRET
    assert auto.has_pending_clear


def test_check_before_deadline_clears_nothing(rig):
    auto, board, clock = rig
    auto.copy_secret(SECRET)
    clock.advance(29.0)
    assert auto.check() is False
    assert board.get_text() == SECRET


def test_check_at_deadline_clears(rig):
    auto, board, clock = rig
    auto.copy_secret(SECRET)
    clock.advance(30.0)
    assert auto.check() is True
    assert board.get_text() == ""
    assert not auto.has_pending_clear
    assert auto.check() is False


def test_newer_copy_by_user_is_never_cleared(rig):
    auto, board, clock = rig
    auto.copy_secret(SECRET)
    board.set_text("something the person copied next")
    clock.advance(60.0)
    assert auto.check() is False
    assert board.get_text() == "something the person copied next"


def test_second_copy_supersedes_first(rig):
    auto, board, clock = rig
    auto.copy_secret("first-fake-secret")
    clock.advance(20.0)
    auto.copy_secret("second-fake-secret")
    clock.advance(15.0)  # past the first deadline, inside the second
    assert auto.check() is False
    assert board.get_text() == "second-fake-secret"
    clock.advance(15.0)  # past the second deadline
    assert auto.check() is True
    assert board.get_text() == ""


def test_clear_now_clears_immediately(rig):
    auto, board, _ = rig
    auto.copy_secret(SECRET)
    assert auto.clear_now() is True
    assert board.get_text() == ""


def test_clear_now_respects_a_newer_copy(rig):
    auto, board, _ = rig
    auto.copy_secret(SECRET)
    board.set_text("the person's own text")
    assert auto.clear_now() is False
    assert board.get_text() == "the person's own text"


def test_unreadable_clipboard_is_left_alone(rig):
    auto, board, clock = rig

    class BrokenBoard:
        def get_text(self):
            raise RuntimeError("no clipboard here")

        def set_text(self, text):
            pass

    broken = AutoClearClipboard(
        BrokenBoard(), clear_after_seconds=10.0, clock=clock
    )
    broken.copy_secret(SECRET)
    clock.advance(20.0)
    assert broken.check() is False
    assert not broken.has_pending_clear


def test_clear_failure_is_contained():
    # Audit regression (Phase 2, A-2): a clipboard that fails while
    # being cleared reports "not cleared" instead of raising into
    # the caller's rhythm.
    class FlakyBoard:
        def __init__(self):
            self.text = None

        def get_text(self):
            return self.text

        def set_text(self, text):
            if text == "":
                raise RuntimeError("clipboard gone")
            self.text = text

    clock = FakeClock()
    board = FlakyBoard()
    auto = AutoClearClipboard(board, clear_after_seconds=10.0, clock=clock)
    auto.copy_secret(SECRET)
    clock.advance(11.0)
    assert auto.check() is False
    auto.copy_secret(SECRET)
    assert auto.clear_now() is False


def test_invalid_arguments(rig):
    auto, _, _ = rig
    with pytest.raises(ValueError):
        AutoClearClipboard(MemoryClipboard(), clear_after_seconds=0)
    with pytest.raises(TypeError):
        auto.copy_secret(b"bytes are not text")
