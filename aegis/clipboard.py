"""Copying passwords out — and taking them back off the clipboard.

A copied password is a secret outside the vault, in a place any
program on the machine can read. Phase 2's rule: it may sit there
only for a short while, and Aegis takes it back off when the while
is up — *if* the clipboard still holds exactly what Aegis put
there. If the person has copied something else since, that newer
thing is theirs and is never touched.

Real clipboard access belongs to the interface (Phase 4); this
module is the seam and the logic:

- A clipboard is anything with ``get_text()`` / ``set_text()``.
  :class:`MemoryClipboard` is the in-memory stand-in used by the
  test suite and available wherever no real clipboard exists.
- :class:`AutoClearClipboard` owns the timing. The interface calls
  :meth:`AutoClearClipboard.check` regularly (and at lock time);
  the clock is injectable so the logic is testable without waiting
  around, which is exactly how the test suite drives it.

One copy replaces the last: copying a second password retires the
first one's deadline — only the newest secret is tracked, and only
it is ever cleared.
"""

from __future__ import annotations

import time

__all__ = [
    "DEFAULT_CLEAR_AFTER_SECONDS",
    "MemoryClipboard",
    "AutoClearClipboard",
]

DEFAULT_CLEAR_AFTER_SECONDS = 30.0


class MemoryClipboard:
    """An in-memory clipboard: the seam's reference implementation."""

    def __init__(self):
        self._text = None

    def get_text(self):
        return self._text

    def set_text(self, text):
        self._text = text


class AutoClearClipboard:
    """Copies secrets to a clipboard and clears them again, on time."""

    def __init__(
        self,
        clipboard,
        *,
        clear_after_seconds=DEFAULT_CLEAR_AFTER_SECONDS,
        clock=time.monotonic,
    ):
        if clear_after_seconds <= 0:
            raise ValueError("The clearing delay must be more than zero.")
        self._clipboard = clipboard
        self._clear_after = float(clear_after_seconds)
        self._clock = clock
        self._pending = None  # (text, deadline) for the newest copy

    @property
    def has_pending_clear(self) -> bool:
        """True while a copied secret is still waiting to be cleared."""
        return self._pending is not None

    def copy_secret(self, text: str) -> None:
        """Put ``text`` on the clipboard and start its countdown."""
        if not isinstance(text, str):
            raise TypeError("Only text can be copied.")
        self._clipboard.set_text(text)
        self._pending = (text, self._clock() + self._clear_after)

    def check(self) -> bool:
        """Run the countdown once; clear if the time is up.

        Returns True if this call cleared the clipboard. The
        clipboard is cleared only when it still holds exactly the
        tracked secret — a newer thing the person copied is never
        erased. A clipboard that cannot be read is left alone, and
        the tracked secret is simply forgotten.
        """
        if self._pending is None:
            return False
        text, deadline = self._pending
        if self._clock() < deadline:
            return False
        self._pending = None
        try:
            current = self._clipboard.get_text()
        except Exception:
            return False
        if current != text:
            return False
        return self._try_clear()

    def clear_now(self) -> bool:
        """Clear a tracked secret immediately (used when locking).

        Same rule as the timed clear: only if the clipboard still
        holds exactly what Aegis put there. Returns True if it
        cleared.
        """
        if self._pending is None:
            return False
        text, _deadline = self._pending
        self._pending = None
        try:
            current = self._clipboard.get_text()
        except Exception:
            return False
        if current != text:
            return False
        return self._try_clear()

    def _try_clear(self) -> bool:
        """Empty the clipboard, tolerating a clipboard that fails.

        A clipboard that cannot be written to cannot be cleared;
        that is reported as "not cleared" rather than raised into
        whatever rhythm (an interface timer, a lock) called us.
        """
        try:
            self._clipboard.set_text("")
        except Exception:
            return False
        return True

    def forget(self) -> None:
        """Stop tracking without clearing (the clipboard changed hands)."""
        self._pending = None
