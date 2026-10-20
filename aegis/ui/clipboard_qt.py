"""The real clipboard, behind Phase 2's clipboard seam.

Phase 2 defined a clipboard as anything with ``get_text()`` /
``set_text()`` and built the auto-clear logic on top of it. This is
the desktop implementation of that seam: Qt's system clipboard.
All timing and all judgement (clear only what Aegis put there, only
when it is still there) stays in :class:`aegis.AutoClearClipboard`;
this class only carries text to and from the operating system.
"""

from __future__ import annotations

from PySide6.QtGui import QGuiApplication

__all__ = ["QtClipboard"]


class QtClipboard:
    """The operating system's clipboard, through Qt."""

    def get_text(self):
        clipboard = QGuiApplication.clipboard()
        if clipboard is None:
            return None
        text = clipboard.text()
        return text if text else None

    def set_text(self, text):
        clipboard = QGuiApplication.clipboard()
        if clipboard is None:
            raise RuntimeError("No clipboard is available on this computer.")
        clipboard.setText(text)
