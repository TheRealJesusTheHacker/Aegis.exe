"""The Aegis interface — Phase 4.

One Lock button, one Unlock button, plain language end to end.
This package is the only part of Aegis that knows about windows:
the core (``aegis`` itself) never imports it, and its test suite
never needs a screen. Importing this package does not import Qt —
the window modules load when the app actually runs — so tools and
tests can use the Qt-free controller layer on its own.
"""

from .controllers import VaultController, user_text

__all__ = ["VaultController", "user_text", "run", "self_check"]


def run(argv=None) -> int:
    """Run the Aegis app (loads Qt on first use)."""
    from .app import run as _run

    return _run(argv)


def self_check() -> int:
    """Build the whole window offscreen and report success."""
    from .app import self_check as _check

    return _check()
