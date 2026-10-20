"""Whether this copy of Aegis is running from its installed home.

This module is the policy half of the first-run install offer:
it decides whether the offer should be made at all, and, if the
person accepts, it hands the work to the real install mechanism.
It is kept free of the window code so the decision can be tested
on its own, without building a window.

Detection uses the same facts ``--install`` uses; nothing is
guessed. The installed home is worked out exactly the way the
launcher's install code works it out — the same override, the
same per-person Programs folder, the same folder name — and a
copy counts as installed only when the folder the app is running
from is that home, compared as settled, full paths. A copy run
from source is not a packaged copy at all, so the offer does not
apply to it: there is no installed home to compare against, and
nothing here pretends otherwise.

Installing itself is not repeated here. Accepting the offer runs
the same mechanism the launcher runs — the packaged build carries
that code as a module beside the app, and a source checkout
carries it in its packaging folder — and whatever that mechanism
reports, word for word, is what the person is told.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

APP_FOLDER = "Aegis"

#: Said when no install mechanism can be found at all. That is
#: the truth for a copy with no packaging beside it: it can keep
#: running exactly where it is.
_NOT_AVAILABLE = (
    "Installing is not available in this copy of Aegis. "
    "You can keep running it from here."
)


def install_root() -> Path:
    """The folder installed copies live under.

    Mirrors the launcher's install code exactly: the
    ``AEGIS_INSTALL_ROOT`` override when it is set, otherwise the
    per-person Programs folder under ``LOCALAPPDATA`` when that
    is set, otherwise a Programs folder in the person's home.
    """
    override = os.environ.get("AEGIS_INSTALL_ROOT")
    if override:
        return Path(override)
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / "Programs"
    return Path.home() / "Programs"


def installed_home() -> Path:
    """Where an installed copy of Aegis lives."""
    return install_root() / APP_FOLDER


def app_home() -> Path | None:
    """The folder this copy of the app is running from.

    Only a packaged copy has one: the folder holding the running
    program file. A source run returns None — it is not a
    packaged copy, and the install offer does not apply to it.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return None


def _settled(path) -> Path:
    """Settle ``path`` to its full, real form for comparison.

    Windows also spells a folder with a verbatim prefix: two
    backslashes, a question mark, and a backslash in front of
    a drive path (and the same, with UNC added, in front of a
    share) -- the same folder, written so its long form is
    taken exactly as given. Settling alone keeps that prefix
    on one side of a comparison and not the other, so the
    same folder in its two spellings compared as two
    different folders: proven on Windows CI, where the
    prefixed spelling of the installed home was not
    recognized as installed. The prefix comes off before
    settling, on both sides alike.
    """
    bs = chr(92)
    verbatim = bs + bs + "?" + bs
    text = str(path)
    if text.startswith(verbatim + "UNC" + bs):
        text = bs + bs + text[len(verbatim) + 4:]
    elif text.startswith(verbatim):
        text = text[len(verbatim):]
    return Path(text).resolve()


def running_from_installed_home(app_dir, home=None) -> bool:
    """True when ``app_dir`` is the installed home, path for path.

    Both sides are settled to their full, real paths before the
    comparison, so two spellings of the same folder count as the
    same folder — exactly the comparison the install code itself
    makes when it decides there is nothing to do.
    """
    if app_dir is None:
        return False
    if home is None:
        home = installed_home()
    return _settled(app_dir) == _settled(home)


def offer_needed(app_dir=None, home=None) -> bool:
    """True when the first-run install offer should be made.

    ``app_dir`` defaults to this copy's own folder. A copy with no
    packaged folder (a source run) never needs the offer, and a
    copy already running from its installed home does not either;
    every other packaged copy does.
    """
    if app_dir is None:
        app_dir = app_home()
    if app_dir is None:
        return False
    return not running_from_installed_home(app_dir, home)


def _load_mechanism(app_dir):
    """Find the real install mechanism, or None when there is none.

    The packaged build ships the launcher's install code as a
    top-level module named ``install`` — the launcher brings it in
    with exactly that import, and so does this. Failing that, the
    code is looked for beside the running copy, and then in a
    source checkout's packaging folder.
    """
    try:
        import install as mechanism
    except ImportError:
        mechanism = None
    if mechanism is not None and hasattr(mechanism, "install"):
        return mechanism
    candidates = []
    if app_dir is not None:
        candidates.append(Path(app_dir) / "install.py")
    candidates.append(
        Path(__file__).resolve().parent.parent / "packaging" / "install.py"
    )
    for candidate in candidates:
        if candidate.exists():
            spec = importlib.util.spec_from_file_location(
                "aegis_install_mechanism", candidate
            )
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if hasattr(module, "install"):
                return module
    return None


def perform_install(app_dir) -> tuple:
    """Install the copy in ``app_dir`` by the real mechanism.

    Returns the mechanism's own (ok, message), unchanged — this
    function adds no words of its own to a result the mechanism
    reached. When no mechanism can be loaded, it says so plainly
    instead of pretending an install happened.
    """
    if app_dir is None:
        return False, _NOT_AVAILABLE
    mechanism = _load_mechanism(app_dir)
    if mechanism is None:
        return False, _NOT_AVAILABLE
    return mechanism.install(app_dir)


class InstallOffer:
    """The seam the window uses for the first-run install offer.

    One small object with two methods, so a test can stand a fake
    in its place and the window behaves the same either way:
    ``needed`` asks the policy above about this very copy, and
    ``run`` installs this very copy.
    """

    def needed(self) -> bool:
        return offer_needed()

    def run(self) -> tuple:
        return perform_install(app_home())
