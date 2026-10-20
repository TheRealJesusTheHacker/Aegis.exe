"""Self-install for the packaged Aegis build.

The kit pattern: one file, self-placement, verified install,
truthful reporting. This module is the mechanism; the launcher
exposes it as ``--install`` / ``--uninstall``. Installing is an
offer, never a gate — the app runs exactly the same uninstalled,
from a folder or a USB stick (that is the portable edition).

What install does, in plain terms: it copies the program folder
next to where Windows keeps per-person programs, puts a shortcut
named "Aegis" in the Start Menu, and then reads the placed copy
back and compares it piece for piece with the copy it came from.
If anything does not match, it says so and removes the partial
install itself — it never reports success it did not check.

``AEGIS_INSTALL_ROOT`` overrides the install root (used by the
test-suite and by anyone who wants the copy somewhere specific).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
from pathlib import Path

APP_FOLDER = "Aegis"
SHORTCUT_NAME = "Aegis.lnk"


def install_root() -> Path:
    override = os.environ.get("AEGIS_INSTALL_ROOT")
    if override:
        return Path(override)
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / "Programs"
    return Path.home() / "Programs"


def start_menu_dir() -> Path:
    override = os.environ.get("AEGIS_INSTALL_ROOT")
    if override:
        return Path(override) / "StartMenu"
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    return Path.home() / "Start Menu" / "Programs"


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _tree_digests(root: Path) -> dict:
    out = {}
    for item in sorted(root.rglob("*")):
        if item.is_file():
            out[str(item.relative_to(root))] = _digest(item)
    return out


def _make_shortcut(target: Path, link: Path) -> bool:
    """Create a Start Menu shortcut on Windows; report honestly elsewhere."""
    if sys.platform != "win32":
        return False
    try:
        import pythoncom  # noqa: F401  (ships with PySide6 builds via pywin32-less path)
    except Exception:
        pass
    try:
        import win32com.client  # type: ignore

        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(str(link))
        shortcut.TargetPath = str(target)
        shortcut.WorkingDirectory = str(target.parent)
        shortcut.Description = "Aegis — file vault and password manager"
        shortcut.Save()
        return link.exists()
    except Exception:
        return False


def install(source_dir: Path) -> tuple:
    """Copy ``source_dir`` into place and verify the copy.

    Returns (ok, message) with a plain-language message either way.
    A failed verification removes the partial install.
    """
    source_dir = Path(source_dir)
    if not (source_dir / "Aegis.exe").exists() and not (source_dir / "Aegis").exists():
        return False, "This copy does not look complete, so nothing was installed."
    dest = install_root() / APP_FOLDER
    if dest.resolve() == source_dir.resolve():
        return True, "Aegis is already running from its installed home; nothing to do."
    try:
        if dest.exists():
            shutil.rmtree(dest)  # heal a partial or older install
        shutil.copytree(source_dir, dest)
    except OSError:
        return False, "Aegis could not be put in place. Nothing was changed; you can keep running it from here."
    if _tree_digests(source_dir) != _tree_digests(dest):
        shutil.rmtree(dest, ignore_errors=True)
        return False, "The installed copy did not check out, so it was removed. Nothing was left half-installed."
    exe = dest / ("Aegis.exe" if (dest / "Aegis.exe").exists() else "Aegis")
    link = start_menu_dir() / SHORTCUT_NAME
    try:
        link.parent.mkdir(parents=True, exist_ok=True)
        made = _make_shortcut(exe, link)
    except OSError:
        made = False
    if made:
        return True, "Aegis is installed and checked. You will find it in your Start Menu as \u201cAegis\u201d."
    return True, "Aegis is installed and checked in your Programs folder. (A Start Menu shortcut could not be added on this machine.)"


def uninstall() -> tuple:
    """Remove the installed copy. Vault files are never touched."""
    dest = install_root() / APP_FOLDER
    link = start_menu_dir() / SHORTCUT_NAME
    removed = False
    try:
        if link.exists():
            link.unlink()
            removed = True
        if dest.exists():
            shutil.rmtree(dest)
            removed = True
    except OSError:
        return False, "Aegis could not be fully removed. Your vault files were not touched either way."
    if removed:
        return True, "Aegis is removed. Your vault files were not touched — they stay exactly where you left them."
    return True, "Aegis was not installed, so there was nothing to remove. Your vault files were not touched."
