"""The timing settings, saved between runs.

Two numbers live here and nothing else: how long Aegis waits
before it locks itself, and how long a copied password stays on
the clipboard. They are preferences, not secrets — no vault
content, no file names, nothing about a person ever enters this
file.

The values are held to exactly the ranges the settings screen
offers (a quiet-time lock between 1 and 120 minutes, a clipboard
stay between 5 and 300 seconds), whether they arrive from the
screen or from a file on disk. A file that is missing, unreadable,
or damaged in any way is simply not used: the built-in defaults
apply and Aegis opens exactly as before. A damaged preferences
file must never stand between a person and their vault.

Saving is a small honest write: the numbers go to a file beside
the destination and are moved into place, so a save cut short
leaves the older settings — or none — rather than half a file.
Whether the save landed is reported to the caller truthfully;
the screen says which of the two happened.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

__all__ = ["default_settings_path", "load_settings", "save_settings"]

# The settings screen's own ranges, held here as the one truth
# both the loader and the saver answer to.
IDLE_SECONDS_RANGE = (60.0, 7200.0)
CLEAR_SECONDS_RANGE = (5.0, 300.0)


def default_settings_path() -> Path:
    """Where this person's settings live.

    ``AEGIS_SETTINGS_PATH`` wins when set; otherwise a per-person
    ``Aegis`` folder under ``LOCALAPPDATA`` when that is set, and
    a ``.aegis`` folder in the home directory everywhere else.
    """
    override = os.environ.get("AEGIS_SETTINGS_PATH")
    if override:
        return Path(override)
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / "Aegis" / "settings.json"
    return Path.home() / ".aegis" / "settings.json"


def _checked(value, bounds):
    """One saved number, or None when it is not usable."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    low, high = bounds
    if not low <= float(value) <= high:
        return None
    return float(value)


def load_settings(path) -> dict:
    """Read saved timings from *path*.

    Returns a dict holding only the values that are present and
    inside their ranges, keyed ``idle_seconds`` /
    ``clear_after_seconds``. Any problem at all — no file, bad
    JSON, wrong shapes — returns an empty dict, never an error.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    found = {}
    idle = _checked(data.get("idle_seconds"), IDLE_SECONDS_RANGE)
    if idle is not None:
        found["idle_seconds"] = idle
    clear = _checked(data.get("clear_after_seconds"), CLEAR_SECONDS_RANGE)
    if clear is not None:
        found["clear_after_seconds"] = clear
    return found


def save_settings(path, *, idle_seconds, clear_after_seconds) -> bool:
    """Save the timings to *path*. True when the save landed."""
    idle = _checked(idle_seconds, IDLE_SECONDS_RANGE)
    clear = _checked(clear_after_seconds, CLEAR_SECONDS_RANGE)
    if idle is None or clear is None:
        return False
    target = Path(path)
    payload = json.dumps(
        {"idle_seconds": idle, "clear_after_seconds": clear},
        indent=2,
        sort_keys=True,
    )
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(payload + "\n", encoding="utf-8")
        os.replace(tmp, target)
    except OSError:
        return False
    return True
