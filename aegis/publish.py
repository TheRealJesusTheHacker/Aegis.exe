"""Putting finished files in place, on real drives.

Every publish in Aegis follows the same shape: the finished
bytes are written to a temporary file beside the destination,
flushed and synced there, and only then put in place. This
module is the "put in place" step, shared by the vault, the
sealed files, and the sealed-copy export, because real drives
complicate it in two ways a test machine never shows:

- **A file can be busy for a moment.** On Windows, a file that
  was just written is often being looked over by the machine's
  own safety checks at the exact moment it should move into
  place, and the move is refused while that lasts. The refusal
  is brief, so a move that meets it waits a moment and tries
  again — a handful of tries over about a second — before the
  failure is reported. A failure that lasts is still reported,
  exactly as before.

- **Some drives cannot hold links.** Putting a file in place
  without ever overwriting is normally a link: the finished
  temporary file appears at the destination in one step, or
  not at all. The drives a portable copy travels on — USB
  sticks above all, usually formatted in a way that has no
  links — refuse that step entirely, which used to make
  creating a vault or a sealed file on such a drive fail
  outright. On a drive that refuses links, the destination
  name is instead claimed for Aegis alone (a name anyone else
  already holds is still refused, never overwritten) and the
  finished bytes are copied into it and synced. A copy left
  unfinished by a failure is taken back off; a sealed file
  that was cut short refuses to open rather than pretending
  to be whole, so nothing about the fallback weakens what a
  finished file promises.
"""

from __future__ import annotations

import os
import shutil
import time

__all__ = ["link_into_place", "replace_with_retry", "rename_with_retry"]

_ATTEMPTS = 5
_DELAYS = (0.05, 0.1, 0.2, 0.4)


def _with_retries(operation):
    """Run ``operation``, waiting out brief in-use refusals.

    Only a permission refusal is retried — that is the shape a
    momentarily busy file takes. Anything else (above all "it
    is already there") is the caller's business and is raised
    at once.
    """
    last = None
    for attempt in range(_ATTEMPTS):
        try:
            return operation()
        except PermissionError as exc:
            last = exc
            if attempt < len(_DELAYS):
                time.sleep(_DELAYS[attempt])
    raise last


def replace_with_retry(tmp_name, dest) -> None:
    """Replace ``dest`` with the finished file at ``tmp_name``."""
    _with_retries(lambda: os.replace(tmp_name, dest))


def rename_with_retry(source, dest) -> None:
    """Move ``source`` to ``dest``, waiting out brief refusals."""
    _with_retries(lambda: os.rename(source, dest))


def link_into_place(tmp_name, dest) -> None:
    """Put the finished file at ``tmp_name`` in place at ``dest``.

    Never overwrites: something already at ``dest`` raises
    :class:`FileExistsError`, exactly as a plain link does.
    Drives that cannot hold links get the claimed-name copy
    described in this module's introduction instead; a failure
    partway through that copy removes the partial destination
    before the failure is raised.
    """
    try:
        _with_retries(lambda: os.link(tmp_name, dest))
        return
    except FileExistsError:
        raise
    except OSError:
        pass
    fd = os.open(
        dest,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
    )
    try:
        with os.fdopen(fd, "wb") as out, open(tmp_name, "rb") as inp:
            shutil.copyfileobj(inp, out)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        try:
            os.unlink(dest)
        except OSError:
            pass
        raise
