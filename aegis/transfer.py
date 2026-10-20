"""Moving logins between vaults — sealed, the whole way.

This module implements the decision in
``docs/IMPORT-EXPORT-SAFETY.md``, and nothing beyond it:

- **Export** is a sealed copy: the vault file itself, written to a
  new place. Sealed on the way out, sealed at rest, opened by the
  same master password and recovery key as the original. There is
  no plain-text export, in whole or in part — a readable copy of
  every login is the one artifact Aegis refuses to make.
- **Import** reads logins from another *open Aegis vault* and
  merges them into this one. Both vaults are opened by their owner;
  nothing readable crosses between them except through this merge,
  in memory.

An exported copy is a full copy: the same password opens it, and
it holds everything the vault held. The functions here say so in
their names and errors — no one should be able to make one by
accident.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from . import format as _format
from .credentials import CredentialStore
from .errors import VaultExistsError, VaultLockedError, VaultSaveError
from .publish import link_into_place

__all__ = ["export_sealed_copy", "import_from_vault"]


def export_sealed_copy(session, destination) -> Path:
    """Write a sealed copy of ``session``'s vault to ``destination``.

    The session's current state is saved first, so the copy holds
    the newest logins. The destination must not exist — a copy is
    never written over anything. The copy is published the same
    careful way a vault is: a temporary file beside the
    destination, put into place complete by :mod:`aegis.publish`,
    so a half-made copy can never sit at the destination looking
    whole, on any drive.
    """
    if session.is_locked:
        raise VaultLockedError()
    dest = Path(destination)
    if _format.windows_unsafe_segment(dest.name):
        raise VaultSaveError(
            "That name can't be used for a vault file on "
            "Windows. Pick a different name and try again."
        )
    if os.path.lexists(dest):
        raise VaultExistsError()
    session.save()
    source = session.path
    directory = str(dest.parent) if str(dest.parent) else "."
    fd, tmp_name = tempfile.mkstemp(
        dir=directory, prefix=dest.name + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as out, open(source, "rb") as inp:
            shutil.copyfileobj(inp, out)
            out.flush()
            os.fsync(out.fileno())
        try:
            link_into_place(tmp_name, dest)
        except FileExistsError:
            raise VaultExistsError() from None
        except OSError:
            raise VaultSaveError() from None
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    try:
        os.unlink(tmp_name)
    except OSError:
        pass
    return dest


def import_from_vault(target_store: CredentialStore, source_session) -> int:
    """Merge another open vault's logins into ``target_store``.

    Every login arrives as a new entry with a new id; its details
    and the date it was first saved are kept, and its last-changed
    date becomes the import moment. Matching names are not merged
    or skipped — duplicates are the owner's to sort out, and
    silently dropping a login would be worse. Returns how many
    logins were brought in.
    """
    if source_session.is_locked:
        raise VaultLockedError()
    source_store = CredentialStore(source_session)
    entries = [
        source_store.get(summary.id)
        for summary in source_store.summaries()
    ]
    return target_store.import_entries(entries)
