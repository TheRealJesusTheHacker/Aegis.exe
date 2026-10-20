"""The interface's controller: every core call, no Qt in sight.

The window talks to Aegis through this one object. It owns the
open session, the password store, the Strongbox, the auto-clearing
clipboard (Phase 2's seam, fed by whatever clipboard the caller
injects — the real desktop clipboard in the app, an in-memory one
in tests), and the idle guard (Phase 2's policy, fed real activity
by the window). Keeping Qt out of this layer means the whole
behavior of the interface — open, lock, copy, idle, every flow —
is testable headless, and the core's own suite never learns that
a window exists.

Discipline notes:

- Every change the core makes is saved by the core the moment it
  happens, so locking here is the Phase 1 lock exactly: the
  session's own ``lock()``, reached through the store, which wipes
  the vault key and drops the cached lists at the same moment.
- A lock that fails (the core raises because the save failed) is
  never hidden: :meth:`lock` lets it propagate, and the idle path
  reports it through ``on_error`` and lets the guard's own retry
  policy take the next tick — a vault that would not lock stays
  open, says so, and keeps trying.
- Copied secrets are cleared before anything else at lock time,
  and changing the clearing delay clears any pending secret early
  rather than carrying a deadline across settings.
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

from ..armor import armor_manifest, seal_tree, unseal_tree
from ..clipboard import (
    DEFAULT_CLEAR_AFTER_SECONDS,
    AutoClearClipboard,
    MemoryClipboard,
)
from ..credentials import CredentialStore
from ..errors import (
    AegisError,
    DocumentTooLargeError,
    SealedExistsError,
)
from ..generator import generate_password
from ..idle import DEFAULT_IDLE_SECONDS, IdleGuard
from ..kdf import DEFAULT_PARAMS
from ..locksend import open_sealed_file, seal_file
from ..strongbox import MAX_DOCUMENT_BYTES, Strongbox
from ..transfer import export_sealed_copy, import_from_vault
from ..vault import Vault

__all__ = ["VaultController", "user_text"]

_GENERIC_TEXT = (
    "Something went wrong. Please try again — if it keeps "
    "happening, close Aegis and open it again."
)


def user_text(exc: BaseException) -> str:
    """The one place an error becomes words on a screen.

    Core errors already speak plain language — their text is the
    message. EVERYTHING else becomes one calm generic line. The
    pass-through is by error type, never by guesswork: a bare
    ValueError can carry codec complaints and file paths, so no
    non-core text is ever shown. The few places with a genuinely
    authored plain message of their own (the password maker's
    length refusal) catch it at their own call site, where its
    source is known — not here.
    """
    if isinstance(exc, AegisError):
        return exc.user_message
    return _GENERIC_TEXT


class VaultController:
    """Owns one vault session and everything the window does with it."""

    def __init__(self, clipboard=None, *, clock=time.monotonic):
        self._port = clipboard if clipboard is not None else MemoryClipboard()
        self._clock = clock
        self.clear_after_seconds = float(DEFAULT_CLEAR_AFTER_SECONDS)
        self.idle_seconds = float(DEFAULT_IDLE_SECONDS)
        self._auto_clip = self._new_auto_clip()
        self._session = None
        self._store = None
        self._strongbox = None
        self._guard = None
        self.vault_path = None
        # Set by the window: called after a lock completes, and
        # with an exception when an idle lock fails during a tick.
        self.on_lock = None
        self.on_error = None
        # A failed idle lock is reported once per failure episode,
        # not on every tick (the guard retries underneath).
        self._lock_failure_reported = False

    # -- state ------------------------------------------------------

    @property
    def is_open(self) -> bool:
        return self._session is not None and not self._session.is_locked

    @property
    def session(self):
        return self._session

    @property
    def store(self) -> CredentialStore:
        if not self.is_open:
            from ..errors import VaultLockedError

            raise VaultLockedError()
        return self._store

    @property
    def strongbox(self) -> Strongbox:
        if not self.is_open:
            from ..errors import VaultLockedError

            raise VaultLockedError()
        return self._strongbox

    # -- open / create / lock ----------------------------------------

    def create_vault(self, path, password, *, params=DEFAULT_PARAMS) -> str:
        """Create a vault and open it; return the recovery key once."""
        created = Vault.create(path, password, params=params)
        self._adopt(created.session, Path(path))
        return created.recovery_key

    def open_vault(self, path, *, password=None, recovery_key=None) -> None:
        session = Vault.open(path, password=password, recovery_key=recovery_key)
        self._adopt(session, Path(path))

    def _adopt(self, session, path: Path) -> None:
        old = self._session
        if old is not None and old is not session and not old.is_locked:
            # Never orphan a live session: a replaced session is
            # locked (its key wiped) before it is let go. The
            # window's single-flight makes this unreachable in the
            # app; it is defense in depth, not the mechanism.
            try:
                old.lock()
            except Exception:
                pass
        self._lock_failure_reported = False
        self._session = session
        self.vault_path = path
        self._store = CredentialStore(session)
        self._strongbox = Strongbox(session)
        self._guard = IdleGuard(
            [self._lock_from_guard],
            idle_seconds=self.idle_seconds,
            clock=self._clock,
        )
        self._guard.touch()

    def _lock_sequence(self) -> None:
        """The one lock: clipboard first, then the Phase 1 lock."""
        self._auto_clip.clear_now()
        store, strongbox = self._store, self._strongbox
        try:
            if store is not None:
                store.lock()  # locks the session, forgets its cache
            elif self._session is not None:
                self._session.lock()
        finally:
            if strongbox is not None:
                strongbox.forget()

    def _drop_refs(self) -> None:
        self._session = None
        self._store = None
        self._strongbox = None
        self._guard = None

    def lock(self) -> None:
        """Lock now. A failure propagates — it is never hidden."""
        if self._session is None:
            return
        self._lock_sequence()
        self._drop_refs()
        if self.on_lock is not None:
            self.on_lock()

    def _lock_from_guard(self) -> None:
        """The idle guard's lockable: lock, then tell the window."""
        self._lock_sequence()
        self._drop_refs()
        if self.on_lock is not None:
            self.on_lock()

    # -- rhythm (the window calls this on a timer) --------------------

    def tick(self) -> None:
        """Run the clipboard countdown and the idle policy once."""
        self._auto_clip.check()
        if self._guard is not None and self.is_open:
            try:
                self._guard.check()
            except Exception as exc:  # the guard retries next tick
                if self.on_error is not None and not self._lock_failure_reported:
                    self._lock_failure_reported = True
                    self.on_error(exc)
            else:
                self._lock_failure_reported = False

    def touch(self) -> None:
        if self._guard is not None:
            self._guard.touch()

    # -- settings ------------------------------------------------------

    def _new_auto_clip(self) -> AutoClearClipboard:
        return AutoClearClipboard(
            self._port,
            clear_after_seconds=self.clear_after_seconds,
            clock=self._clock,
        )

    def apply_settings(self, *, idle_seconds=None, clear_after_seconds=None) -> None:
        """Apply timing settings for this run of the app.

        A pending copied secret is cleared early rather than
        carried across the change.
        """
        if clear_after_seconds is not None and float(
            clear_after_seconds
        ) != self.clear_after_seconds:
            self.clear_after_seconds = float(clear_after_seconds)
            self._auto_clip.clear_now()
            self._auto_clip = self._new_auto_clip()
        if idle_seconds is not None and float(idle_seconds) != self.idle_seconds:
            self.idle_seconds = float(idle_seconds)
            if self.is_open:
                self._guard = IdleGuard(
                    [self._lock_from_guard],
                    idle_seconds=self.idle_seconds,
                    clock=self._clock,
                )
                self._guard.touch()

    # -- passwords ------------------------------------------------------

    def search_logins(self, query: str = ""):
        return self.store.search(query)

    def get_login(self, entry_id: str):
        return self.store.get(entry_id)

    def add_login(self, title, *, username="", password="", url="", notes=""):
        entry = self.store.add(
            title, username=username, password=password, url=url, notes=notes
        )
        self.touch()
        return entry

    def update_login(self, entry_id: str, **changes):
        entry = self.store.update(entry_id, **changes)
        self.touch()
        return entry

    def delete_login(self, entry_id: str) -> None:
        self.store.remove(entry_id)
        self.touch()

    def copy_login_password(self, entry_id: str) -> None:
        """The one deliberate reveal, straight onto the clipboard."""
        secret = self.store.reveal_password(entry_id)
        self._auto_clip.copy_secret(secret)
        self.touch()

    def copy_text(self, text: str) -> None:
        """Copy a shown secret (a login's user name is not secret;
        this path is for passwords and Strongbox text)."""
        self._auto_clip.copy_secret(text)
        self.touch()

    def make_password(self, length, *, lowercase=True, uppercase=True,
                      digits=True, symbols=True) -> str:
        return generate_password(
            length,
            use_lowercase=lowercase,
            use_uppercase=uppercase,
            use_digits=digits,
            use_symbols=symbols,
        )

    # -- Strongbox ------------------------------------------------------

    def list_items(self, kind=None):
        return self.strongbox.summaries(kind)

    def get_item(self, entry_id: str):
        return self.strongbox.get(entry_id)

    def reveal_item(self, entry_id: str) -> str:
        return self.strongbox.reveal(entry_id)

    def add_text_item(self, kind, title, body):
        entry = self.strongbox.add_text(kind, title, body)
        self.touch()
        return entry

    def add_document_from_path(self, title, file_path):
        """Save a document copy from a file on disk.

        The size is checked before a single byte is read, so
        pointing Aegis at an enormous file costs nothing; the name
        is the file's own plain name, judged by the core's rules
        (which refuse names like ``..`` outright).
        """
        path = Path(file_path)
        try:
            size = os.path.getsize(path)
        except OSError:
            from ..errors import SealedSourceError

            raise SealedSourceError(
                "That file isn't there, or this computer can't read "
                "it right now. Check the file and try again."
            ) from None
        if size > MAX_DOCUMENT_BYTES:
            raise DocumentTooLargeError()
        data = self._read_intake_file(path)
        entry = self.strongbox.add_document(title, path.name, data)
        self.touch()
        return entry

    @staticmethod
    def _read_intake_file(path: Path) -> bytes:
        """Read a file the person pointed Aegis at, plainly or not at all.

        A directory, a vanished file, or anything unreadable is a
        designed refusal — never a raw system error on a screen.
        The read itself is capped as it streams: the size checked
        a moment ago is not trusted, so a file that grows, is
        swapped, or misreports its size is refused the moment it
        passes the cap — never loaded whole into memory first.
        """
        from ..errors import SealedSourceError

        if not path.is_file():
            raise SealedSourceError(
                "That isn't a plain file, so Aegis can't keep a "
                "copy of it. Pick a file and try again."
            )
        chunks = []
        total = 0
        try:
            with open(path, "rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_DOCUMENT_BYTES:
                        raise DocumentTooLargeError()
                    chunks.append(chunk)
        except DocumentTooLargeError:
            raise
        except OSError:
            raise SealedSourceError(
                "Aegis couldn't read that file. Check it and try again."
            ) from None
        return b"".join(chunks)

    def save_document_copy(self, entry_id: str, destination) -> Path:
        """Write a document copy out; never overwrites."""
        filename, data = self.strongbox.read_document(entry_id)
        dest = Path(destination)
        try:
            with open(dest, "xb") as handle:
                handle.write(data)
        except FileExistsError:
            raise SealedExistsError() from None
        except OSError:
            from ..errors import SealedSaveError

            raise SealedSaveError() from None
        self.touch()
        return dest

    def update_item(self, entry_id: str, *, title=None, body=None):
        entry = self.strongbox.update(entry_id, title=title, body=body)
        self.touch()
        return entry

    def replace_document_from_path(self, entry_id: str, file_path):
        path = Path(file_path)
        try:
            size = os.path.getsize(path)
        except OSError:
            from ..errors import SealedSourceError

            raise SealedSourceError(
                "That file isn't there, or this computer can't read "
                "it right now. Check the file and try again."
            ) from None
        if size > MAX_DOCUMENT_BYTES:
            raise DocumentTooLargeError()
        entry = self.strongbox.replace_document(
            entry_id, self._read_intake_file(path), filename=path.name
        )
        self.touch()
        return entry

    def delete_item(self, entry_id: str) -> None:
        self.strongbox.remove(entry_id)
        self.touch()

    # -- Lock-and-send ---------------------------------------------------

    def seal_a_file(self, source, password, destination=None) -> Path:
        result = seal_file(source, password, destination)
        self.touch()
        return result

    def open_a_sealed_file(self, sealed_path, password, destination_dir=None,
                           *, place_guard=None) -> Path:
        """Open a sealed file, placing the result only if allowed.

        The file is opened into a holding folder first; the move
        into its real place happens only when ``place_guard`` (if
        given) still says yes at that moment. If the app locked
        while the opening ran, the held copy is removed and
        nothing is placed — a lock must never be followed by new
        plain files appearing on disk.
        """
        if place_guard is None:
            result = open_sealed_file(sealed_path, password, destination_dir)
            self.touch()
            return result
        from ..errors import VaultLockedError

        src = Path(sealed_path)
        dest_dir = (
            Path(destination_dir) if destination_dir is not None else src.parent
        )
        staging = Path(tempfile.mkdtemp(dir=str(dest_dir), prefix=".aegis-opening-"))
        try:
            staged = open_sealed_file(sealed_path, password, staging)
            if not place_guard():
                raise VaultLockedError()
            target = dest_dir / staged.name
            if os.path.lexists(target):
                from ..errors import SealedExistsError

                raise SealedExistsError(
                    "There's already a file called \"%s\" there. "
                    "Move it, rename it, or open this into a "
                    "different folder." % staged.name
                )
            os.rename(staged, target)
        finally:
            import shutil

            shutil.rmtree(staging, ignore_errors=True)
        self.touch()
        return target

    # -- Backup sets (Lazarus's armor) -----------------------------------

    def seal_a_folder(self, folder, password, destination=None) -> Path:
        result = seal_tree(folder, password, destination)
        self.touch()
        return result

    def look_inside_set(self, sealed_path, password):
        return armor_manifest(sealed_path, password)

    def unseal_a_set(self, sealed_path, password, destination,
                     *, place_guard=None) -> Path:
        result = unseal_tree(
            sealed_path, password, destination, place_guard=place_guard
        )
        self.touch()
        return result

    # -- Vault care --------------------------------------------------------

    def change_password(self, new_password: str) -> None:
        self.store.session.change_password(new_password)
        self.touch()

    def new_recovery_key(self) -> str:
        key = self.store.session.regenerate_recovery_key()
        self.touch()
        return key

    def export_copy(self, destination) -> Path:
        result = export_sealed_copy(self.store.session, destination)
        self.touch()
        return result

    def import_logins(self, source_path, password) -> int:
        """Bring in the logins from another vault; returns the count.

        The other vault is opened with the password given, read,
        and locked again in all cases — it is never left open.
        """
        source = Vault.open(source_path, password=password)
        try:
            count = import_from_vault(self.store, source)
        finally:
            source.lock()
        self.touch()
        return count
