"""The password vault: saved logins, held inside an Aegis vault.

Phase 2 stands entirely on the Phase 1 core. A credential store is
not a second format and has no cryptography of its own: the logins
live as one reserved item — ``passwords/manifest.json`` — inside an
ordinary vault, sealed by the same vault key, opened by the same
master password and recovery key, and covered by the same password
changes, recovery resets, tamper checks, and stale-session guard as
every other item in the vault. Nothing readable exists on disk
while the vault is locked, because nothing readable exists on disk
at any time: the vault file is sealed even while a session is open.

Design notes, stated honestly:

- The store caches the parsed logins in memory while the vault is
  open — the same posture as the session itself, which holds the
  vault's contents in memory for as long as it is open. Python
  strings cannot be scrubbed the way the vault key buffer is, so
  the cache is *dropped*, not erased, when the store is forgotten;
  a full memory-handling review is Phase 5's release gate, as it is
  for the rest of Aegis.
- The store refuses to work the moment its session is locked, and
  locking through the store (or the idle guard in :mod:`aegis.idle`)
  forgets the cache at the same moment the session wipes its keys.
- Search looks at names, user names, and web addresses only — never
  at passwords, and never at notes. There is no index of password
  values anywhere, in memory or on disk, beyond the sealed logins
  themselves.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import format as _format
from .errors import (
    CredentialNotFoundError,
    EntryNotFoundError,
    InvalidCredentialError,
    PasswordStoreDamagedError,
    VaultLockedError,
)
from .vault import VaultSession

__all__ = [
    "STORE_ENTRY_NAME",
    "CredentialEntry",
    "CredentialSummary",
    "CredentialStore",
]

#: The reserved vault item that holds the saved logins. Anything a
#: person stored under this exact name by hand is the store's list
#: as far as Aegis is concerned — the name is the store's door.
STORE_ENTRY_NAME = "passwords/manifest.json"

_STORE_VERSION = 1

_MAX_TITLE = 200
_MAX_USERNAME = 500
_MAX_PASSWORD = 1000
_MAX_URL = 2000
_MAX_NOTES = 10000


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _check_text(value, limit, *, allow_empty=True):
    if not isinstance(value, str):
        raise InvalidCredentialError()
    if len(value) > limit:
        raise InvalidCredentialError()
    if not allow_empty and not value.strip():
        raise InvalidCredentialError()
    return value


@dataclass
class CredentialEntry:
    """One saved login.

    ``password`` is excluded from ``repr``/``str``: echoing or
    logging an entry can never spill the secret it holds (the same
    lesson Phase 1 learned with the recovery key).
    """

    id: str
    title: str
    username: str
    password: str = field(repr=False)
    url: str = ""
    notes: str = ""
    created_utc: str = ""
    modified_utc: str = ""

    def summary(self) -> "CredentialSummary":
        """A password-free view of this login, for lists and search."""
        return CredentialSummary(
            id=self.id,
            title=self.title,
            username=self.username,
            url=self.url,
            created_utc=self.created_utc,
            modified_utc=self.modified_utc,
        )

    def describe(self) -> str:
        """Plain-language lines about this login — never the password."""
        lines = [self.title]
        if self.username:
            lines.append("User name: %s" % self.username)
        if self.url:
            lines.append("Site: %s" % self.url)
        lines.append("Password: saved (hidden)")
        return "\n".join(lines)


@dataclass(frozen=True)
class CredentialSummary:
    """A saved login without its password — safe to show and search."""

    id: str
    title: str
    username: str
    url: str
    created_utc: str
    modified_utc: str


class CredentialStore:
    """The saved logins inside one open vault session."""

    def __init__(self, session: VaultSession):
        self._session = session
        self._entries = None  # None = not loaded yet

    # -- session discipline --------------------------------------------------

    @property
    def session(self) -> VaultSession:
        return self._session

    def _require_open(self) -> None:
        if self._session.is_locked:
            # The session is gone; drop the cache with it.
            self._entries = None
            raise VaultLockedError()

    def forget(self) -> None:
        """Drop the in-memory logins without touching the vault.

        Called when the vault locks (directly or through the idle
        guard) so the store keeps nothing the session no longer
        holds the keys to.
        """
        self._entries = None

    def lock(self) -> None:
        """Lock the vault this store belongs to, forgetting the cache."""
        try:
            self._session.lock()
        finally:
            self.forget()

    # -- loading / saving ------------------------------------------------------

    def _load(self) -> list:
        self._require_open()
        if self._entries is not None:
            return self._entries
        try:
            raw = self._session.read(STORE_ENTRY_NAME)
        except EntryNotFoundError:
            # No store item yet: a fresh, empty store.
            self._entries = []
            return self._entries
        self._entries = _parse_store(raw)
        return self._entries

    def _persist(self) -> None:
        doc = {
            "version": _STORE_VERSION,
            "entries": [
                {
                    "id": e.id,
                    "title": e.title,
                    "username": e.username,
                    "password": e.password,
                    "url": e.url,
                    "notes": e.notes,
                    "created_utc": e.created_utc,
                    "modified_utc": e.modified_utc,
                }
                for e in self._entries
            ],
        }
        raw = json.dumps(
            doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        self._session.write(STORE_ENTRY_NAME, raw)
        self._session.save()

    # -- queries -----------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._load())

    def summaries(self) -> list:
        """All saved logins, without passwords, in stored order."""
        return [entry.summary() for entry in self._load()]

    def get(self, entry_id: str) -> CredentialEntry:
        """Return the full login with this id (password included)."""
        for entry in self._load():
            if entry.id == entry_id:
                return entry
        raise CredentialNotFoundError()

    def reveal_password(self, entry_id: str) -> str:
        """Return just the password for a login — the deliberate reveal.

        This is the one path the copy flow uses, so there is exactly
        one place a password leaves the store on purpose.
        """
        return self.get(entry_id).password

    def search(self, query: str) -> list:
        """Find logins by name, user name, or web address.

        Passwords and notes are never searched, so a search can
        never become a way to test whether a password is inside.
        Returns password-free summaries.
        """
        self._require_open()
        if not isinstance(query, str):
            raise TypeError("A search must be text.")
        needle = query.strip().lower()
        entries = self._load()
        if not needle:
            return [entry.summary() for entry in entries]
        found = []
        for entry in entries:
            haystacks = (entry.title, entry.username, entry.url)
            if any(needle in text.lower() for text in haystacks):
                found.append(entry.summary())
        return found

    # -- changes -------------------------------------------------------------------

    def add(self, title, *, username="", password="", url="", notes=""):
        """Save a new login and return it."""
        entries = self._load()
        entry = CredentialEntry(
            id=secrets.token_hex(8),
            title=_check_text(title, _MAX_TITLE, allow_empty=False),
            username=_check_text(username, _MAX_USERNAME),
            password=_check_text(password, _MAX_PASSWORD),
            url=_check_text(url, _MAX_URL),
            notes=_check_text(notes, _MAX_NOTES),
            created_utc=_now_utc(),
            modified_utc=_now_utc(),
        )
        entries.append(entry)
        self._persist()
        return entry

    def update(self, entry_id, **changes):
        """Change fields of a saved login and return the updated login.

        Accepted fields: title, username, password, url, notes.
        Unknown fields are refused.
        """
        entries = self._load()
        allowed = {"title", "username", "password", "url", "notes"}
        if not set(changes) <= allowed:
            raise InvalidCredentialError()
        # Validate everything before changing anything, so a
        # refused update leaves the saved login exactly as it was.
        limits = {
            "title": (_MAX_TITLE, False),
            "username": (_MAX_USERNAME, True),
            "password": (_MAX_PASSWORD, True),
            "url": (_MAX_URL, True),
            "notes": (_MAX_NOTES, True),
        }
        checked = {
            name: _check_text(value, limits[name][0],
                              allow_empty=limits[name][1])
            for name, value in changes.items()
        }
        for entry in entries:
            if entry.id == entry_id:
                for name, value in checked.items():
                    setattr(entry, name, value)
                entry.modified_utc = _now_utc()
                self._persist()
                return entry
        raise CredentialNotFoundError()

    def import_entries(self, entries) -> int:
        """Bring in copies of logins from another vault's store.

        Each arrives as a new login with a fresh id; its details
        and first-saved date are kept, and its last-changed date
        becomes the moment of import. Nothing is merged or skipped
        — duplicates are the owner's to sort out, and silently
        dropping a login would be worse. Returns how many logins
        were brought in. Used by :mod:`aegis.transfer`.
        """
        loaded = self._load()
        brought = 0
        for entry in entries:
            loaded.append(
                CredentialEntry(
                    id=secrets.token_hex(8),
                    title=_check_text(entry.title, _MAX_TITLE,
                                      allow_empty=False),
                    username=_check_text(entry.username, _MAX_USERNAME),
                    password=_check_text(entry.password, _MAX_PASSWORD),
                    url=_check_text(entry.url, _MAX_URL),
                    notes=_check_text(entry.notes, _MAX_NOTES),
                    created_utc=entry.created_utc,
                    modified_utc=_now_utc(),
                )
            )
            brought += 1
        if brought:
            self._persist()
        return brought

    def remove(self, entry_id) -> None:
        """Delete a saved login."""
        entries = self._load()
        for index, entry in enumerate(entries):
            if entry.id == entry_id:
                del entries[index]
                self._persist()
                return
        raise CredentialNotFoundError()

    # -- context manager -----------------------------------------------------------

    def __enter__(self) -> "CredentialStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.lock()
        return False


def _parse_store(raw: bytes) -> list:
    """Parse the sealed store document, refusing anything off-shape.

    The vault payload is authenticated end to end, so a document
    that fails these checks was not written by this store — it is
    refused as damaged rather than guessed at.
    """
    try:
        doc = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_format.reject_duplicate_keys,
        )
    except Exception:
        raise PasswordStoreDamagedError() from None
    if not isinstance(doc, dict):
        raise PasswordStoreDamagedError()
    version = doc.get("version")
    if type(version) is not int or version != _STORE_VERSION:
        raise PasswordStoreDamagedError()
    docs = doc.get("entries")
    if not isinstance(docs, list):
        raise PasswordStoreDamagedError()
    entries = []
    seen_ids = set()
    for item in docs:
        if not isinstance(item, dict):
            raise PasswordStoreDamagedError()
        fields = {}
        for key in (
            "id", "title", "username", "password", "url", "notes",
            "created_utc", "modified_utc",
        ):
            value = item.get(key)
            if not isinstance(value, str):
                raise PasswordStoreDamagedError()
            fields[key] = value
        if not fields["id"] or fields["id"] in seen_ids:
            raise PasswordStoreDamagedError()
        seen_ids.add(fields["id"])
        entries.append(CredentialEntry(**fields))
    return entries
