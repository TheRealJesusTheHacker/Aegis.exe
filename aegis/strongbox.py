"""The Strongbox: the vault's compartment for small, critical things.

Phase 3, standing on the Phase 1 core exactly as the password
vault does. The Strongbox holds what is not a login: recovery
codes, keys, private notes, and copies of documents. It is not a
second format and has no cryptography of its own — the items live
inside an ordinary vault:

- the list itself is one reserved item, ``strongbox/manifest.json``;
- a document copy's bytes are one more vault item per document,
  ``strongbox/files/<id>``, with the document's original file name,
  size, and SHA-256 check value recorded in the list, so a copy
  that is read back is verified against what was saved before it
  is handed over.

Everything is sealed by the same vault key, opened by the same
master password and recovery key, and covered by the same password
changes, recovery path, tamper checks, and stale-session guard as
every other item in the vault.

Honest notes, same as the rest of Aegis:

- Summaries and printed forms never carry an item's contents: a
  code, a key, or a note's text leaves the Strongbox through one
  deliberate reveal path, and a document through its read path.
- A document whose bytes have gone missing or no longer match
  their recorded check value is refused at read time as damaged —
  the rest of the Strongbox, and the rest of the vault, still work.
- The list is parsed into memory while the vault is open, the same
  posture as the session itself; it is dropped, not scrubbed, when
  the vault locks. The full memory review is Phase 5's gate.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import format as _format
from .errors import (
    DocumentTooLargeError,
    EntryNotFoundError,
    InvalidStrongboxEntryError,
    StrongboxDamagedError,
    StrongboxNotFoundError,
    VaultLockedError,
)
from .vault import VaultSession

__all__ = [
    "STRONGBOX_ENTRY_NAME",
    "MAX_DOCUMENT_BYTES",
    "KIND_CODE",
    "KIND_KEY",
    "KIND_NOTE",
    "KIND_DOCUMENT",
    "KIND_LABELS",
    "StrongboxEntry",
    "StrongboxSummary",
    "Strongbox",
]

#: The reserved vault item that holds the Strongbox's list.
STRONGBOX_ENTRY_NAME = "strongbox/manifest.json"

#: A document copy's bytes live under this prefix, one item each.
_DOCUMENT_PREFIX = "strongbox/files/"

#: The largest document copy the Strongbox holds: 10 MB. Past this,
#: the file itself belongs in the vault as a file, not as a copy in
#: the Strongbox's quick-access compartment.
MAX_DOCUMENT_BYTES = 10 * 1024 * 1024

KIND_CODE = "code"
KIND_KEY = "key"
KIND_NOTE = "note"
KIND_DOCUMENT = "document"

#: Plain-language names for the kinds of thing the Strongbox holds.
KIND_LABELS = {
    KIND_CODE: "Recovery code",
    KIND_KEY: "Key",
    KIND_NOTE: "Private note",
    KIND_DOCUMENT: "Document copy",
}

_TEXT_KINDS = (KIND_CODE, KIND_KEY, KIND_NOTE)
_ALL_KINDS = (KIND_CODE, KIND_KEY, KIND_NOTE, KIND_DOCUMENT)

_STORE_VERSION = 1

_MAX_TITLE = 200
_MAX_BODY = 100000
_MAX_FILENAME = 255


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _check_text(value, limit, *, allow_empty=True):
    if not isinstance(value, str):
        raise InvalidStrongboxEntryError()
    if len(value) > limit:
        raise InvalidStrongboxEntryError()
    if not allow_empty and not value.strip():
        raise InvalidStrongboxEntryError()
    return value


def _check_filename(filename):
    """A document's original name must stay a plain file name."""
    if not isinstance(filename, str):
        raise InvalidStrongboxEntryError()
    if not 1 <= len(filename) <= _MAX_FILENAME:
        raise InvalidStrongboxEntryError()
    if filename in (".", ".."):
        raise InvalidStrongboxEntryError()
    if "/" in filename or "\\" in filename or "\x00" in filename:
        raise InvalidStrongboxEntryError()
    return filename


def _document_item_name(entry_id: str) -> str:
    return _DOCUMENT_PREFIX + entry_id


@dataclass
class StrongboxEntry:
    """One item in the Strongbox.

    ``body`` (a code, a key, or a note's text) is excluded from
    ``repr``/``str``: echoing or logging an item can never spill
    what it holds. Document copies keep their bytes in the vault,
    not on this object; ``size`` and ``sha256`` describe them.
    """

    id: str
    kind: str
    title: str
    body: str = field(default="", repr=False)
    filename: str = ""
    size: int = 0
    sha256: str = ""
    created_utc: str = ""
    modified_utc: str = ""

    @property
    def kind_label(self) -> str:
        return KIND_LABELS[self.kind]

    def summary(self) -> "StrongboxSummary":
        """A contents-free view of this item, for lists."""
        return StrongboxSummary(
            id=self.id,
            kind=self.kind,
            title=self.title,
            filename=self.filename,
            size=self.size,
            created_utc=self.created_utc,
            modified_utc=self.modified_utc,
        )

    def describe(self) -> str:
        """Plain-language lines about this item — never its contents."""
        lines = [self.title, "Kind: %s" % KIND_LABELS[self.kind]]
        if self.kind == KIND_DOCUMENT:
            lines.append("File: %s" % self.filename)
        return "\n".join(lines)


@dataclass(frozen=True)
class StrongboxSummary:
    """A Strongbox item without its contents — safe to show and list."""

    id: str
    kind: str
    title: str
    filename: str
    size: int
    created_utc: str
    modified_utc: str

    @property
    def kind_label(self) -> str:
        return KIND_LABELS[self.kind]


class Strongbox:
    """The Strongbox inside one open vault session."""

    def __init__(self, session: VaultSession):
        self._session = session
        self._entries = None  # None = not loaded yet

    # -- session discipline --------------------------------------------------

    @property
    def session(self) -> VaultSession:
        return self._session

    def _require_open(self) -> None:
        if self._session.is_locked:
            self._entries = None
            raise VaultLockedError()

    def forget(self) -> None:
        """Drop the in-memory list without touching the vault."""
        self._entries = None

    def lock(self) -> None:
        """Lock the vault this Strongbox belongs to, forgetting the list."""
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
            raw = self._session.read(STRONGBOX_ENTRY_NAME)
        except EntryNotFoundError:
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
                    "kind": e.kind,
                    "title": e.title,
                    "body": e.body,
                    "filename": e.filename,
                    "size": e.size,
                    "sha256": e.sha256,
                    "created_utc": e.created_utc,
                    "modified_utc": e.modified_utc,
                }
                for e in self._entries
            ],
        }
        raw = json.dumps(
            doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        self._session.write(STRONGBOX_ENTRY_NAME, raw)
        self._session.save()

    # -- queries -----------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._load())

    def summaries(self, kind: str = None) -> list:
        """All items, without contents, in stored order.

        ``kind`` may name one kind (``"code"``, ``"key"``,
        ``"note"``, ``"document"``) to list only that kind.
        """
        entries = self._load()
        if kind is not None:
            if kind not in _ALL_KINDS:
                raise InvalidStrongboxEntryError()
            entries = [e for e in entries if e.kind == kind]
        return [entry.summary() for entry in entries]

    def get(self, entry_id: str) -> StrongboxEntry:
        """Return the item with this id (text items carry their text)."""
        for entry in self._load():
            if entry.id == entry_id:
                return entry
        raise StrongboxNotFoundError()

    def reveal(self, entry_id: str) -> str:
        """Return a text item's contents — the deliberate reveal.

        This is the one path a code, a key, or a note's text
        leaves the Strongbox on purpose. Document copies are read
        with :meth:`read_document` instead.
        """
        entry = self.get(entry_id)
        if entry.kind == KIND_DOCUMENT:
            raise InvalidStrongboxEntryError(
                "That item is a document copy. "
                "Read it as a document to see what's in it."
            )
        return entry.body

    def read_document(self, entry_id: str):
        """Return ``(original filename, bytes)`` for a document copy.

        The bytes are checked against the size and check value
        recorded when the copy was saved; a copy that doesn't
        check out is refused as damaged, never handed over.
        """
        entry = self.get(entry_id)
        if entry.kind != KIND_DOCUMENT:
            raise InvalidStrongboxEntryError(
                "That item isn't a document copy, so there's "
                "no file to read from it."
            )
        try:
            data = self._session.read(_document_item_name(entry.id))
        except EntryNotFoundError:
            raise StrongboxDamagedError() from None
        if len(data) != entry.size or hashlib.sha256(data).hexdigest() != entry.sha256:
            raise StrongboxDamagedError()
        return entry.filename, data

    # -- changes -------------------------------------------------------------------

    def add_text(self, kind: str, title, body) -> StrongboxEntry:
        """Save a recovery code, key, or private note and return it."""
        entries = self._load()
        if kind not in _TEXT_KINDS:
            raise InvalidStrongboxEntryError(
                "Text items in the Strongbox are recovery codes, "
                "keys, or private notes. Save a file as a "
                "document copy instead."
            )
        entry = StrongboxEntry(
            id=secrets.token_hex(8),
            kind=kind,
            title=_check_text(title, _MAX_TITLE, allow_empty=False),
            body=_check_text(body, _MAX_BODY, allow_empty=False),
            created_utc=_now_utc(),
            modified_utc=_now_utc(),
        )
        entries.append(entry)
        self._persist()
        return entry

    def add_document(self, title, filename, data) -> StrongboxEntry:
        """Save a copy of a document (its name and bytes) and return it.

        The copy is capped at :data:`MAX_DOCUMENT_BYTES`; past the
        cap the refusal says so plainly, because the file itself
        belongs in the vault as a file, not in the Strongbox.
        """
        entries = self._load()
        title = _check_text(title, _MAX_TITLE, allow_empty=False)
        filename = _check_filename(filename)
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("A document copy must be bytes.")
        data = bytes(data)
        if len(data) > MAX_DOCUMENT_BYTES:
            raise DocumentTooLargeError()
        entry = StrongboxEntry(
            id=secrets.token_hex(8),
            kind=KIND_DOCUMENT,
            title=title,
            filename=filename,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            created_utc=_now_utc(),
            modified_utc=_now_utc(),
        )
        self._session.write(_document_item_name(entry.id), data)
        entries.append(entry)
        self._persist()
        return entry

    def update(self, entry_id, *, title=None, body=None) -> StrongboxEntry:
        """Change an item's title, or a text item's contents.

        Everything is checked before anything changes, so a
        refused update leaves the item exactly as it was. A
        document copy's bytes change through
        :meth:`replace_document`, never here.
        """
        entries = self._load()
        for entry in entries:
            if entry.id == entry_id:
                new_title = entry.title
                new_body = entry.body
                if title is not None:
                    new_title = _check_text(
                        title, _MAX_TITLE, allow_empty=False
                    )
                if body is not None:
                    if entry.kind == KIND_DOCUMENT:
                        raise InvalidStrongboxEntryError(
                            "That item is a document copy. Replace "
                            "the document itself to change what's "
                            "in it."
                        )
                    new_body = _check_text(
                        body, _MAX_BODY, allow_empty=False
                    )
                entry.title = new_title
                entry.body = new_body
                entry.modified_utc = _now_utc()
                self._persist()
                return entry
        raise StrongboxNotFoundError()

    def replace_document(self, entry_id, data, filename=None) -> StrongboxEntry:
        """Replace a document copy's bytes (and, optionally, its name)."""
        entries = self._load()
        for entry in entries:
            if entry.id == entry_id:
                if entry.kind != KIND_DOCUMENT:
                    raise InvalidStrongboxEntryError(
                        "That item isn't a document copy, so "
                        "there's no document to replace."
                    )
                new_filename = entry.filename
                if filename is not None:
                    new_filename = _check_filename(filename)
                if not isinstance(data, (bytes, bytearray, memoryview)):
                    raise TypeError("A document copy must be bytes.")
                data = bytes(data)
                if len(data) > MAX_DOCUMENT_BYTES:
                    raise DocumentTooLargeError()
                entry.filename = new_filename
                entry.size = len(data)
                entry.sha256 = hashlib.sha256(data).hexdigest()
                entry.modified_utc = _now_utc()
                self._session.write(_document_item_name(entry.id), data)
                self._persist()
                return entry
        raise StrongboxNotFoundError()

    def remove(self, entry_id) -> None:
        """Delete an item from the Strongbox (and a copy's bytes)."""
        entries = self._load()
        for index, entry in enumerate(entries):
            if entry.id == entry_id:
                del entries[index]
                if entry.kind == KIND_DOCUMENT:
                    try:
                        self._session.remove(_document_item_name(entry.id))
                    except EntryNotFoundError:
                        # The bytes were already gone; the list is
                        # what the person asked to change.
                        pass
                self._persist()
                return
        raise StrongboxNotFoundError()

    # -- context manager -----------------------------------------------------------

    def __enter__(self) -> "Strongbox":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.lock()
        return False


def _parse_store(raw: bytes) -> list:
    """Parse the sealed Strongbox list, refusing anything off-shape.

    The vault payload is authenticated end to end, so a list that
    fails these checks was not written by this module — it is
    refused as damaged rather than guessed at.
    """
    try:
        doc = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_format.reject_duplicate_keys,
        )
    except Exception:
        raise StrongboxDamagedError() from None
    if not isinstance(doc, dict):
        raise StrongboxDamagedError()
    version = doc.get("version")
    if type(version) is not int or version != _STORE_VERSION:
        raise StrongboxDamagedError()
    docs = doc.get("entries")
    if not isinstance(docs, list):
        raise StrongboxDamagedError()
    entries = []
    seen_ids = set()
    for item in docs:
        if not isinstance(item, dict):
            raise StrongboxDamagedError()
        if set(item.keys()) != {
            "id", "kind", "title", "body", "filename", "size",
            "sha256", "created_utc", "modified_utc",
        }:
            raise StrongboxDamagedError()
        for key in (
            "id", "kind", "title", "body", "filename",
            "sha256", "created_utc", "modified_utc",
        ):
            if not isinstance(item[key], str):
                raise StrongboxDamagedError()
        if type(item["size"]) is not int or item["size"] < 0:
            raise StrongboxDamagedError()
        entry = StrongboxEntry(
            id=item["id"],
            kind=item["kind"],
            title=item["title"],
            body=item["body"],
            filename=item["filename"],
            size=item["size"],
            sha256=item["sha256"],
            created_utc=item["created_utc"],
            modified_utc=item["modified_utc"],
        )
        if not entry.id or entry.id in seen_ids:
            raise StrongboxDamagedError()
        seen_ids.add(entry.id)
        if entry.kind not in _ALL_KINDS:
            raise StrongboxDamagedError()
        if entry.kind in _TEXT_KINDS:
            # A text item never carries document details.
            if entry.filename or entry.size != 0 or entry.sha256:
                raise StrongboxDamagedError()
        else:
            # A document copy never carries text contents, and its
            # recorded details must be well-formed.
            if entry.body:
                raise StrongboxDamagedError()
            try:
                _check_filename(entry.filename)
            except InvalidStrongboxEntryError:
                raise StrongboxDamagedError() from None
            if (
                len(entry.sha256) != 64
                or any(c not in "0123456789abcdef" for c in entry.sha256)
            ):
                raise StrongboxDamagedError()
        entries.append(entry)
    return entries
