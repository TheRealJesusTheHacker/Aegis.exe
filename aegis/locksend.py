"""Lock-and-send: one file, sealed with its own password, to travel.

A file that has to leave the machine — a contract, a report, a
client document going by email or USB — is sealed here with a
password chosen for that file. The output is one sealed file
(``.aegis-send``). Whoever receives it opens it with the same
password in their own copy of Aegis (a small standalone opener may
come later; it does not exist yet, and nothing here pretends
otherwise).

The construction is the standalone sealed-file construction in
:mod:`aegis.sealed` — the Phase 1 vault construction re-shaped for
one file and one password. Nothing new was invented for this.

What the sealed file carries, and what it does not:

- The file's name and contents stay inside the seal. The sealed
  file's own name is a plain default (``sealed-file.aegis-send``)
  that says nothing about what is inside, unless the person
  sealing it chooses a name themselves.
- Aegis never sends anything. This module makes a sealed file on
  this machine; how it travels, and how the password reaches the
  other person, are the sender's choices — which is why the flow
  copy below says, plainly, that the password is the whole lock
  and must travel a different way than the file.
"""

from __future__ import annotations

import io
import json
import os
import struct
from pathlib import Path

from . import format as _format
from .errors import (
    SealedExistsError,
    SealedFormatError,
    SealedSaveError,
    SealedSourceError,
    SealedTamperedError,
)
from .kdf import DEFAULT_PARAMS, KdfParams
from .sealed import (
    SEND_MAGIC,
    SealedWriter,
    open_sealed,
    write_new_file,
)

__all__ = [
    "SEALED_FILE_SUFFIX",
    "DEFAULT_SEALED_NAME",
    "LOCK_AND_SEND_PASSWORD_NOTE",
    "seal_file",
    "read_sealed_file",
    "open_sealed_file",
]

#: The suffix every Lock-and-send file carries.
SEALED_FILE_SUFFIX = ".aegis-send"

#: The name a sealed file gets when the sender doesn't choose one.
#: It is deliberately plain: it never repeats the name of what's
#: inside, so the sealed file's name gives nothing away.
DEFAULT_SEALED_NAME = "sealed-file" + SEALED_FILE_SUFFIX

#: Shown where a person sets the password for a file they are
#: about to send. The password is the security — the copy says so.
LOCK_AND_SEND_PASSWORD_NOTE = (
    "One thing to know before you send: the password is the whole "
    "lock on this file. Anyone who gets the file and the password "
    "can open it — there is no second check, and Aegis can't take "
    "it back once it has gone. Share the password a different way "
    "than the file: if the file goes by email, give the password "
    "by phone or in person, never in the same message."
)

_STREAM_BYTES = 1 << 20
_INNER_MANIFEST_VERSION = 1
# The inner document describing the sealed file: a version and one
# file name. It lives inside the seal, so it gets a tight cap.
_MAX_INNER_MANIFEST_BYTES = 8192


def _inner_manifest(filename: str) -> bytes:
    doc = {"version": _INNER_MANIFEST_VERSION, "filename": filename}
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _parse_inner_manifest(raw: bytes) -> str:
    """Read the sealed contents' first document; return the file name.

    Everything here arrives through authenticated contents, so an
    ill-formed document — or a "name" that is really a path trying
    to escape the folder it opens into — is damage, and refused.
    """
    try:
        doc = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_format.reject_duplicate_keys,
        )
    except Exception:
        raise SealedTamperedError() from None
    if not isinstance(doc, dict) or set(doc.keys()) != {"version", "filename"}:
        raise SealedTamperedError()
    version = doc["version"]
    if type(version) is not int or version != _INNER_MANIFEST_VERSION:
        raise SealedTamperedError()
    filename = doc["filename"]
    if not isinstance(filename, str):
        raise SealedTamperedError()
    if (
        not 1 <= len(filename) <= 255
        or filename in (".", "..")
        or _format.windows_unsafe_segment(filename)
        or "/" in filename
        or "\\" in filename
        or "\x00" in filename
    ):
        raise SealedTamperedError()
    return filename


def _read_inner_header(reader):
    """Read (file name, reader) — the name from the sealed contents."""
    (length,) = struct.unpack(">I", reader.read_exact(4))
    if length < 1 or length > _MAX_INNER_MANIFEST_BYTES:
        raise SealedTamperedError()
    return _parse_inner_manifest(reader.read_exact(length))


def seal_file(source, password: str, destination=None, *,
              params: KdfParams = DEFAULT_PARAMS) -> Path:
    """Seal the file at ``source`` with ``password``; return its path.

    The sealed file is written beside the original (or at
    ``destination``, which may be a folder to write into) under
    :data:`DEFAULT_SEALED_NAME` unless a full file path is given.
    Nothing already there is ever overwritten.
    """
    src = Path(source)
    if src.is_symlink():
        src = src.resolve()
    if not src.exists():
        raise SealedSourceError(
            "That file isn't there, or this computer can't read "
            "it right now. Check the file and try again."
        )
    if src.is_dir():
        raise SealedSourceError(
            "That's a folder, not a file. Lock-and-send seals one "
            "file at a time — seal the files inside it one by one, "
            "or seal the whole folder as a backup set instead."
        )
    if not src.is_file():
        raise SealedSourceError(
            "That isn't a plain file, so Aegis can't seal it. "
            "Pick a file and try again."
        )
    filename = src.name
    if _format.windows_unsafe_segment(filename):
        raise SealedSourceError(
            "That file's name can't be used on Windows, so it "
            "can't be sealed for sending — it could never be "
            "opened there under that name. Rename the file and "
            "try again."
        )

    if destination is None:
        dest = src.parent / DEFAULT_SEALED_NAME
    else:
        dest = Path(destination)
        if dest.is_dir():
            dest = dest / DEFAULT_SEALED_NAME

    def _write(handle):
        with SealedWriter(
            handle, magic=SEND_MAGIC, password=password, params=params
        ) as writer:
            manifest = _inner_manifest(filename)
            writer.write(struct.pack(">I", len(manifest)))
            writer.write(manifest)
            try:
                with open(src, "rb") as inp:
                    while True:
                        block = inp.read(_STREAM_BYTES)
                        if not block:
                            break
                        writer.write(block)
            except OSError:
                raise SealedSourceError(
                    "Aegis couldn't read that file all the way "
                    "through, so nothing was sealed. Check the "
                    "file and try again."
                ) from None

    try:
        return write_new_file(dest, _write)
    except OSError:
        raise SealedSaveError() from None


def read_sealed_file(sealed_path, password: str):
    """Open a Lock-and-send file in memory: ``(filename, bytes)``.

    For small files and previews; :func:`open_sealed_file` is the
    streaming path that writes the file out.
    """
    raw = _read_file_bytes(sealed_path)
    with open_sealed(
        io.BytesIO(raw), magic=SEND_MAGIC, password=password
    ) as reader:
        filename = _read_inner_header(reader)
        return filename, reader.read()


def open_sealed_file(sealed_path, password: str, destination_dir=None) -> Path:
    """Open a Lock-and-send file and write its contents out.

    The file inside is written into ``destination_dir`` (default:
    the sealed file's own folder) under its original name. If a
    file with that name is already there, the refusal comes before
    anything is written — opening never overwrites.
    """
    src = Path(sealed_path)
    dest_dir = (
        Path(destination_dir) if destination_dir is not None else src.parent
    )
    if not dest_dir.is_dir():
        raise SealedSaveError(
            "That folder isn't there. Pick a folder that exists "
            "and try again."
        )
    try:
        handle = open(src, "rb")
    except OSError:
        raise SealedFormatError(
            "Aegis couldn't open that file. It may have moved, or "
            "this computer can't read it right now."
        ) from None
    with handle:
        with open_sealed(handle, magic=SEND_MAGIC, password=password) as reader:
            filename = _read_inner_header(reader)
            target = dest_dir / filename
            if os.path.lexists(target):
                raise SealedExistsError(
                    "There's already a file called \"%s\" there. "
                    "Move it, rename it, or open this into a "
                    "different folder." % filename
                )

            def _write(out):
                while True:
                    block = reader.read(_STREAM_BYTES)
                    if not block:
                        break
                    out.write(block)

            return write_new_file(target, _write)


def _read_file_bytes(path) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError:
        raise SealedFormatError(
            "Aegis couldn't open that file. It may have moved, or "
            "this computer can't read it right now."
        ) from None
