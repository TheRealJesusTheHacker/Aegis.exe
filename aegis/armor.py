"""Lazarus's armor: a whole folder, sealed as one armored set.

Aegis seals a completed backup set — above all a Lazarus snapshot
store — into a single sealed file (``.aegis-armored``), so a backup
drive that is lost or stolen is an inconvenience, not a privacy
disaster. Unsealing gives the folder back, byte for byte.

The boundary between the two tools is the design, stated in the
roadmap and kept here: **the store is sealed and unsealed as a
whole, at the boundary, by Aegis.** This module knows nothing about
what is inside the folder — no Lazarus layout, no snapshot format —
and Lazarus knows nothing about this one. Either tool's insides can
change without the other noticing.

The construction is the standalone sealed-file construction in
:mod:`aegis.sealed`, under armor's own magic. Inside the seal, the
contents are: a manifest (every folder, and every file's place,
size, and SHA-256 check value), then the files' bytes in manifest
order. Unsealing checks each file against its recorded check value
as it is written, so damage is pinned to the file that carries it —
and unsealing writes into a holding place first: the destination
folder only appears once the whole set has checked out. A set that
fails partway leaves nothing behind.

Rules kept from hard lessons elsewhere in the kit:

- **Sealing never follows links.** A folder holding a link (or
  anything that isn't a plain file or folder) is refused, in plain
  language, before anything is sealed: a link's target is outside
  the folder the person pointed at, and sealing it would smuggle
  in whatever it points to.
- **Unsealing is confined.** Manifest paths are validated on the
  way in — no absolute paths, no ``..`` steps, no backslashes, no
  duplicates even under different capitalization — and every file
  being written is checked to land inside the destination. A
  crafted set cannot put a byte outside it.
- Sealing reads each file twice: once to record its check value
  for the manifest, once to seal it. If a file changes between
  those reads, its sealed bytes won't match the manifest and the
  set will refuse to unseal — the safe direction to fail.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import format as _format
from .errors import (
    ArmorRefusalError,
    SealedExistsError,
    SealedFormatError,
    SealedSaveError,
    SealedTamperedError,
    VaultLockedError,
)
from .kdf import DEFAULT_PARAMS, KdfParams
from .publish import rename_with_retry
from .sealed import (
    ARMOR_MAGIC,
    SealedWriter,
    _fsync_directory,
    open_sealed,
    write_new_file,
)

__all__ = [
    "ARMOR_SUFFIX",
    "ARMOR_PASSWORD_NOTE",
    "ArmorFileInfo",
    "ArmorManifest",
    "seal_tree",
    "armor_manifest",
    "unseal_tree",
]

#: The suffix every armored backup set carries.
ARMOR_SUFFIX = ".aegis-armored"

#: Shown where a person sets the password for a backup set.
ARMOR_PASSWORD_NOTE = (
    "The password is the whole lock on this backup set. Without "
    "it, the set can't be opened — not by Sentinel, not by "
    "anyone. Write it down and keep it somewhere safe, apart from "
    "the set itself."
)

_MANIFEST_VERSION = 1
# The manifest is a list of names and check values; 64 MB of it
# describes more files than a backup set reasonably holds.
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_MAX_PATH_CHARS = 1024
_STREAM_BYTES = 1 << 20


@dataclass(frozen=True)
class ArmorFileInfo:
    """One file in an armored set: its place, size, and check value."""

    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class ArmorManifest:
    """What an armored set holds, without opening it out."""

    created_utc: str
    dirs: tuple
    files: tuple

    @property
    def total_bytes(self) -> int:
        return sum(info.size for info in self.files)


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


# -- sealing --------------------------------------------------------------------


def _scan_tree(root: Path):
    """Walk ``root`` into (dirs, files) with '/'-separated places.

    Both lists are sorted for a deterministic manifest. Anything
    that is not a plain file or folder — a link above all — is a
    plain-language refusal.
    """
    dirs = []
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        current = Path(dirpath)
        for name in dirnames:
            if _format.windows_unsafe_segment(name):
                rel = (current / name).relative_to(root).as_posix()
                raise ArmorRefusalError(
                    "Aegis found a name Windows can't use (at "
                    "\"%s\") and can't seal it — a set sealed with "
                    "it could never be opened there. Rename it "
                    "and try again." % rel
                )
            if (current / name).is_symlink():
                rel = (current / name).relative_to(root).as_posix()
                raise ArmorRefusalError(
                    "Aegis found a link in the folder (at \"%s\") "
                    "and can't seal links — a link points outside "
                    "the folder you chose. Replace it with the real "
                    "folder, or take it out, and try again." % rel
                )
        if current != root:
            dirs.append(current.relative_to(root).as_posix())
        for name in filenames:
            path = current / name
            rel = path.relative_to(root).as_posix()
            if _format.windows_unsafe_segment(name):
                raise ArmorRefusalError(
                    "Aegis found a name Windows can't use (at "
                    "\"%s\") and can't seal it — a set sealed with "
                    "it could never be opened there. Rename it "
                    "and try again." % rel
                )
            if path.is_symlink():
                raise ArmorRefusalError(
                    "Aegis found a link in the folder (at \"%s\") "
                    "and can't seal links — a link points outside "
                    "the folder you chose. Replace it with the real "
                    "file, or take it out, and try again." % rel
                )
            if not path.is_file():
                raise ArmorRefusalError(
                    "Aegis found something in the folder (at "
                    "\"%s\") that isn't a plain file, and can't "
                    "seal it. Take it out and try again." % rel
                )
            files.append((rel, path))
    return dirs, files


def _hash_file(path: Path, rel: str) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while True:
                block = handle.read(_STREAM_BYTES)
                if not block:
                    break
                digest.update(block)
    except OSError:
        raise ArmorRefusalError(
            "Aegis couldn't read \"%s\" all the way through, so "
            "nothing was sealed. Check the folder and try again."
            % rel
        ) from None
    return digest.hexdigest()


def seal_tree(source_dir, password: str, destination=None, *,
              params: KdfParams = DEFAULT_PARAMS) -> Path:
    """Seal the folder at ``source_dir`` whole; return the set's path.

    The set is written beside the folder as ``<folder>.aegis-armored``
    (or at ``destination``, which may be a folder to write into).
    It is never written inside the folder being sealed, and nothing
    already at the destination is ever overwritten.
    """
    root = Path(source_dir)
    if root.is_symlink():
        raise ArmorRefusalError(
            "That folder is a link to somewhere else. "
            "Seal the real folder instead."
        )
    if not root.is_dir():
        raise ArmorRefusalError(
            "That isn't a folder Aegis can seal. "
            "Pick a folder and try again."
        )
    root = root.resolve()

    if destination is None:
        dest = root.parent / (root.name + ARMOR_SUFFIX)
    else:
        dest = Path(destination)
        if dest.is_dir():
            dest = dest / (root.name + ARMOR_SUFFIX)
    dest_abs = Path(os.path.abspath(dest))
    if dest_abs == root or root in dest_abs.parents:
        raise ArmorRefusalError(
            "The sealed set can't be written inside the folder "
            "being sealed. Pick a place outside it."
        )

    dirs, files = _scan_tree(root)
    infos = []
    for rel, path in files:
        try:
            size = path.stat().st_size
        except OSError:
            raise ArmorRefusalError(
                "Aegis couldn't read \"%s\", so nothing was "
                "sealed. Check the folder and try again." % rel
            ) from None
        infos.append(
            ArmorFileInfo(path=rel, size=size, sha256=_hash_file(path, rel))
        )
    manifest = ArmorManifest(created_utc=_now_utc(), dirs=tuple(dirs),
                             files=tuple(infos))
    manifest_raw = _encode_manifest(manifest)
    if len(manifest_raw) > _MAX_MANIFEST_BYTES:
        raise ArmorRefusalError(
            "That folder holds more files than one sealed set can "
            "list. Split it into smaller sets and seal each one."
        )
    by_rel = {rel: path for rel, path in files}

    def _write(handle):
        with SealedWriter(
            handle, magic=ARMOR_MAGIC, password=password, params=params
        ) as writer:
            writer.write(struct.pack(">I", len(manifest_raw)))
            writer.write(manifest_raw)
            for info in manifest.files:
                _stream_file(writer, by_rel[info.path], info.path)

    return write_new_file(dest, _write)


def _stream_file(writer, path: Path, rel: str) -> None:
    try:
        with open(path, "rb") as handle:
            while True:
                block = handle.read(_STREAM_BYTES)
                if not block:
                    break
                writer.write(block)
    except OSError:
        raise ArmorRefusalError(
            "Aegis couldn't read \"%s\" all the way through, so "
            "nothing was sealed. Check the folder and try again."
            % rel
        ) from None


def _encode_manifest(manifest: ArmorManifest) -> bytes:
    doc = {
        "version": _MANIFEST_VERSION,
        "created_utc": manifest.created_utc,
        "dirs": list(manifest.dirs),
        "files": [
            {"path": f.path, "size": f.size, "sha256": f.sha256}
            for f in manifest.files
        ],
    }
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# -- reading the manifest ---------------------------------------------------------


def _validate_rel_path(path) -> str:
    """Confine one manifest path to a plain relative place."""
    if not isinstance(path, str):
        raise SealedTamperedError()
    if not 1 <= len(path) <= _MAX_PATH_CHARS:
        raise SealedTamperedError()
    if "\\" in path or "\x00" in path or path.startswith("/"):
        raise SealedTamperedError()
    for segment in path.split("/"):
        if segment in ("", ".", ".."):
            raise SealedTamperedError()
        if _format.windows_unsafe_segment(segment):
            raise SealedTamperedError()
    return path


def _parse_manifest(raw: bytes) -> ArmorManifest:
    """Parse and fully validate a manifest from the sealed contents."""
    try:
        doc = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_format.reject_duplicate_keys,
        )
    except Exception:
        raise SealedTamperedError() from None
    if not isinstance(doc, dict) or set(doc.keys()) != {
        "version", "created_utc", "dirs", "files",
    }:
        raise SealedTamperedError()
    version = doc["version"]
    if type(version) is not int or version != _MANIFEST_VERSION:
        raise SealedTamperedError()
    if not isinstance(doc["created_utc"], str):
        raise SealedTamperedError()
    if not isinstance(doc["dirs"], list) or not isinstance(doc["files"], list):
        raise SealedTamperedError()

    dirs = tuple(_validate_rel_path(p) for p in doc["dirs"])
    files = []
    for item in doc["files"]:
        if not isinstance(item, dict) or set(item.keys()) != {
            "path", "size", "sha256",
        }:
            raise SealedTamperedError()
        path = _validate_rel_path(item["path"])
        size = item["size"]
        if type(size) is not int or size < 0:
            raise SealedTamperedError()
        sha = item["sha256"]
        if (
            not isinstance(sha, str)
            or len(sha) != 64
            or any(c not in "0123456789abcdef" for c in sha)
        ):
            raise SealedTamperedError()
        files.append(ArmorFileInfo(path=path, size=size, sha256=sha))

    # No place may be named twice — not even under different
    # capitalization, because the drives Aegis runs on treat those
    # as the same place — and no file may stand where another
    # file's folder needs to be.
    seen = set()
    for path in list(dirs) + [f.path for f in files]:
        folded = path.casefold()
        if folded in seen:
            raise SealedTamperedError()
        seen.add(folded)
    file_paths = {f.path for f in files}
    for path in list(dirs) + [f.path for f in files]:
        parts = path.split("/")
        for cut in range(1, len(parts)):
            if "/".join(parts[:cut]) in file_paths:
                raise SealedTamperedError()
    return ArmorManifest(
        created_utc=doc["created_utc"], dirs=dirs, files=tuple(files)
    )


def _read_manifest(reader) -> ArmorManifest:
    (length,) = struct.unpack(">I", reader.read_exact(4))
    if length < 1 or length > _MAX_MANIFEST_BYTES:
        raise SealedTamperedError()
    return _parse_manifest(reader.read_exact(length))


def _open_armor(sealed_path, password: str):
    src = Path(sealed_path)
    try:
        handle = open(src, "rb")
    except OSError:
        raise SealedFormatError(
            "Aegis couldn't open that file. It may have moved, or "
            "this computer can't read it right now."
        ) from None
    try:
        reader = open_sealed(handle, magic=ARMOR_MAGIC, password=password)
    except BaseException:
        handle.close()
        raise
    return handle, reader


def armor_manifest(sealed_path, password: str) -> ArmorManifest:
    """List what an armored set holds, without opening it out."""
    handle, reader = _open_armor(sealed_path, password)
    with handle, reader:
        return _read_manifest(reader)


# -- unsealing --------------------------------------------------------------------


def unseal_tree(sealed_path, password: str, destination, *, place_guard=None) -> Path:
    """Open an armored set back into a folder; return its path.

    ``destination`` must not exist: unsealing never overwrites and
    never merges. The folder is built in a holding place beside the
    destination and moved into place only after every file has
    checked out — a set that fails partway leaves nothing behind.
    """
    dest = Path(destination)
    if _format.windows_unsafe_segment(dest.name):
        raise SealedSaveError(
            "That name can't be used for a folder on Windows. "
            "Pick a different name and try again."
        )
    if os.path.lexists(dest):
        raise SealedExistsError()
    parent = dest.parent if str(dest.parent) else Path(".")
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        raise SealedSaveError() from None

    handle, reader = _open_armor(sealed_path, password)
    staging = None
    try:
        with handle, reader:
            manifest = _read_manifest(reader)
            staging = Path(
                tempfile.mkdtemp(dir=str(parent), prefix=dest.name + ".unsealing-")
            )
            staging_root = os.path.realpath(staging)
            for rel in manifest.dirs:
                target = _confined_target(staging, staging_root, rel)
                target.mkdir(parents=True, exist_ok=True)
            for info in manifest.files:
                target = _confined_target(staging, staging_root, info.path)
                target.parent.mkdir(parents=True, exist_ok=True)
                _unseal_one(reader, target, info)
            if reader.read(1):
                # Anything past the last file was not part of the set.
                raise SealedTamperedError()
        # The destination was free when we started; check once
        # more before the move, and never let a raw system error
        # escape the move itself.
        if place_guard is not None and not place_guard():
            # The caller withdrew permission while the work ran
            # (the app locked). The set is fully built in staging
            # and the finally below removes it — nothing is placed.
            raise VaultLockedError()
        if os.path.lexists(dest):
            raise SealedExistsError()
        try:
            rename_with_retry(staging, dest)
        except OSError:
            raise SealedSaveError() from None
        staging = None
        _fsync_directory(str(parent))
        return dest
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


def _confined_target(staging: Path, staging_root: str, rel: str) -> Path:
    """The place ``rel`` lands, proven to be inside the staging folder."""
    target = staging / rel
    resolved_parent = os.path.realpath(target.parent)
    if resolved_parent != staging_root and not resolved_parent.startswith(
        staging_root + os.sep
    ):
        raise SealedTamperedError()
    return target


def _unseal_one(reader, target: Path, info: ArmorFileInfo) -> None:
    digest = hashlib.sha256()
    remaining = info.size
    try:
        out = open(target, "wb")
    except OSError:
        raise SealedSaveError() from None
    with out:
        while remaining > 0:
            block = reader.read(min(_STREAM_BYTES, remaining))
            if not block:
                # The sealed contents ended before this file did.
                raise SealedTamperedError()
            digest.update(block)
            try:
                out.write(block)
            except OSError:
                raise SealedSaveError() from None
            remaining -= len(block)
    if digest.hexdigest() != info.sha256:
        raise SealedTamperedError(
            "This sealed set doesn't check out — \"%s\" doesn't "
            "match what was sealed, so Aegis stopped. Nothing was "
            "put in place." % info.path
        )
