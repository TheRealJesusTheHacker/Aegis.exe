"""Standalone sealed files: the construction behind Phase 3's
Lock-and-send and Lazarus's armor.

This is *not* a second cryptography. It is the Phase 1 construction
(the one in :mod:`aegis.format` and :mod:`aegis.kdf`) re-shaped for
a single file with a single password:

- Argon2id turns the password into a key-encryption key, with the
  parameters stored in the file's header and validated — floors and
  ceilings — before any derivation runs, exactly as a vault's are.
  A header edited down can only ever produce a refusal.
- A fresh random 256-bit file key does the sealing; it never
  touches disk except wrapped by the derived key under an
  authenticated context binding the magic, the format version, the
  KDF parameters, and the salt.
- The contents are sealed in 1 MiB AES-256-GCM chunks, each bound
  to the file's random id and to the wrapped key, so a payload
  spliced under a different header — even one made with the same
  password — fails every tag and is refused.

What differs from a vault, deliberately:

- **Each product has its own magic.** A vault (``AEGISVLT``), a
  Lock-and-send file (``AEGISSND``), and an armored backup set
  (``AEGISARM``) are three different doors, and none of them opens
  another's files: each reader checks its own magic before it
  checks anything else. There is no generic "open any Aegis file"
  path anywhere.
- **There is no recovery key.** A standalone sealed file has one
  password and nothing else — the person who seals a file for
  sending chooses a password for that file, and the password is the
  whole lock. (A vault's recovery story lives in the vault.)
- **Sealing and opening stream.** A sealed file can be far larger
  than memory, so the writer and reader here move chunk by chunk
  instead of the vault's whole-bundle shape.

The header carries no file name, no sizes, and nothing about the
contents; what a file is called and what is inside it live in the
sealed contents themselves, written by the modules above this one
(:mod:`aegis.locksend`, :mod:`aegis.armor`).

A note on memory hygiene, matching the vault's honesty: the file
key and the derived key are held as ``bytearray`` and zeroed when
the writer or reader is done with them. Copies the runtime and the
vetted libraries make on their own are beyond reach, as everywhere
in Aegis; the full memory review is Phase 5's gate.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import os
import secrets
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import format as _format
from .errors import (
    SealedExistsError,
    SealedFormatError,
    SealedSaveError,
    SealedTamperedError,
    VaultFormatError,
    WeakPasswordError,
    WrongFilePasswordError,
)
from .kdf import DEFAULT_PARAMS, KdfParams, derive_key, validate_params
from .passwords import MIN_PASSWORD_LENGTH

__all__ = [
    "SEND_MAGIC",
    "ARMOR_MAGIC",
    "SEALED_FORMAT_VERSION",
    "SealedHeader",
    "SealedWriter",
    "SealedReader",
    "open_sealed",
    "seal_all",
    "open_all",
    "write_new_file",
]

#: The three Aegis doors. The vault's magic (``AEGISVLT``) lives in
#: :mod:`aegis.format`; these two are Phase 3's standalone files.
SEND_MAGIC = b"AEGISSND"
ARMOR_MAGIC = b"AEGISARM"

SEALED_FORMAT_VERSION = 1

_FILE_KEY_BYTES = 32
_SALT_BYTES = 16
_FILE_ID_BYTES = 16
_PREFIX_LEN = 8 + 2 + 4  # magic || version || header_len

_NEWER_MESSAGE = (
    "This file was sealed by a newer version of Aegis, and this "
    "copy can't open it. Update Aegis and try again."
)

# When a file from one Aegis door is brought to another, the refusal
# can at least name the right door, in plain language.
_WRONG_DOOR_MESSAGES = {
    _format.MAGIC: (
        "That's an Aegis vault, not this kind of file. "
        "Open it as a vault instead."
    ),
    SEND_MAGIC: (
        "That's a sealed file made for sending, not this kind of "
        "file. Open it as a sealed file instead."
    ),
    ARMOR_MAGIC: (
        "That's a sealed backup set, not this kind of file. "
        "Open it as a backup set instead."
    ),
}


def _zero(buf) -> None:
    if buf is not None:
        for i in range(len(buf)):
            buf[i] = 0


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(bytes(raw)).decode("ascii")


def _b64decode_field(value, expected_len):
    if not isinstance(value, str):
        raise SealedFormatError()
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise SealedFormatError() from None
    if len(raw) != expected_len:
        raise SealedFormatError()
    return raw


def _canonical_kdf_json(kdf: KdfParams) -> bytes:
    """The canonical KDF bytes, mirroring the vault format's."""
    return json.dumps(
        {
            "memory_kib": kdf.memory_kib,
            "time_cost": kdf.time_cost,
            "parallelism": kdf.parallelism,
            "hash_len": kdf.hash_len,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _wrap_context(magic: bytes, kdf: KdfParams, salt: bytes) -> bytes:
    """The wrapped key's authenticated context for a standalone file.

    ``magic || version || canonical KDF JSON || salt`` — the same
    shape as the vault's per-credential contexts, with this file's
    own magic standing where the vault's stands.
    """
    return b"".join(
        [
            bytes(magic),
            struct.pack(">H", SEALED_FORMAT_VERSION),
            _canonical_kdf_json(kdf),
            bytes(salt),
        ]
    )


def _chunk_aad(
    magic: bytes,
    file_id: bytes,
    wrapped_key: bytes,
    chunk_size: int,
    nonce_prefix: bytes,
    index: int,
    is_final: bool,
) -> bytes:
    """The authenticated context for one payload chunk.

    Mirrors the vault's chunk context: the magic, the version, the
    file's random id, a hash of the wrapped key (so the contents
    are bound to this exact sealed header), the chunk size, the
    nonce prefix, the chunk index, and the final-chunk flag.
    """
    return b"".join(
        [
            bytes(magic),
            struct.pack(">H", SEALED_FORMAT_VERSION),
            bytes(file_id),
            hashlib.sha256(bytes(wrapped_key)).digest(),
            struct.pack(">Q", chunk_size),
            bytes(nonce_prefix),
            struct.pack(">Q", index),
            b"\x01" if is_final else b"\x00",
        ]
    )


@dataclass
class SealedHeader:
    """Everything in a standalone sealed file's header, validated."""

    magic: bytes
    kdf: KdfParams
    salt: bytes
    wrap_nonce: bytes
    wrapped_key: bytes
    file_id: bytes
    chunk_size: int = _format.CHUNK_SIZE
    nonce_prefix: bytes = b""


def _encode_header(header: SealedHeader) -> bytes:
    doc = {
        "format": SEALED_FORMAT_VERSION,
        "file_id": _b64encode(header.file_id),
        "kdf": {
            "memory_kib": header.kdf.memory_kib,
            "time_cost": header.kdf.time_cost,
            "parallelism": header.kdf.parallelism,
            "hash_len": header.kdf.hash_len,
        },
        "wrap": {
            "salt": _b64encode(header.salt),
            "nonce": _b64encode(header.wrap_nonce),
            "wrapped_key": _b64encode(header.wrapped_key),
        },
        "payload": {
            "chunk_size": header.chunk_size,
            "nonce_prefix": _b64encode(header.nonce_prefix),
        },
    }
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(raw) > _format.HEADER_MAX_BYTES:
        raise SealedFormatError()
    return raw


def _require_keys(obj, keys):
    if not isinstance(obj, dict) or set(obj.keys()) != set(keys):
        raise SealedFormatError()


def _parse_header_json(raw: bytes, magic: bytes) -> SealedHeader:
    if len(raw) > _format.HEADER_MAX_BYTES:
        raise SealedFormatError()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise SealedFormatError() from None
    try:
        doc = json.loads(
            text, object_pairs_hook=_format.reject_duplicate_keys
        )
    except VaultFormatError:
        # The duplicate-key hook raises the vault's format error;
        # at this door it is a sealed-file format error.
        raise SealedFormatError() from None
    except (ValueError, RecursionError, MemoryError):
        raise SealedFormatError() from None

    _require_keys(doc, ("format", "file_id", "kdf", "wrap", "payload"))
    if type(doc["format"]) is not int or doc["format"] != SEALED_FORMAT_VERSION:
        raise SealedFormatError()

    kdf_doc = doc["kdf"]
    _require_keys(kdf_doc, ("memory_kib", "time_cost", "parallelism", "hash_len"))
    for value in kdf_doc.values():
        if type(value) is not int:
            raise SealedFormatError()
    kdf = KdfParams(
        memory_kib=kdf_doc["memory_kib"],
        time_cost=kdf_doc["time_cost"],
        parallelism=kdf_doc["parallelism"],
        hash_len=kdf_doc["hash_len"],
    )
    # Floors and ceilings are enforced here, before any derivation.
    try:
        validate_params(kdf)
    except VaultFormatError:
        raise SealedFormatError() from None

    wrap = doc["wrap"]
    _require_keys(wrap, ("salt", "nonce", "wrapped_key"))
    payload = doc["payload"]
    _require_keys(payload, ("chunk_size", "nonce_prefix"))
    if (
        type(payload["chunk_size"]) is not int
        or not _format.MIN_CHUNK_SIZE
        <= payload["chunk_size"]
        <= (16 << 20)
    ):
        raise SealedFormatError()

    return SealedHeader(
        magic=bytes(magic),
        kdf=kdf,
        file_id=_b64decode_field(doc["file_id"], _FILE_ID_BYTES),
        salt=_b64decode_field(wrap["salt"], _SALT_BYTES),
        wrap_nonce=_b64decode_field(wrap["nonce"], _format.WRAP_NONCE_BYTES),
        wrapped_key=_b64decode_field(wrap["wrapped_key"], _format.WRAPPED_KEY_BYTES),
        chunk_size=payload["chunk_size"],
        nonce_prefix=_b64decode_field(
            payload["nonce_prefix"], _format.NONCE_PREFIX_BYTES
        ),
    )


def _parse_prefix(prefix: bytes, magic: bytes) -> int:
    """Validate a 14-byte prefix against ``magic``; return header_len."""
    if len(prefix) < _PREFIX_LEN:
        raise SealedFormatError()
    prefix = bytes(prefix)
    found = prefix[:8]
    if found != bytes(magic):
        message = _WRONG_DOOR_MESSAGES.get(found)
        if message is not None:
            raise SealedFormatError(message)
        raise SealedFormatError()
    (version,) = struct.unpack(">H", prefix[8:10])
    if version != SEALED_FORMAT_VERSION:
        if version > SEALED_FORMAT_VERSION:
            raise SealedFormatError(_NEWER_MESSAGE)
        raise SealedFormatError()
    (header_len,) = struct.unpack(">I", prefix[10:14])
    if header_len < 1 or header_len > _format.HEADER_MAX_BYTES:
        raise SealedFormatError()
    return header_len


def _secret_bytes(password) -> bytearray:
    if not isinstance(password, str):
        raise TypeError("A password must be text.")
    return bytearray(password.encode("utf-8"))


def _check_password(password) -> None:
    if not isinstance(password, str):
        raise TypeError("A password must be text.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError()


class SealedWriter:
    """Stream plaintext in, sealed bytes out.

    ``out`` is a binary file object. The header is written by the
    constructor; :meth:`write` takes plaintext of any size;
    :meth:`close` finishes the file. Use as a context manager, or
    call :meth:`close` exactly once.
    """

    def __init__(self, out, *, magic: bytes, password: str,
                 params: KdfParams = DEFAULT_PARAMS):
        _check_password(password)
        try:
            validate_params(params)
        except VaultFormatError:
            raise SealedFormatError() from None
        self._out = out
        self._magic = bytes(magic)
        self._closed = False
        self._buffer = bytearray()
        self._index = 0

        salt = secrets.token_bytes(_SALT_BYTES)
        file_id = secrets.token_bytes(_FILE_ID_BYTES)
        nonce_prefix = secrets.token_bytes(_format.NONCE_PREFIX_BYTES)
        self._file_key = bytearray(secrets.token_bytes(_FILE_KEY_BYTES))
        secret = _secret_bytes(password)
        try:
            kek = bytearray(derive_key(bytes(secret), salt, params))
        finally:
            _zero(secret)
        try:
            wrap_nonce = secrets.token_bytes(_format.WRAP_NONCE_BYTES)
            wrapped = AESGCM(bytes(kek)).encrypt(
                wrap_nonce,
                bytes(self._file_key),
                _wrap_context(self._magic, params, salt),
            )
        finally:
            _zero(kek)

        self._header = SealedHeader(
            magic=self._magic,
            kdf=params,
            salt=salt,
            wrap_nonce=wrap_nonce,
            wrapped_key=wrapped,
            file_id=file_id,
            chunk_size=_format.CHUNK_SIZE,
            nonce_prefix=nonce_prefix,
        )
        self._aes = AESGCM(bytes(self._file_key))
        header_json = _encode_header(self._header)
        out.write(
            b"".join(
                [
                    self._magic,
                    struct.pack(">H", SEALED_FORMAT_VERSION),
                    struct.pack(">I", len(header_json)),
                    header_json,
                ]
            )
        )

    @property
    def header(self) -> SealedHeader:
        return self._header

    def _emit(self, plain: bytes, *, is_final: bool) -> None:
        header = self._header
        try:
            nonce = _format.chunk_nonce(header.nonce_prefix, self._index)
        except VaultFormatError:
            raise SealedFormatError() from None
        aad = _chunk_aad(
            self._magic,
            header.file_id,
            header.wrapped_key,
            header.chunk_size,
            header.nonce_prefix,
            self._index,
            is_final,
        )
        self._out.write(self._aes.encrypt(nonce, bytes(plain), aad))
        self._index += 1

    def write(self, data) -> int:
        """Seal ``data`` (bytes-like), emitting full chunks as they fill."""
        if self._closed:
            raise ValueError("This sealed file is already finished.")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("Only bytes can be sealed.")
        self._buffer += bytes(data)
        chunk_size = self._header.chunk_size
        # A chunk may only be called non-final once at least one
        # more byte is known to follow it, so a full chunk is held
        # until the buffer grows past it (or close() ends the file).
        while len(self._buffer) > chunk_size:
            self._emit(bytes(self._buffer[:chunk_size]), is_final=False)
            del self._buffer[:chunk_size]
        return len(data)

    def close(self) -> None:
        """Emit the final chunk and wipe the file key."""
        if self._closed:
            return
        self._closed = True
        try:
            self._emit(bytes(self._buffer), is_final=True)
            self._buffer = bytearray()
            flush = getattr(self._out, "flush", None)
            if flush is not None:
                flush()
        finally:
            _zero(self._file_key)

    def __enter__(self) -> "SealedWriter":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False


class SealedReader:
    """Stream a sealed file back to plaintext, verifying as it goes.

    Construct through :func:`open_sealed`, which reads and checks
    the header and unwraps the file key. :meth:`read` returns
    plaintext; a chunk that fails its check raises
    :class:`SealedTamperedError` — nothing past a failed chunk is
    ever handed out, and the failure sticks: every later read
    raises it again.
    """

    def __init__(self, inp, header: SealedHeader, file_key: bytearray):
        self._inp = inp
        self._header = header
        self._file_key = file_key
        self._aes = AESGCM(bytes(file_key))
        self._cipher_buf = bytearray()
        self._plain = bytearray()
        self._src_eof = False
        self._finished = False
        self._chunks = 0
        self._failed = None
        self._closed = False

    @property
    def header(self) -> SealedHeader:
        return self._header

    def _pull_chunk(self) -> None:
        header = self._header
        step = header.chunk_size + _format.GCM_TAG_BYTES
        while len(self._cipher_buf) <= step and not self._src_eof:
            data = self._inp.read(step + 1 - len(self._cipher_buf))
            if data:
                self._cipher_buf += data
            else:
                self._src_eof = True
        if len(self._cipher_buf) > step:
            ct = bytes(self._cipher_buf[:step])
            del self._cipher_buf[:step]
            is_final = False
        elif self._src_eof:
            if not self._cipher_buf:
                # The stream ended with no final chunk: it was cut
                # short (or never had a payload at all).
                raise SealedTamperedError()
            ct = bytes(self._cipher_buf)
            self._cipher_buf = bytearray()
            if len(ct) < _format.GCM_TAG_BYTES or len(ct) > step:
                raise SealedTamperedError()
            is_final = True
            self._finished = True
        else:  # pragma: no cover - the fill loop guarantees one branch
            return
        nonce = _format.chunk_nonce(header.nonce_prefix, self._chunks)
        aad = _chunk_aad(
            header.magic,
            header.file_id,
            header.wrapped_key,
            header.chunk_size,
            header.nonce_prefix,
            self._chunks,
            is_final,
        )
        try:
            plain = self._aes.decrypt(nonce, ct, aad)
        except InvalidTag:
            raise SealedTamperedError() from None
        if not is_final and len(plain) != header.chunk_size:
            raise SealedTamperedError()
        self._plain += plain
        self._chunks += 1

    def read(self, size: int = -1) -> bytes:
        """Return up to ``size`` plaintext bytes (all of them if -1).

        Returns ``b""`` only at the true end of the sealed contents,
        after the final chunk has verified.
        """
        if self._failed is not None:
            raise self._failed
        try:
            if size is None or size < 0:
                while not self._finished:
                    self._pull_chunk()
                out = bytes(self._plain)
                self._plain = bytearray()
                return out
            if size == 0:
                return b""
            while len(self._plain) < size and not self._finished:
                self._pull_chunk()
            out = bytes(self._plain[:size])
            del self._plain[:size]
            return out
        except SealedTamperedError as exc:
            self._failed = exc
            raise

    def read_exact(self, size: int) -> bytes:
        """Return exactly ``size`` bytes, or raise SealedTamperedError.

        For readers of the structured contents (a length, then a
        document of that length): a stream that ends early has been
        cut, and that is reported as damage, never as a short read.
        """
        data = self.read(size)
        if len(data) != size:
            raise SealedTamperedError()
        return data

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            _zero(self._file_key)

    def __enter__(self) -> "SealedReader":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False


def open_sealed(inp, *, magic: bytes, password: str) -> SealedReader:
    """Open a sealed stream: check its header, unwrap its file key.

    ``inp`` is a binary file object positioned at the start of the
    sealed file. A wrong password raises
    :class:`WrongFilePasswordError`; a file that is not this kind
    of sealed file raises :class:`SealedFormatError` — checked from
    its first bytes, before any derivation runs.
    """
    if not isinstance(password, str):
        raise TypeError("A password must be text.")
    prefix = inp.read(_PREFIX_LEN)
    if len(prefix) < _PREFIX_LEN:
        raise SealedFormatError()
    header_len = _parse_prefix(prefix, magic)
    header_json = inp.read(header_len)
    if len(header_json) < header_len:
        raise SealedFormatError()
    header = _parse_header_json(header_json, magic)

    secret = _secret_bytes(password)
    try:
        kek = bytearray(derive_key(bytes(secret), header.salt, header.kdf))
    finally:
        _zero(secret)
    try:
        try:
            plain = AESGCM(bytes(kek)).decrypt(
                header.wrap_nonce,
                header.wrapped_key,
                _wrap_context(header.magic, header.kdf, header.salt),
            )
        except InvalidTag:
            raise WrongFilePasswordError() from None
    finally:
        _zero(kek)
    return SealedReader(inp, header, bytearray(plain))


def seal_all(data: bytes, *, magic: bytes, password: str,
             params: KdfParams = DEFAULT_PARAMS) -> bytes:
    """Seal ``data`` in memory and return the whole sealed file."""
    out = io.BytesIO()
    with SealedWriter(out, magic=magic, password=password, params=params) as writer:
        writer.write(data)
    return out.getvalue()


def open_all(raw: bytes, *, magic: bytes, password: str) -> bytes:
    """Open a whole in-memory sealed file and return its contents."""
    with open_sealed(io.BytesIO(bytes(raw)), magic=magic, password=password) as reader:
        return reader.read()


def write_new_file(destination, write_fn) -> Path:
    """Write a brand-new file at ``destination``, refusing to overwrite.

    ``write_fn`` is called with the open binary handle of a
    temporary file beside the destination; when it returns, the
    file is flushed, synced, and linked into place — so a
    half-written file can never sit at the destination looking
    whole, and something already at the destination is never
    replaced. Mirrors the vault's and the sealed export's publish
    discipline.
    """
    dest = Path(destination)
    if os.path.lexists(dest):
        raise SealedExistsError()
    directory = str(dest.parent) if str(dest.parent) else "."
    fd, tmp_name = tempfile.mkstemp(
        dir=directory, prefix=dest.name + ".", suffix=".tmp"
    )
    published = False
    try:
        with os.fdopen(fd, "wb") as handle:
            write_fn(handle)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(tmp_name, dest)
        except FileExistsError:
            raise SealedExistsError() from None
        except OSError:
            raise SealedSaveError() from None
        published = True
    except SealedExistsError:
        raise
    except OSError:
        raise SealedSaveError() from None
    finally:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
    if published:
        _fsync_directory(directory)
    return dest


def _fsync_directory(directory: str) -> None:
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        try:
            os.close(dir_fd)
        except OSError:
            pass
