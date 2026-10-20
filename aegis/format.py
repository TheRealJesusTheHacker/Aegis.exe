"""The Aegis vault file format (version 1).

Layout of a sealed ``.aegis`` file::

    MAGIC (8 bytes, "AEGISVLT")
    || format_version (uint16, big-endian, = 1)
    || header_len (uint32, big-endian)
    || header JSON (UTF-8, ``header_len`` bytes)
    || payload chunks (concatenated)

The header JSON carries a random vault id, the KDF parameters, one
wrapped copy of the vault key for the password and one for the
recovery key, and the payload's chunking details::

    {
      "format": 1,
      "vault_id": b64(16 random bytes, fixed for the vault's life),
      "kdf": {"memory_kib": ..., "time_cost": ...,
              "parallelism": ..., "hash_len": ...},
      "password_wrap": {"salt": b64, "nonce": b64, "wrapped_key": b64},
      "recovery_wrap": {"salt": b64, "nonce": b64, "wrapped_key": b64},
      "payload": {"chunk_size": ..., "nonce_prefix": b64}
    }

Authenticated-data design:

- Each credential path has its *own* wrap context:
  ``wrap_context_password`` is the magic, the format version, the
  canonical KDF parameters, and the *password* salt only;
  ``wrap_context_recovery`` is the same shape with the *recovery*
  salt only. Neither the other path's salt nor ``chunk_size`` is in
  either wrap context. That is what lets a credential change rotate
  its own salt and re-wrap its own path without stranding the other
  path (a session holds only one credential, so it could never
  rebuild the other wrap), and it keeps payload-layout parameters
  from holding the credential wraps hostage.
- The payload ``nonce_prefix`` stays out of the wrap AAD for the
  same reason as before: every seal picks a fresh prefix, and a
  session that re-seals a vault no longer holds the password needed
  to re-wrap, so the prefix must be free to change without touching
  the wraps.
- Chunk ``i`` uses nonce ``nonce_prefix (8B) || i (4B BE)`` and AAD
  ``MAGIC || version || vault_id || wrap_set_hash ||
  chunk_size (8B BE) || nonce_prefix || i (8B BE) || final-flag``,
  where ``wrap_set_hash`` is SHA-256 over the two wrapped-key byte
  strings (password first, then recovery). The vault id — random,
  generated at creation, immutable — names this vault across
  credential generations, while the wrap-set hash binds the payload
  to the *current* credential generation: after any credential
  rotation and re-seal, an older payload spliced under the new
  header fails every chunk tag and is refused.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import struct
from dataclasses import dataclass

from .errors import VaultFormatError
from .kdf import KdfParams, validate_params

__all__ = [
    "MAGIC",
    "FORMAT_VERSION",
    "HEADER_MAX_BYTES",
    "CHUNK_SIZE",
    "NONCE_PREFIX_BYTES",
    "WRAP_NONCE_BYTES",
    "WRAPPED_KEY_BYTES",
    "Header",
    "encode_header",
    "decode_header",
    "encode_file_prefix",
    "parse_file_prefix",
    "parse_prefix",
    "wrap_context_password",
    "wrap_context_recovery",
    "wrap_set_hash",
    "chunk_aad",
    "chunk_nonce",
    "split_chunks",
    "join_chunks",
    "reject_duplicate_keys",
    "VAULT_ID_BYTES",
    "MIN_CHUNK_SIZE",
]

MAGIC = b"AEGISVLT"
FORMAT_VERSION = 1
HEADER_MAX_BYTES = 65536
CHUNK_SIZE = 1 << 20

NONCE_PREFIX_BYTES = 8
WRAP_NONCE_BYTES = 12
WRAPPED_KEY_BYTES = 48  # 32-byte vault key + 16-byte GCM tag
GCM_TAG_BYTES = 16
SALT_BYTES = 16
VAULT_ID_BYTES = 16

_PREFIX_LEN = len(MAGIC) + 2 + 4  # magic || version || header_len
PREFIX_LEN = _PREFIX_LEN

MIN_CHUNK_SIZE = 65536
_MAX_CHUNK_SIZE = 16 << 20


@dataclass
class Header:
    """Everything in a vault header, decoded and validated."""

    kdf: KdfParams
    password_salt: bytes
    password_nonce: bytes
    password_wrapped_key: bytes
    recovery_salt: bytes
    recovery_nonce: bytes
    recovery_wrapped_key: bytes
    chunk_size: int = CHUNK_SIZE
    nonce_prefix: bytes = b""
    format_version: int = FORMAT_VERSION
    vault_id: bytes = b""


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(bytes(raw)).decode("ascii")


def _b64decode_field(value, expected_len=None):
    if not isinstance(value, str):
        raise VaultFormatError()
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise VaultFormatError() from None
    if expected_len is not None and len(raw) != expected_len:
        raise VaultFormatError()
    if len(raw) < 1 and expected_len is None:
        raise VaultFormatError()
    return raw


def _canonical_kdf_json(kdf: KdfParams) -> bytes:
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


def _coerce_header(header, fields):
    """Return ``header``, or build one from keyword fields."""
    if header is not None:
        return header
    try:
        return Header(
            kdf=fields["kdf"],
            password_salt=fields.get("password_salt", b"\x00" * SALT_BYTES),
            password_nonce=fields.get(
                "password_nonce", b"\x00" * WRAP_NONCE_BYTES
            ),
            password_wrapped_key=fields.get(
                "password_wrapped_key", b"\x00" * WRAPPED_KEY_BYTES
            ),
            recovery_salt=fields.get("recovery_salt", b"\x00" * SALT_BYTES),
            recovery_nonce=fields.get(
                "recovery_nonce", b"\x00" * WRAP_NONCE_BYTES
            ),
            recovery_wrapped_key=fields.get(
                "recovery_wrapped_key", b"\x00" * WRAPPED_KEY_BYTES
            ),
            chunk_size=fields.get("chunk_size", CHUNK_SIZE),
            nonce_prefix=fields.get(
                "nonce_prefix", b"\x00" * NONCE_PREFIX_BYTES
            ),
            format_version=fields.get("format_version", FORMAT_VERSION),
            vault_id=fields.get("vault_id", b"\x00" * VAULT_ID_BYTES),
        )
    except KeyError:
        raise TypeError(
            "wrap contexts need a Header or at least a kdf field"
        ) from None


def wrap_context_password(header: Header = None, **fields) -> bytes:
    """Build the password path's wrap AAD context.

    ``MAGIC || version (2B BE) || canonical KDF JSON || password
    salt`` — the recovery salt, ``chunk_size``, and the payload
    ``nonce_prefix`` are deliberately absent.
    """
    header = _coerce_header(header, fields)
    return b"".join(
        [
            MAGIC,
            struct.pack(">H", header.format_version),
            _canonical_kdf_json(header.kdf),
            bytes(header.password_salt),
        ]
    )


def wrap_context_recovery(header: Header = None, **fields) -> bytes:
    """Build the recovery path's wrap AAD context.

    ``MAGIC || version (2B BE) || canonical KDF JSON || recovery
    salt`` — the password salt, ``chunk_size``, and the payload
    ``nonce_prefix`` are deliberately absent.
    """
    header = _coerce_header(header, fields)
    return b"".join(
        [
            MAGIC,
            struct.pack(">H", header.format_version),
            _canonical_kdf_json(header.kdf),
            bytes(header.recovery_salt),
        ]
    )


def wrap_set_hash(header: Header) -> bytes:
    """SHA-256 over both wrapped-key byte strings (password first).

    This is the credential-generation binding used in chunk AAD:
    any re-wrap of either path changes it, so a payload sealed
    under an older wrap set fails authentication under a header
    carrying a newer one.
    """
    return hashlib.sha256(
        bytes(header.password_wrapped_key)
        + bytes(header.recovery_wrapped_key)
    ).digest()


def chunk_aad(
    header: Header, nonce_prefix: bytes, index: int, is_final: bool
) -> bytes:
    """Build the AAD for payload chunk ``index``.

    ``header`` must be a :class:`Header`; the AAD is
    ``MAGIC || version || vault_id || wrap_set_hash ||
    chunk_size (8B BE) || nonce_prefix || index (8B BE) ||
    final-flag``. There is no raw-bytes fallback: the Header-based
    construction is the only layout, so no caller can silently lose
    the vault-id / wrap-set binding.
    """
    if not isinstance(header, Header):
        raise TypeError("chunk_aad needs a Header.")
    prefix = b"".join(
        [
            MAGIC,
            struct.pack(">H", header.format_version),
            bytes(header.vault_id),
            wrap_set_hash(header),
            struct.pack(">Q", header.chunk_size),
        ]
    )
    return b"".join(
        [
            prefix,
            bytes(nonce_prefix),
            struct.pack(">Q", index),
            b"\x01" if is_final else b"\x00",
        ]
    )


def chunk_nonce(nonce_prefix: bytes, index: int) -> bytes:
    """Build the 12-byte GCM nonce for payload chunk ``index``."""
    if len(nonce_prefix) != NONCE_PREFIX_BYTES:
        raise VaultFormatError()
    if not 0 <= index <= 0xFFFFFFFF:
        raise VaultFormatError()
    return bytes(nonce_prefix) + struct.pack(">I", index)


def split_chunks(data: bytes, chunk_size: int = CHUNK_SIZE) -> list:
    """Split ``data`` into plaintext chunks of at most ``chunk_size``.

    Always returns at least one chunk (an empty input yields one
    empty chunk), matching the vault sealing rules.
    """
    if chunk_size <= 0:
        raise VaultFormatError()
    chunks = [
        bytes(data[i : i + chunk_size])
        for i in range(0, len(data), chunk_size)
    ]
    return chunks if chunks else [b""]


def join_chunks(chunks) -> bytes:
    """Concatenate payload chunks back into a single byte string."""
    return b"".join(bytes(c) for c in chunks)


def encode_header(header: Header = None, **fields) -> bytes:
    """Encode a header as the UTF-8 JSON bytes stored in the file.

    Accepts either a :class:`Header` or its fields as keywords.
    """
    if header is None:
        header = Header(**fields)
    _validate_header(header)
    doc = {
        "format": header.format_version,
        "vault_id": _b64encode(header.vault_id),
        "kdf": {
            "memory_kib": header.kdf.memory_kib,
            "time_cost": header.kdf.time_cost,
            "parallelism": header.kdf.parallelism,
            "hash_len": header.kdf.hash_len,
        },
        "password_wrap": {
            "salt": _b64encode(header.password_salt),
            "nonce": _b64encode(header.password_nonce),
            "wrapped_key": _b64encode(header.password_wrapped_key),
        },
        "recovery_wrap": {
            "salt": _b64encode(header.recovery_salt),
            "nonce": _b64encode(header.recovery_nonce),
            "wrapped_key": _b64encode(header.recovery_wrapped_key),
        },
        "payload": {
            "chunk_size": header.chunk_size,
            "nonce_prefix": _b64encode(header.nonce_prefix),
        },
    }
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(raw) > HEADER_MAX_BYTES:
        raise VaultFormatError()
    return raw


def _validate_header(header: Header) -> None:
    if type(header.format_version) is not int or header.format_version != FORMAT_VERSION:
        raise VaultFormatError()
    validate_params(header.kdf)
    for salt in (header.password_salt, header.recovery_salt):
        if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_BYTES:
            raise VaultFormatError()
    for nonce in (header.password_nonce, header.recovery_nonce):
        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != WRAP_NONCE_BYTES:
            raise VaultFormatError()
    for wrapped in (header.password_wrapped_key, header.recovery_wrapped_key):
        if not isinstance(wrapped, (bytes, bytearray)) or len(wrapped) != WRAPPED_KEY_BYTES:
            raise VaultFormatError()
    if (
        not isinstance(header.nonce_prefix, (bytes, bytearray))
        or len(header.nonce_prefix) != NONCE_PREFIX_BYTES
    ):
        raise VaultFormatError()
    if (
        not isinstance(header.vault_id, (bytes, bytearray))
        or len(header.vault_id) != VAULT_ID_BYTES
    ):
        raise VaultFormatError()
    # The write path keeps the historical 1..16 MiB sanity range;
    # the accepted floor on *open* (MIN_CHUNK_SIZE) is enforced by
    # the header parser, so vaults are only ever written at the
    # 1 MiB CHUNK_SIZE while hostile tiny-chunk files are refused
    # when read.
    if type(header.chunk_size) is not int or not 1 <= header.chunk_size <= _MAX_CHUNK_SIZE:
        raise VaultFormatError()


def _require_keys(obj, keys):
    if not isinstance(obj, dict) or set(obj.keys()) != set(keys):
        raise VaultFormatError()


def _parse_header_json(doc) -> Header:
    _require_keys(
        doc,
        ("format", "vault_id", "kdf", "password_wrap", "recovery_wrap", "payload"),
    )
    if type(doc["format"]) is not int or doc["format"] != FORMAT_VERSION:
        raise VaultFormatError()

    kdf_doc = doc["kdf"]
    _require_keys(kdf_doc, ("memory_kib", "time_cost", "parallelism", "hash_len"))
    for value in kdf_doc.values():
        if type(value) is not int:
            raise VaultFormatError()
    kdf = KdfParams(
        memory_kib=kdf_doc["memory_kib"],
        time_cost=kdf_doc["time_cost"],
        parallelism=kdf_doc["parallelism"],
        hash_len=kdf_doc["hash_len"],
    )
    # Floors/ceilings are enforced here, before any derivation runs.
    validate_params(kdf)

    pw = doc["password_wrap"]
    rec = doc["recovery_wrap"]
    _require_keys(pw, ("salt", "nonce", "wrapped_key"))
    _require_keys(rec, ("salt", "nonce", "wrapped_key"))

    payload = doc["payload"]
    _require_keys(payload, ("chunk_size", "nonce_prefix"))
    if (
        type(payload["chunk_size"]) is not int
        or not MIN_CHUNK_SIZE <= payload["chunk_size"] <= _MAX_CHUNK_SIZE
    ):
        raise VaultFormatError()

    header = Header(
        kdf=kdf,
        vault_id=_b64decode_field(doc["vault_id"], VAULT_ID_BYTES),
        password_salt=_b64decode_field(pw["salt"], SALT_BYTES),
        password_nonce=_b64decode_field(pw["nonce"], WRAP_NONCE_BYTES),
        password_wrapped_key=_b64decode_field(pw["wrapped_key"], WRAPPED_KEY_BYTES),
        recovery_salt=_b64decode_field(rec["salt"], SALT_BYTES),
        recovery_nonce=_b64decode_field(rec["nonce"], WRAP_NONCE_BYTES),
        recovery_wrapped_key=_b64decode_field(rec["wrapped_key"], WRAPPED_KEY_BYTES),
        chunk_size=payload["chunk_size"],
        nonce_prefix=_b64decode_field(payload["nonce_prefix"], NONCE_PREFIX_BYTES),
        format_version=doc["format"],
    )
    return header


def decode_header(raw: bytes) -> Header:
    """Decode and strictly validate a header.

    ``raw`` may be either the header JSON bytes on their own or a
    whole vault file (or its prefix) beginning with the magic; in
    the latter case the embedded header length is checked against
    the size cap before the JSON is read.

    Raises:
        VaultFormatError: on any structural problem.
    """
    if not isinstance(raw, (bytes, bytearray)) or len(raw) == 0:
        raise VaultFormatError()
    raw = bytes(raw)
    if raw.startswith(MAGIC):
        header_json, _payload = parse_file_prefix(raw)
        return _parse_header_json(_loads(header_json))
    return _parse_header_json(_loads(raw))


def reject_duplicate_keys(pairs):
    """``object_pairs_hook`` that refuses duplicated JSON keys.

    JSON's last-wins behaviour would let two different parsers
    disagree about a header; a duplicated key is a format error.
    """
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise VaultFormatError()
        obj[key] = value
    return obj


def _loads(raw: bytes):
    if len(raw) > HEADER_MAX_BYTES:
        raise VaultFormatError()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise VaultFormatError() from None
    try:
        return json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except (ValueError, RecursionError, MemoryError):
        raise VaultFormatError() from None


def encode_file_prefix(header: Header) -> bytes:
    """Encode the file prefix: magic || version || length || header JSON."""
    header_json = encode_header(header)
    return b"".join(
        [
            MAGIC,
            struct.pack(">H", FORMAT_VERSION),
            struct.pack(">I", len(header_json)),
            header_json,
        ]
    )


def parse_prefix(prefix: bytes) -> int:
    """Validate the 14-byte file prefix and return ``header_len``.

    This is what a staged reader checks *before* committing to
    reading the rest of a file, so a non-vault file is refused on
    its first bytes alone.

    Raises:
        VaultFormatError: on a short prefix, bad magic, an
            unsupported version, or a header length beyond the cap.
            A version newer than this build gets the newer-version
            message.
    """
    if not isinstance(prefix, (bytes, bytearray)) or len(prefix) < _PREFIX_LEN:
        raise VaultFormatError()
    prefix = bytes(prefix)
    if prefix[: len(MAGIC)] != MAGIC:
        raise VaultFormatError()
    (version,) = struct.unpack(">H", prefix[len(MAGIC) : len(MAGIC) + 2])
    if version != FORMAT_VERSION:
        if version > FORMAT_VERSION:
            raise VaultFormatError(
                "This vault was made by a newer version of Aegis, and "
                "this copy can't open it. Update Aegis and try again."
            )
        raise VaultFormatError()
    (header_len,) = struct.unpack(
        ">I", prefix[len(MAGIC) + 2 : len(MAGIC) + 2 + 4]
    )
    if header_len < 1 or header_len > HEADER_MAX_BYTES:
        raise VaultFormatError()
    return header_len


def parse_file_prefix(raw: bytes):
    """Split a vault file (or prefix) into (header JSON, payload).

    Raises:
        VaultFormatError: on bad magic, an unsupported version, or a
            header length beyond the cap or the available bytes. A
            version newer than this build gets the newer-version
            message.
    """
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < _PREFIX_LEN:
        raise VaultFormatError()
    raw = bytes(raw)
    header_len = parse_prefix(raw[:_PREFIX_LEN])
    end = _PREFIX_LEN + header_len
    if len(raw) < end:
        raise VaultFormatError()
    return raw[_PREFIX_LEN:end], raw[end:]
