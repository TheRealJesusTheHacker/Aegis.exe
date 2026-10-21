"""The Aegis vault: create, open, and work with sealed vault files.

A vault file on disk is *always* sealed — even while a session is
open, nothing readable sits on disk; the plaintext lives only in the
session's memory. Writing is atomic: a temporary file in the same
directory is sealed completely, then swapped into place.

Cryptography (vetted libraries only, never hand-rolled):

- Each vault has its own random 32-byte vault key. It never touches
  disk in plaintext; the header stores two AES-256-GCM wrapped
  copies, one under a key derived from the master password and one
  under a key derived from the recovery key, both derivations being
  Argon2id with the vault's stored parameters.
- The payload (a manifest plus the entry bytes, bundled) is sealed
  with the vault key in 1 MiB chunks, each with its own nonce and
  authenticated context. Every seal picks a fresh nonce prefix, so
  a nonce is never reused under the vault key for new plaintext.
- Keys in memory are held as ``bytearray`` and zeroed after use and
  on lock.
- Beside the core, the rollback tripwire (B-13,
  :mod:`aegis.freshness`): the newest vault state this copy of
  Aegis has seen is remembered outside the vault file, and the
  open path refuses a file that comes back as a state it has
  seen and moved past. It works on the file fingerprint the open
  and save paths already compute; it changes no format, no
  algorithm, and no signature in this module.

A note on memory hygiene, stated honestly: the *primary* buffers
this module owns — the session vault key, the derived wrapping
keys, and the password / recovery secret buffers — are zeroed
after use, on lock, and on exception paths (derivations run inside
``try/finally`` for exactly that reason). What cannot be zeroed is
everything the runtime and the vetted libraries copy on their own:
``bytes(...)`` conversions are immutable, an ``AESGCM`` object
retains the key copy it was built from for its lifetime, and
plaintext entry bytes are ordinary immutable objects. Those copies
are beyond reach and are reclaimed only by the garbage collector.
A full memory review is Phase 5's release gate; no claim of total
erasure is made here.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import struct
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import format as _format
from .errors import (
    EntryNotFoundError,
    InvalidEntryNameError,
    VaultChangedOnDiskError,
    VaultExistsError,
    VaultFormatError,
    VaultLockedError,
    VaultSaveError,
    VaultTamperedError,
    WeakPasswordError,
    WrongPasswordError,
    WrongRecoveryKeyError,
)
from .format import Header
from .freshness import check_freshness, remember_freshness
from .kdf import DEFAULT_PARAMS, KdfParams, derive_key, validate_params
from .publish import link_into_place, replace_with_retry
from .passwords import MIN_PASSWORD_LENGTH
from .recovery import format_recovery_key, recovery_key_to_bytes

__all__ = ["Vault", "VaultSession", "CreatedVault", "MIN_PASSWORD_LENGTH"]

_VAULT_KEY_BYTES = 32
_SALT_BYTES = 16
_MANIFEST_VERSION = 1

_COULDNT_OPEN_MESSAGE = (
    "Aegis couldn't open that file. It may have moved, or this "
    "computer can't read it right now."
)


def _fsync_directory(directory: str) -> None:
    """Best-effort fsync of a directory after publishing a file.

    Without it, a power loss can roll back the rename even though
    the file itself was fsynced. Platforms that disallow opening or
    fsyncing a directory skip this silently.
    """
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


def _zero(buf) -> None:
    """Overwrite a bytearray with zeros, in place."""
    if buf is not None:
        for i in range(len(buf)):
            buf[i] = 0


def _secret_bytes(password: str) -> bytearray:
    if not isinstance(password, str):
        raise TypeError("A password must be text.")
    return bytearray(password.encode("utf-8"))


def _derive_kek(secret, salt: bytes, params: KdfParams) -> bytearray:
    return bytearray(derive_key(bytes(secret), salt, params))


def _wrap_vault_key(kek: bytearray, vault_key: bytearray, aad: bytes):
    nonce = secrets.token_bytes(_format.WRAP_NONCE_BYTES)
    wrapped = AESGCM(bytes(kek)).encrypt(nonce, bytes(vault_key), aad)
    return nonce, wrapped


def _unwrap_vault_key(kek: bytearray, nonce: bytes, wrapped: bytes, aad: bytes):
    """Return the vault key as a bytearray, or None if the tag fails."""
    try:
        plain = AESGCM(bytes(kek)).decrypt(nonce, wrapped, aad)
    except InvalidTag:
        return None
    return bytearray(plain)


@dataclass
class CreatedVault:
    """The result of creating a vault.

    ``recovery_key`` is the display form of the recovery key. It is
    shown to the user once, here; it is stored nowhere else. It is
    excluded from ``repr``/``str`` so that logging or echoing a
    ``CreatedVault`` can never leak the one credential that is
    stored nowhere.
    """

    session: "VaultSession"
    recovery_key: str = field(repr=False)


class VaultSession:
    """An open (or formerly open) vault, holding its contents in memory."""

    def __init__(self, path, header: Header, vault_key: bytearray,
                 entries: dict, created_utc: str, fingerprint: str = None):
        self._path = Path(path)
        self._header = header
        self._vault_key = vault_key  # bytearray while unlocked, None after lock
        self._entries = dict(entries)
        self._created_utc = created_utc
        self._dirty = False
        self._locked = False
        # SHA-256 hex of the vault file bytes as this session last
        # read or wrote them; the optimistic freshness guard (N-02)
        # compares the on-disk file against it before every save so
        # a stale session can never silently revert another
        # session's newer save or credential change.
        self._fingerprint = fingerprint

    # -- freshness guard (N-02) ---------------------------------------------

    @staticmethod
    def _fingerprint_of(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _check_unchanged_on_disk(self) -> None:
        """Refuse to save over a vault that changed since we saw it.

        A mismatch — or the file having gone missing — raises
        :class:`VaultChangedOnDiskError` and no write occurs. A
        session with no recorded fingerprint (never produced by
        :class:`Vault`) has no baseline and skips the check.
        """
        if self._fingerprint is None:
            return
        try:
            current = self._path.read_bytes()
        except OSError:
            raise VaultChangedOnDiskError() from None
        if self._fingerprint_of(current) != self._fingerprint:
            raise VaultChangedOnDiskError()

    # -- basic properties -------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    @property
    def is_locked(self) -> bool:
        return self._locked

    # -- internals ---------------------------------------------------------

    def _require_unlocked(self) -> None:
        if self._locked or self._vault_key is None:
            raise VaultLockedError()

    @staticmethod
    def _validate_name(name) -> None:
        if not isinstance(name, str):
            raise InvalidEntryNameError()
        if not 1 <= len(name) <= 255:
            raise InvalidEntryNameError()
        if "\x00" in name or "\\" in name:
            raise InvalidEntryNameError()
        if name.startswith("/"):
            raise InvalidEntryNameError()
        if any(segment == ".." for segment in name.split("/")):
            raise InvalidEntryNameError()

    def _serialize_bundle(self) -> bytes:
        manifest = {
            "version": _MANIFEST_VERSION,
            "created_utc": self._created_utc,
            "entries": [
                {"name": name, "size": len(data)}
                for name, data in self._entries.items()
            ],
        }
        manifest_json = json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        parts = [struct.pack(">I", len(manifest_json)), manifest_json]
        parts.extend(self._entries.values())
        return b"".join(parts)

    def _seal_bytes(self) -> bytes:
        """Seal the current contents into complete vault file bytes."""
        # Every seal gets a fresh nonce prefix.
        self._header.nonce_prefix = secrets.token_bytes(
            _format.NONCE_PREFIX_BYTES
        )
        bundle = self._serialize_bundle()
        chunks = _format.split_chunks(bundle, self._header.chunk_size)
        aes = AESGCM(bytes(self._vault_key))
        sealed = bytearray()
        last = len(chunks) - 1
        for index, chunk in enumerate(chunks):
            nonce = _format.chunk_nonce(self._header.nonce_prefix, index)
            aad = _format.chunk_aad(
                self._header, self._header.nonce_prefix, index, index == last
            )
            sealed.extend(aes.encrypt(nonce, chunk, aad))
        return _format.encode_file_prefix(self._header) + bytes(sealed)

    def _atomic_write(self, data: bytes, *, overwrite: bool = True) -> None:
        """Publish ``data`` to the vault path via a same-dir temp file.

        With ``overwrite`` (session saves) the temp file replaces the
        target unconditionally. Without it (vault creation) the temp
        file is put into place by :mod:`aegis.publish`, which fails
        with :class:`VaultExistsError` if anything already sits at
        the target — a racing creator can never be silently
        overwritten, on any drive. Either way the containing
        directory is fsynced afterwards so the publish itself is
        durable.
        """
        directory = str(self._path.parent) if str(self._path.parent) else "."
        fd, tmp_name = tempfile.mkstemp(
            dir=directory, prefix=self._path.name + ".", suffix=".tmp"
        )
        published = False
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            if overwrite:
                replace_with_retry(tmp_name, self._path)
            else:
                try:
                    link_into_place(tmp_name, self._path)
                except FileExistsError:
                    raise VaultExistsError() from None
            published = True
            # Everything after the publish is strictly best-effort
            # (N-01): once the new file is in place the operation
            # has succeeded, and no cleanup or durability step may
            # turn that success into a reported failure — otherwise
            # a credential change would roll its in-memory header
            # back to a wrap the disk no longer carries.
            if not overwrite:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
            try:
                _fsync_directory(directory)
            except OSError:
                pass
        except BaseException:
            if not published:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
            raise

    # -- content operations -------------------------------------------------

    def names(self) -> list:
        """Return the names of the items in this vault, in stored order."""
        self._require_unlocked()
        return list(self._entries.keys())

    def read(self, name: str) -> bytes:
        """Return the bytes stored under ``name``."""
        self._require_unlocked()
        try:
            return self._entries[name]
        except KeyError:
            raise EntryNotFoundError() from None

    def write(self, name: str, data: bytes) -> None:
        """Store ``data`` under ``name``, replacing any existing item."""
        self._require_unlocked()
        self._validate_name(name)
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("Vault items must be bytes.")
        self._entries[name] = bytes(data)
        self._dirty = True

    def remove(self, name: str) -> None:
        """Remove the item stored under ``name``."""
        self._require_unlocked()
        try:
            del self._entries[name]
        except KeyError:
            raise EntryNotFoundError() from None
        self._dirty = True

    def save(self) -> None:
        """Seal the current contents back to disk, atomically.

        Refuses with :class:`VaultChangedOnDiskError` (writing
        nothing) if the file on disk no longer matches what this
        session last read or wrote. A failure in the write machinery
        surfaces as a plain :class:`VaultSaveError`, never a raw
        ``OSError``.
        """
        self._require_unlocked()
        self._check_unchanged_on_disk()
        data = self._seal_bytes()
        try:
            self._atomic_write(data)
        except OSError:
            raise VaultSaveError() from None
        self._fingerprint = self._fingerprint_of(data)
        self._dirty = False
        # The rollback tripwire (B-13): the state just written is
        # the newest this copy of Aegis has seen. Best-effort —
        # a state that cannot be remembered never turns a landed
        # save into a failure.
        remember_freshness(
            self._path, self._header.vault_id, self._fingerprint
        )

    def _publish_new(self) -> None:
        """Publish a brand-new vault file, refusing to overwrite.

        Used only by :meth:`Vault.create`: the file is linked into
        place rather than replaced, so a target that appeared after
        the upfront existence check is never silently destroyed
        (:class:`VaultExistsError`). Any other failure in the write
        machinery surfaces as :class:`VaultSaveError`.
        """
        self._require_unlocked()
        data = self._seal_bytes()
        try:
            self._atomic_write(data, overwrite=False)
        except OSError:
            raise VaultSaveError() from None
        self._fingerprint = self._fingerprint_of(data)
        self._dirty = False
        # A new vault's first state is remembered for the
        # rollback tripwire, like any state a save lands (B-13).
        remember_freshness(
            self._path, self._header.vault_id, self._fingerprint
        )

    # -- credential changes ---------------------------------------------------

    def change_password(self, new_password: str) -> None:
        """Change the master password.

        Only the password path is rebuilt: a *fresh salt* and a fresh
        nonce, under a key derived from the new password with that
        new salt, and the vault is saved (re-sealed, which rebinds
        the payload to the new wrap set). The recovery path's salt
        and wrap are untouched — the per-path wrap contexts are what
        make that possible: neither path's AAD mentions the other
        path's salt, so rotating one salt strands nothing. Rotating
        the salt also means the new password is a fresh derivation
        problem, not testable with work done against the old salt.
        """
        self._require_unlocked()
        if not isinstance(new_password, str):
            raise TypeError("A password must be text.")
        if len(new_password) < MIN_PASSWORD_LENGTH:
            raise WeakPasswordError()
        header = self._header
        old_salt, old_nonce, old_wrapped = (
            header.password_salt,
            header.password_nonce,
            header.password_wrapped_key,
        )
        new_salt = secrets.token_bytes(_SALT_BYTES)
        secret = _secret_bytes(new_password)
        try:
            kek = _derive_kek(secret, new_salt, header.kdf)
        finally:
            _zero(secret)
        # Point the header at the new salt so the wrap is sealed
        # under the new per-path context; restored on any failure.
        header.password_salt = new_salt
        try:
            context = _format.wrap_context_password(header)
            try:
                nonce, wrapped = _wrap_vault_key(kek, self._vault_key, context)
            finally:
                _zero(kek)
            header.password_nonce = nonce
            header.password_wrapped_key = wrapped
            self.save()
        except BaseException:
            header.password_salt = old_salt
            header.password_nonce, header.password_wrapped_key = (
                old_nonce,
                old_wrapped,
            )
            raise

    def regenerate_recovery_key(self) -> str:
        """Replace the recovery key and return the new display form.

        The old recovery key stops working. Only the recovery path
        is rebuilt — a *fresh salt* and a fresh nonce around a fresh
        32 random bytes — and the vault is saved (re-sealed, which
        rebinds the payload to the new wrap set). The password
        path's salt and wrap are untouched; the per-path wrap
        contexts are what make that possible.
        """
        self._require_unlocked()
        header = self._header
        raw = bytearray(secrets.token_bytes(32))
        display = format_recovery_key(bytes(raw))
        new_salt = secrets.token_bytes(_SALT_BYTES)
        try:
            kek = _derive_kek(raw, new_salt, header.kdf)
        finally:
            _zero(raw)
        old_salt = header.recovery_salt
        old_nonce, old_wrapped = header.recovery_nonce, header.recovery_wrapped_key
        header.recovery_salt = new_salt
        try:
            context = _format.wrap_context_recovery(header)
            try:
                nonce, wrapped = _wrap_vault_key(kek, self._vault_key, context)
            finally:
                _zero(kek)
            header.recovery_nonce = nonce
            header.recovery_wrapped_key = wrapped
            self.save()
        except BaseException:
            header.recovery_salt = old_salt
            header.recovery_nonce, header.recovery_wrapped_key = old_nonce, old_wrapped
            raise
        return display

    # -- locking ---------------------------------------------------------------

    def lock(self) -> None:
        """Save any changes, wipe the vault key from memory, and lock.

        The save happens *first*: if it fails, the error propagates
        and the session stays unlocked with its entries and vault
        key intact, so no unsaved work is destroyed by the failure
        itself and the user can retry. Only a successful save (or a
        clean session) is followed by wiping and locking.
        """
        if self._locked:
            return
        if self._dirty:
            self.save()
        _zero(self._vault_key)
        self._vault_key = None
        # Empty the held contents in place before rebinding, so a
        # reference held elsewhere sees them gone too. Values are
        # immutable bytes, which cannot be scrubbed in place —
        # dropping every reference is the honest limit, stated in
        # docs/THREAT-MODEL.md.
        self._entries.clear()
        self._entries = {}
        self._locked = True

    def close(self) -> None:
        """Close the session (the same as locking it)."""
        self.lock()

    def __enter__(self) -> "VaultSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.lock()
        return False


def _parse_bundle(bundle: bytes):
    """Split a decrypted payload bundle into (created_utc, entries)."""
    if len(bundle) < 4:
        raise VaultTamperedError()
    (manifest_len,) = struct.unpack(">I", bundle[:4])
    end = 4 + manifest_len
    if manifest_len < 1 or end > len(bundle):
        raise VaultTamperedError()
    try:
        manifest = json.loads(
            bundle[4:end].decode("utf-8"),
            object_pairs_hook=_format.reject_duplicate_keys,
        )
    except VaultFormatError:
        # Duplicate keys (the hook's error) inside a sealed payload
        # are tampering, not a format problem.
        raise VaultTamperedError() from None
    except (ValueError, UnicodeDecodeError, RecursionError, MemoryError):
        raise VaultTamperedError() from None
    if not isinstance(manifest, dict):
        raise VaultTamperedError()
    version = manifest.get("version")
    if type(version) is not int or version != _MANIFEST_VERSION:
        raise VaultTamperedError()
    created_utc = manifest.get("created_utc")
    entry_docs = manifest.get("entries")
    if not isinstance(created_utc, str) or not isinstance(entry_docs, list):
        raise VaultTamperedError()
    entries = {}
    offset = end
    for doc in entry_docs:
        if not isinstance(doc, dict):
            raise VaultTamperedError()
        name, size = doc.get("name"), doc.get("size")
        if not isinstance(name, str) or type(size) is not int or size < 0:
            raise VaultTamperedError()
        # Names on the read path obey exactly the writer's rules, so
        # a vault that opens never carries a name a later feature
        # (export, extract, display) could be hurt by.
        try:
            VaultSession._validate_name(name)
        except InvalidEntryNameError:
            raise VaultTamperedError() from None
        if name in entries:
            raise VaultTamperedError()
        chunk = bundle[offset : offset + size]
        if len(chunk) != size:
            raise VaultTamperedError()
        entries[name] = chunk
        offset += size
    if offset != len(bundle):
        raise VaultTamperedError()
    return created_utc, entries


def _read_vault_file(target: Path):
    """Read a vault file in stages: prefix, then header, then payload.

    A non-vault file is rejected from its first 14 bytes — magic,
    version, and header-length bounds are all validated before the
    header is read, and the payload (which may legitimately be
    large; there is deliberately no absolute size cap) is read
    only after the header checks out structurally. Any OS-level
    failure to read (missing file, a directory, unreadable) is
    reported as a plain :class:`VaultFormatError`; no raw
    ``OSError`` and no filesystem path escapes through it.
    """
    try:
        with open(target, "rb") as handle:
            prefix = handle.read(_format.PREFIX_LEN)
            if len(prefix) < _format.PREFIX_LEN:
                raise VaultFormatError()
            header_len = _format.parse_prefix(prefix)
            header_json = handle.read(header_len)
            if len(header_json) < header_len:
                raise VaultFormatError()
            payload = handle.read()
    except OSError:
        raise VaultFormatError(_COULDNT_OPEN_MESSAGE) from None
    fingerprint = hashlib.sha256(prefix + header_json + payload).hexdigest()
    return header_json, payload, fingerprint


class Vault:
    """Factory for vault sessions: create a new vault, or open one."""

    @staticmethod
    def create(path, password: str, *, params: KdfParams = DEFAULT_PARAMS) -> CreatedVault:
        """Create a new sealed vault at ``path`` and open a session on it.

        The (empty) vault file is written to disk, sealed, before
        this returns. The recovery key is generated fresh and
        returned in the :class:`CreatedVault`; it is stored nowhere.

        Raises:
            VaultExistsError: if anything already exists at ``path``.
            WeakPasswordError: if ``password`` is under the minimum length.
            VaultFormatError: if ``params`` are outside the policy.
            VaultSaveError: if the new vault file cannot be written.
        """
        target = Path(path)
        if _format.windows_unsafe_segment(target.name):
            raise VaultSaveError(
                "That name can't be used for a vault file on "
                "Windows. Pick a different name and try again."
            )
        if os.path.lexists(target):
            raise VaultExistsError()
        if not isinstance(password, str):
            raise TypeError("A password must be text.")
        if len(password) < MIN_PASSWORD_LENGTH:
            raise WeakPasswordError()
        validate_params(params)

        vault_key = bytearray(secrets.token_bytes(_VAULT_KEY_BYTES))
        try:
            recovery_raw = bytearray(secrets.token_bytes(32))
            recovery_display = format_recovery_key(bytes(recovery_raw))

            header = Header(
                kdf=params,
                password_salt=secrets.token_bytes(_SALT_BYTES),
                password_nonce=b"\x00" * _format.WRAP_NONCE_BYTES,
                password_wrapped_key=b"\x00" * _format.WRAPPED_KEY_BYTES,
                recovery_salt=secrets.token_bytes(_SALT_BYTES),
                recovery_nonce=b"\x00" * _format.WRAP_NONCE_BYTES,
                recovery_wrapped_key=b"\x00" * _format.WRAPPED_KEY_BYTES,
                chunk_size=_format.CHUNK_SIZE,
                nonce_prefix=secrets.token_bytes(_format.NONCE_PREFIX_BYTES),
                vault_id=secrets.token_bytes(_format.VAULT_ID_BYTES),
            )

            secret = _secret_bytes(password)
            try:
                kek_pw = _derive_kek(secret, header.password_salt, params)
            finally:
                _zero(secret)
            try:
                nonce, wrapped = _wrap_vault_key(
                    kek_pw, vault_key, _format.wrap_context_password(header)
                )
            finally:
                _zero(kek_pw)
            header.password_nonce = nonce
            header.password_wrapped_key = wrapped

            try:
                kek_rec = _derive_kek(recovery_raw, header.recovery_salt, params)
            finally:
                _zero(recovery_raw)
            try:
                nonce, wrapped = _wrap_vault_key(
                    kek_rec, vault_key, _format.wrap_context_recovery(header)
                )
            finally:
                _zero(kek_rec)
            header.recovery_nonce = nonce
            header.recovery_wrapped_key = wrapped

            created_utc = datetime.now(timezone.utc).isoformat()
            session = VaultSession(target, header, vault_key, {}, created_utc)
            # No-overwrite publish: a target that appeared after the
            # upfront check raises VaultExistsError, never a clobber;
            # a write failure raises VaultSaveError (see _publish_new).
            session._publish_new()
        except BaseException:
            # F-10: anything that fails after the vault key exists
            # but before a successful publish zeroes the key buffer
            # before it falls out of scope, mirroring the other
            # derivation sites.
            _zero(vault_key)
            raise
        return CreatedVault(session=session, recovery_key=recovery_display)

    @staticmethod
    def open(path, *, password: str = None, recovery_key: str = None) -> VaultSession:
        """Open the vault at ``path`` with a password or a recovery key.

        Exactly one credential must be given.

        Raises:
            ValueError: if both or neither credential is given.
            VaultFormatError: if the file is not an openable vault.
            WrongPasswordError: if the password does not open it.
            WrongRecoveryKeyError: if the recovery key does not open it.
            VaultTamperedError: if a credential opens the vault but
                the contents fail their checks.
            VaultRolledBackError: if the file is a vault state this
                copy of Aegis has seen and moved past (the rollback
                tripwire, aegis.freshness), or the remembered state
                it would be checked against is damaged.
        """
        if (password is None) == (recovery_key is None):
            raise ValueError(
                "Give exactly one of password or recovery_key to open a vault."
            )
        target = Path(path)
        header_json, payload, fingerprint = _read_vault_file(target)
        # Strict header validation (including KDF floors/ceilings)
        # happens here, before any key derivation runs.
        header = _format.decode_header(header_json)
        # The rollback tripwire (B-13, aegis.freshness): refuse a
        # vault file that comes back as a state this copy of Aegis
        # has seen and moved past, and refuse when the remembered
        # state itself is damaged. Beside the crypto core, on
        # fingerprints only — and before any key derivation, so a
        # rolled-back vault costs no password work and reveals
        # nothing about whether a password would have opened it.
        check_freshness(target, header.vault_id, fingerprint)

        using_password = password is not None
        if using_password:
            secret = _secret_bytes(password)
            salt = header.password_salt
            nonce = header.password_nonce
            wrapped = header.password_wrapped_key
            context = _format.wrap_context_password(header)
        else:
            try:
                secret = bytearray(recovery_key_to_bytes(recovery_key))
            except ValueError:
                raise WrongRecoveryKeyError() from None
            salt = header.recovery_salt
            nonce = header.recovery_nonce
            wrapped = header.recovery_wrapped_key
            context = _format.wrap_context_recovery(header)

        try:
            kek = _derive_kek(secret, salt, header.kdf)
        finally:
            _zero(secret)
        try:
            vault_key = _unwrap_vault_key(kek, nonce, wrapped, context)
        finally:
            _zero(kek)
        if vault_key is None:
            if using_password:
                raise WrongPasswordError()
            raise WrongRecoveryKeyError()

        # The credential checked out. From here, any failure is a
        # damaged or changed file, not a wrong credential.
        try:
            bundle = Vault._unseal_payload(header, vault_key, payload)
            created_utc, entries = _parse_bundle(bundle)
        except BaseException:
            _zero(vault_key)
            raise
        # The vault opened and checked out: this state is now the
        # newest this copy of Aegis has seen (adopting a state it
        # had never seen, per the tripwire's stated limits).
        # Best-effort; a failure to remember never fails an open
        # that already succeeded.
        remember_freshness(target, header.vault_id, fingerprint)
        return VaultSession(
            target, header, vault_key, entries, created_utc,
            fingerprint=fingerprint,
        )

    @staticmethod
    def _unseal_payload(header: Header, vault_key: bytearray,
                        payload: bytes) -> bytes:
        if len(payload) == 0:
            raise VaultTamperedError()
        aes = AESGCM(bytes(vault_key))
        plain_chunks = []
        offset = 0
        index = 0
        step = header.chunk_size + _format.GCM_TAG_BYTES
        total = len(payload)
        while offset < total:
            take = min(step, total - offset)
            if take <= _format.GCM_TAG_BYTES:
                raise VaultTamperedError()
            chunk = payload[offset : offset + take]
            is_final = offset + take == total
            nonce = _format.chunk_nonce(header.nonce_prefix, index)
            aad = _format.chunk_aad(
                header, header.nonce_prefix, index, is_final
            )
            try:
                plain = aes.decrypt(nonce, chunk, aad)
            except InvalidTag:
                raise VaultTamperedError() from None
            if not is_final and len(plain) != header.chunk_size:
                raise VaultTamperedError()
            plain_chunks.append(plain)
            offset += take
            index += 1
        return _format.join_chunks(plain_chunks)
