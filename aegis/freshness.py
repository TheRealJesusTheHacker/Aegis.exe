"""The rollback tripwire: the newest vault state, remembered
outside the vault file.

The Phase 1 design note in docs/ROADMAP.md asks for this: the
app remembers the newest vault state it has seen, outside the
vault file, as one more tripwire against silent rollback. A
sealed vault file on its own cannot tell time — replaced whole
by an older copy of itself, it would open as that older copy,
and the vault format (rightly) carries nothing that could
notice. This module is the outside memory.

What is remembered, per vault, in one small file of its own:

- a *check value* (SHA-256) of the newest vault file bytes this
  copy of Aegis has seen for that vault, and
- check values of up to ``_MAX_SUPERSEDED`` states it saw and
  moved past.

A vault is known by its random vault id plus the settled path
of the file — both hashed together into the record's key, so
the record holds no file names, no paths, and nothing about a
vault's contents: check values only. Two different vaults never
share an entry, and the same vault living at two places is
remembered at each place separately, so a vault on a USB stick
works on the machine in front of it.

The check, run on the vault open path in :mod:`aegis.vault`
(before any password work):

- Presented state == remembered newest: the normal case.
- Presented state is one this copy has seen and moved past:
  a rollback, proven from this copy's own history. Refused
  with :class:`VaultRolledBackError` — fail-closed, in keeping
  with the product's posture. It does not open.
- Presented state has never been seen here: taken as current
  and remembered. A check value cannot tell time, so Aegis
  cannot prove such a state is old — it may be the same vault
  changed on another computer, and refusing it would break
  that honest use. The limit is stated, not hidden: the
  tripwire proves rollbacks to states *this copy* has seen.
- No record at all (a first run): the vault opens and its
  state is remembered. Nothing about a first run changes.
- A record that exists but is damaged or not in the expected
  shape: fail closed. The vaults are refused and the damaged
  record is left exactly as it is — never silently replaced,
  because quietly starting over would erase the one thing
  that might be standing between a person and a rollback.

The honest limits, stated here as plainly as in the threat
model: the record is an ordinary file. Someone (or some sync
tool) who puts back an older vault file *and* an older copy of
this record defeats the tripwire — it raises the bar from
"swap one file" to "know about and swap two, consistently",
and it catches the common accident (a sync or backup tool
restoring an old vault on its own) cold. It is a tripwire,
not a proof. Remembering a state is best-effort: if the record
cannot be written, the vault operation that just succeeded
still stands, exactly as it did before this module existed —
the absence of a record is the documented first-run case,
never an error shown to a person mid-work.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from . import format as _format
from .errors import VaultFormatError, VaultRolledBackError
from .publish import replace_with_retry

__all__ = [
    "default_freshness_path",
    "check_freshness",
    "remember_freshness",
]

_RECORD_VERSION = 1
_MAX_RECORD_BYTES = 1 << 20
_MAX_SUPERSEDED = 256

_DAMAGED_MESSAGE = (
    "Aegis can't check this vault against the newest copy it "
    "remembers, because that record is damaged — so Aegis won't "
    "open it. Restoring Aegis's saved state from a backup will "
    "let it check again."
)


class _RecordDamaged(Exception):
    """The remembered-state file exists but cannot be trusted."""


def default_freshness_path() -> Path:
    """Where the remembered vault states live.

    ``AEGIS_FRESHNESS_PATH`` wins when set; otherwise a
    per-person ``Aegis`` folder under ``LOCALAPPDATA`` when that
    is set, and a ``.aegis`` folder in the home directory
    everywhere else — the same places the settings file uses.
    """
    override = os.environ.get("AEGIS_FRESHNESS_PATH")
    if override:
        return Path(override)
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / "Aegis" / "vault-state.json"
    return Path.home() / ".aegis" / "vault-state.json"


def _settled(path) -> str:
    """The settled, full form of *path*, as record-key text.

    Mirrors the comparison settling in
    :mod:`aegis.install_state`: a Windows verbatim prefix comes
    off before settling, so two spellings of one folder key the
    same.
    """
    bs = chr(92)
    verbatim = bs + bs + "?" + bs
    text = str(path)
    if text.startswith(verbatim + "UNC" + bs):
        text = bs + bs + text[len(verbatim) + 4:]
    elif text.startswith(verbatim):
        text = text[len(verbatim):]
    return str(Path(text).resolve())


def _record_key(vault_path, vault_id) -> str | None:
    """The record key for one vault at one place, or None.

    SHA-256 over the vault's random id and its settled path:
    stable for the life of the vault at that place, and it
    reveals neither the id nor the path. A vault id that is not
    the format's 16 bytes yields None — such a file is refused
    by the header parser long before this matters, and the
    tripwire simply does not apply.
    """
    if not isinstance(vault_id, (bytes, bytearray)) or len(vault_id) != 16:
        return None
    digest = hashlib.sha256()
    digest.update(b"aegis-vault-state\x00")
    digest.update(bytes(vault_id))
    digest.update(b"\x00")
    digest.update(_settled(vault_path).encode("utf-8"))
    return digest.hexdigest()


def _is_check_value(value) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _load_records(record_path) -> dict:
    """Read and strictly validate the remembered states.

    Returns the ``vaults`` mapping. No file at all is the
    first-run case and returns an empty mapping; a file that
    exists but is unreadable, oversized, or not exactly the
    expected shape raises :class:`_RecordDamaged` — when a
    security record is in doubt, the doubt wins.
    """
    target = Path(record_path)
    try:
        raw = target.read_bytes()
    except (FileNotFoundError, NotADirectoryError):
        # No record there — including a record path under
        # something that is not a folder at all, where no record
        # could ever have been written. That is the first-run
        # case, not damage.
        return {}
    except OSError:
        raise _RecordDamaged() from None
    if len(raw) > _MAX_RECORD_BYTES:
        raise _RecordDamaged()
    try:
        # Duplicated keys are refused, exactly as the vault
        # header parser refuses them: last-wins parsing would
        # let two readers disagree about what was remembered.
        doc = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_format.reject_duplicate_keys,
        )
    except VaultFormatError:
        raise _RecordDamaged() from None
    except (ValueError, UnicodeDecodeError, RecursionError, MemoryError):
        raise _RecordDamaged() from None
    if not isinstance(doc, dict) or set(doc.keys()) != {"version", "vaults"}:
        raise _RecordDamaged()
    if type(doc["version"]) is not int or doc["version"] != _RECORD_VERSION:
        raise _RecordDamaged()
    vaults = doc["vaults"]
    if not isinstance(vaults, dict):
        raise _RecordDamaged()
    for key, entry in vaults.items():
        if not _is_check_value(key) or not isinstance(entry, dict):
            raise _RecordDamaged()
        if set(entry.keys()) != {"newest", "superseded"}:
            raise _RecordDamaged()
        if not _is_check_value(entry["newest"]):
            raise _RecordDamaged()
        superseded = entry["superseded"]
        if (
            not isinstance(superseded, list)
            or len(superseded) > _MAX_SUPERSEDED
            or any(not _is_check_value(item) for item in superseded)
            or len(set(superseded)) != len(superseded)
            or entry["newest"] in superseded
        ):
            raise _RecordDamaged()
    return vaults


def _fsync_directory(directory: str) -> None:
    """Best-effort fsync of a directory after publishing a file."""
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


def _write_records(record_path, vaults) -> bool:
    """Publish the remembered states atomically. True if it landed."""
    target = Path(record_path)
    payload = json.dumps(
        {"version": _RECORD_VERSION, "vaults": vaults},
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    directory = str(target.parent) if str(target.parent) else "."
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    fd, tmp_name = tempfile.mkstemp(
        dir=directory, prefix=target.name + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # The shared publish step, like every other publish in
        # Aegis: a record file busy for a moment (a scanner
        # looking it over, on Windows above all) is waited out
        # rather than silently dropping the remembered state.
        replace_with_retry(tmp_name, target)
    except OSError:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        return False
    _fsync_directory(directory)
    return True


def check_freshness(vault_path, vault_id, fingerprint, *,
                    record_path=None) -> None:
    """Refuse a vault whose state this copy has seen and passed.

    Raises :class:`VaultRolledBackError` when the presented
    *fingerprint* (the SHA-256 of the vault file's bytes, as the
    open path already computes it) is a superseded state for
    this vault at this place, or when the record itself is
    damaged. A current state, an unseen state, and a first run
    all pass.
    """
    if record_path is None:
        record_path = default_freshness_path()
    key = _record_key(vault_path, vault_id)
    if key is None:
        return
    try:
        vaults = _load_records(record_path)
    except _RecordDamaged:
        raise VaultRolledBackError(_DAMAGED_MESSAGE) from None
    entry = vaults.get(key)
    if entry is None:
        return
    if fingerprint == entry["newest"]:
        return
    if fingerprint in entry["superseded"]:
        raise VaultRolledBackError()


def remember_freshness(vault_path, vault_id, fingerprint, *,
                       record_path=None) -> bool:
    """Remember *fingerprint* as this vault's newest seen state.

    The state it replaces joins the superseded set (kept to the
    most recent ``_MAX_SUPERSEDED``). Best-effort by design:
    returns False — and changes nothing — when the existing
    record is damaged (a damaged record is evidence; it is never
    silently replaced), when the state is already the newest,
    when asked to move a superseded state back to newest (which
    no honest flow requests), or when the record cannot be
    written. Returns True when the record on disk now names
    this state as newest.
    """
    if record_path is None:
        record_path = default_freshness_path()
    key = _record_key(vault_path, vault_id)
    if key is None or not _is_check_value(fingerprint):
        return False
    try:
        vaults = _load_records(record_path)
    except _RecordDamaged:
        return False
    entry = vaults.get(key)
    if entry is not None:
        if fingerprint == entry["newest"]:
            return True
        if fingerprint in entry["superseded"]:
            return False
        superseded = entry["superseded"] + [entry["newest"]]
        entry = {
            "newest": fingerprint,
            "superseded": superseded[-_MAX_SUPERSEDED:],
        }
    else:
        entry = {"newest": fingerprint, "superseded": []}
    vaults[key] = entry
    return _write_records(record_path, vaults)
