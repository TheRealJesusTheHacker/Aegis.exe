"""Recovery keys for Aegis vaults.

A recovery key is 32 random bytes generated when a vault is created.
It is shown to the user exactly once, in display form: RFC 4648
base32, uppercase, padding stripped, grouped in blocks of four
characters separated by dashes — made to be printed and kept
somewhere physically safe.

The raw bytes are a credential of the same strength as the master
password: they feed the same key derivation, with their own salt,
and wrap their own copy of the vault key. The display string is the
only place the key ever exists outside the user's printed copy; it
is never stored in the vault or anywhere else on disk.
"""

from __future__ import annotations

import base64
import binascii
import secrets

__all__ = [
    "RECOVERY_KEY_BYTES",
    "generate_recovery_key",
    "format_recovery_key",
    "recovery_key_to_bytes",
]

RECOVERY_KEY_BYTES = 32

_GROUP = 4


def format_recovery_key(raw: bytes) -> str:
    """Render raw recovery-key bytes in printable display form."""
    if len(raw) != RECOVERY_KEY_BYTES:
        raise ValueError(
            "A recovery key must be exactly %d bytes." % RECOVERY_KEY_BYTES
        )
    text = base64.b32encode(bytes(raw)).decode("ascii").rstrip("=")
    return "-".join(
        text[i : i + _GROUP] for i in range(0, len(text), _GROUP)
    )


def generate_recovery_key() -> str:
    """Generate a fresh recovery key and return its display form."""
    return format_recovery_key(secrets.token_bytes(RECOVERY_KEY_BYTES))


def recovery_key_to_bytes(text: str) -> bytes:
    """Parse a recovery key in display (or loosely typed) form.

    Spaces and dashes are ignored and case does not matter, so a key
    can be typed back in the way it was printed.

    Raises:
        ValueError: if the text is not a well-formed recovery key.
    """
    if not isinstance(text, str):
        raise ValueError("A recovery key must be text.")
    compact = "".join(text.split()).replace("-", "").upper()
    if not compact:
        raise ValueError("That recovery key is empty.")
    padding = (-len(compact)) % 8
    try:
        raw = base64.b32decode(compact + ("=" * padding))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("That recovery key is not written correctly.") from exc
    if len(raw) != RECOVERY_KEY_BYTES:
        raise ValueError("That recovery key is the wrong length.")
    # Reject non-canonical spellings that decode to the right length
    # by a fluke (wrong final-char bits): re-encoding must round-trip.
    if base64.b32encode(raw).decode("ascii").rstrip("=") != compact:
        raise ValueError("That recovery key is not written correctly.")
    return raw
