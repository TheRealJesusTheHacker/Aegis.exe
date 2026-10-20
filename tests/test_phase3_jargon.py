"""Phase 3 plain-language sweep: no crypto jargon in new user-facing copy.

Extends the Phase 1/2 discipline to everything Phase 3 says to a
person: the new error messages, the lock-and-send and armor flow
notes, and a Strongbox item's plain-language description.
"""

import pytest

from aegis.armor import ARMOR_PASSWORD_NOTE
from aegis.errors import (
    ArmorRefusalError,
    DocumentTooLargeError,
    InvalidStrongboxEntryError,
    SealedExistsError,
    SealedFormatError,
    SealedSaveError,
    SealedSourceError,
    SealedTamperedError,
    StrongboxDamagedError,
    StrongboxNotFoundError,
    WrongFilePasswordError,
)
from aegis.locksend import LOCK_AND_SEND_PASSWORD_NOTE
from aegis.strongbox import StrongboxEntry

BANNED_JARGON = ["argon2", "aes", "encrypt", "kdf", "key derivation", "cipher"]

ENTRY = StrongboxEntry(
    id="abc123",
    kind="code",
    title="Example recovery code",
    body="0000-FAKE",
    created_utc="2026-10-20T00:00:00+00:00",
    modified_utc="2026-10-20T00:00:00+00:00",
)


def _texts():
    texts = {}
    for cls in (
        ArmorRefusalError,
        DocumentTooLargeError,
        InvalidStrongboxEntryError,
        SealedExistsError,
        SealedFormatError,
        SealedSaveError,
        SealedSourceError,
        SealedTamperedError,
        StrongboxDamagedError,
        StrongboxNotFoundError,
        WrongFilePasswordError,
    ):
        texts[f"error:{cls.__name__}"] = str(cls())
    texts["locksend:password-note"] = LOCK_AND_SEND_PASSWORD_NOTE
    texts["armor:password-note"] = ARMOR_PASSWORD_NOTE
    texts["strongbox:describe"] = ENTRY.describe()
    return texts


@pytest.mark.parametrize("label", sorted(_texts()))
def test_no_banned_jargon_in_phase3_copy(label):
    text = _texts()[label].lower()
    for word in BANNED_JARGON:
        assert word not in text, f"{word!r} found in {label}"
