"""Phase 2 plain-language sweep: no crypto jargon in new user-facing copy.

Extends the Phase 1 item-14 discipline to everything Phase 2 says
to a person: the new error messages, the generator's refusals, and
an entry's plain-language description.
"""

import pytest

from aegis.credentials import CredentialEntry
from aegis.errors import (
    CredentialNotFoundError,
    InvalidCredentialError,
    PasswordStoreDamagedError,
)
from aegis.generator import generate_password

BANNED_JARGON = ["argon2", "aes", "encrypt", "kdf", "key derivation", "cipher"]

ENTRY = CredentialEntry(
    id="abc123",
    title="Example Mail",
    username="test.person@example.test",
    password="fake-password-for-tests-1",
    url="https://example.test/login",
    notes="Synthetic.",
    created_utc="2026-10-20T00:00:00+00:00",
    modified_utc="2026-10-20T00:00:00+00:00",
)


def _texts():
    texts = {}
    for cls in (
        CredentialNotFoundError,
        InvalidCredentialError,
        PasswordStoreDamagedError,
    ):
        texts[f"error:{cls.__name__}"] = str(cls())
    try:
        generate_password(3)
    except ValueError as exc:
        texts["generator:length"] = str(exc)
    try:
        generate_password(
            20, use_lowercase=False, use_uppercase=False,
            use_digits=False, use_symbols=False,
        )
    except ValueError as exc:
        texts["generator:no-kinds"] = str(exc)
    texts["entry:describe"] = ENTRY.describe()
    return texts


@pytest.mark.parametrize("label", sorted(_texts()))
def test_no_banned_jargon_in_phase2_copy(label):
    text = _texts()[label].lower()
    for word in BANNED_JARGON:
        assert word not in text, f"{word!r} found in {label}"
