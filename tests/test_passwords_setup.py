"""Password feedback and setup copy (spec items 13 and 14).

Feedback levels and messages are the spec's exact strings.  Every piece of
user-facing copy — error messages, feedback, the setup warning, the
recovery guidance, and the printed recovery sheet — must stay plain
language: no crypto jargon anywhere.
"""

import pytest

import aegis
from aegis import password_feedback
from aegis.errors import (
    AegisError,
    EntryNotFoundError,
    UnlockError,
    VaultExistsError,
    VaultFormatError,
    VaultLockedError,
    VaultTamperedError,
    WeakPasswordError,
    WrongPasswordError,
    WrongRecoveryKeyError,
)
from aegis.passwords import MIN_PASSWORD_LENGTH
from aegis.setup import (
    MASTER_PASSWORD_WARNING,
    RECOVERY_KEY_GUIDANCE,
    printable_recovery_sheet,
)

FEEDBACK_MESSAGES = {
    "too short": "Too short — use at least 8 characters. "
                 "A short phrase you can remember works well.",
    "weak": "Weak. It's short or uses just one kind of character. "
            "Longer is stronger — try adding words.",
    "fair": "Fair. More length would make this stronger — "
            "every extra word helps.",
    "good": "Good. This should hold up well.",
    "strong": "Strong. This is a hard password to guess.",
}


# -- item 13: feedback levels + exact messages ---------------------------------
# NOTE: the spec pins the levels, the messages, and the rule "<8 chars ->
# too short", and says scoring is length bands + character-class count.
# The samples below are chosen to sit unambiguously in each band under
# that description (minimum-length single-class = weak, max-length
# four-class passphrase = strong, etc.).

FEEDBACK_SAMPLES = [
    ("aB3!x", "too short"),            # 5 chars, all classes, still too short
    ("short", "too short"),            # 5 chars
    ("1234567", "too short"),          # 7 chars
    ("aaaaaaaa", "weak"),              # minimum length, one character class
    ("password", "weak"),              # 8 chars, one class
    ("abcd1234", "fair"),              # 8 chars, two classes
    ("Abcd1234efgh", "good"),          # 12 chars, three classes
    ("Tr0ub4dor&3-correct-horse!", "strong"),  # long, four classes
]


@pytest.mark.parametrize("password,level", FEEDBACK_SAMPLES,
                         ids=[lvl for _, lvl in FEEDBACK_SAMPLES])
def test_password_feedback_levels_and_messages(password, level):
    feedback = password_feedback(password)
    assert feedback.level == level
    assert feedback.message == FEEDBACK_MESSAGES[level]


def test_password_feedback_boundary_and_shape():
    assert MIN_PASSWORD_LENGTH == 8
    assert password_feedback("1234567").level == "too short"
    assert password_feedback("12345678").level != "too short"
    feedback = password_feedback("whatever-password")
    assert isinstance(feedback.level, str)
    assert isinstance(feedback.message, str)


# -- setup copy -----------------------------------------------------------------

def test_master_password_warning_copy():
    text = MASTER_PASSWORD_WARNING
    assert "Before you store anything" in text
    assert "If you lose your master password, nobody can open your vault." in text
    assert "Not Sentinel, not a support line, not anyone." in text
    assert "no back door" in text
    assert "no reset" in text
    assert "Your recovery key is the one way back in." in text
    assert "Print it" in text
    assert "somewhere safe" in text


def test_recovery_key_guidance_copy():
    text = RECOVERY_KEY_GUIDANCE
    assert "only way back into your vault" in text
    assert "forget your master password" in text
    assert "Print this page now" in text
    assert "locked drawer" in text
    assert "Anyone who finds this key can open your vault" in text
    assert "don't save it in a photo, an email, or a note on this computer" in text


def test_printable_recovery_sheet(create_vault):
    created, _ = create_vault()
    created.session.lock()
    sheet = printable_recovery_sheet("Family Vault", created.recovery_key)
    assert "AEGIS" in sheet
    assert "Family Vault" in sheet
    # The recovery key itself, exactly as displayed at creation.
    assert created.recovery_key in sheet
    # Warning recap + sign-off line.
    assert "master password" in sheet
    assert "It does not open — for anyone but you." in sheet


# -- item 14: banned jargon -------------------------------------------------------
# None of these may appear (case-insensitive) in any user-facing string.

BANNED_JARGON = ["argon2", "aes", "encrypt", "kdf", "key derivation", "cipher"]

ALL_ERROR_CLASSES = [
    AegisError,
    VaultFormatError,
    UnlockError,
    WrongPasswordError,
    WrongRecoveryKeyError,
    VaultTamperedError,
    VaultLockedError,
    WeakPasswordError,
    VaultExistsError,
    EntryNotFoundError,
]


def _user_texts():
    texts = {}
    for cls in ALL_ERROR_CLASSES:
        exc = cls()
        texts[f"error:{cls.__name__}"] = str(exc) or getattr(
            exc, "user_message", "")
        texts[f"user_message:{cls.__name__}"] = getattr(
            cls, "user_message", "") or ""
    for password, _ in FEEDBACK_SAMPLES:
        texts[f"feedback:{password!r}"] = password_feedback(password).message
    texts["MASTER_PASSWORD_WARNING"] = MASTER_PASSWORD_WARNING
    texts["RECOVERY_KEY_GUIDANCE"] = RECOVERY_KEY_GUIDANCE
    # Controlled name/key so the sheet check cannot trip on a random
    # substring inside a generated base32 key.
    texts["printable_recovery_sheet"] = printable_recovery_sheet(
        "Test Vault", "2222-2222-2222-2222-2222-2222-2222-2222")
    return texts


@pytest.mark.parametrize("label", sorted(_user_texts()))
def test_no_banned_jargon_in_user_facing_copy(label):
    text = _user_texts()[label].lower()
    for word in BANNED_JARGON:
        assert word not in text, f"{word!r} found in {label}"


# -- public exports ---------------------------------------------------------------

def test_public_exports():
    assert aegis.__version__ == "1.0.3"
    for name in ("Vault", "VaultSession", "CreatedVault", "password_feedback",
                 "MASTER_PASSWORD_WARNING", "RECOVERY_KEY_GUIDANCE",
                 "printable_recovery_sheet"):
        assert hasattr(aegis, name), name
