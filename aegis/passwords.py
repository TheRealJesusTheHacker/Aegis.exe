"""Plain-language feedback on master password strength.

Scoring is deterministic — the same password always earns the same
answer. It works from two things only: length, and how many kinds of
character the password uses (lowercase letters, uppercase letters,
digits, and everything else, including spaces and symbols).

- Fewer than 8 characters is always "too short"; a vault will not
  accept it at all.
- Otherwise the score counts thresholds crossed: one point each for
  reaching 8, 12, 16, and 20 characters, plus one point for each
  kind of character used beyond the first (so 0 to 3 extra).
- The total maps to a level: 1 or fewer is "weak", 2-3 is "fair",
  4-5 is "good", and 6 or more is "strong". (The minimum-length,
  single-kind password scores 1 — weak; eight characters with two
  kinds of character scores 2 — fair.)

Length matters most: a long phrase made of ordinary words scores
well, and that is deliberate — a phrase a person can remember beats
a short scramble they have to write on a sticky note.
"""

from __future__ import annotations

import string
from dataclasses import dataclass

__all__ = ["MIN_PASSWORD_LENGTH", "PasswordFeedback", "password_feedback"]

MIN_PASSWORD_LENGTH = 8

_MESSAGES = {
    "too short": (
        "Too short — use at least 8 characters. "
        "A short phrase you can remember works well."
    ),
    "weak": (
        "Weak. It's short or uses just one kind of character. "
        "Longer is stronger — try adding words."
    ),
    "fair": (
        "Fair. More length would make this stronger — "
        "every extra word helps."
    ),
    "good": "Good. This should hold up well.",
    "strong": "Strong. This is a hard password to guess.",
}


@dataclass(frozen=True)
class PasswordFeedback:
    """A strength level and its plain-language explanation."""

    level: str
    message: str


def _character_classes(password: str) -> int:
    classes = 0
    if any(c in string.ascii_lowercase for c in password):
        classes += 1
    if any(c in string.ascii_uppercase for c in password):
        classes += 1
    if any(c in string.digits for c in password):
        classes += 1
    if any(
        c not in string.ascii_letters and c not in string.digits
        for c in password
    ):
        classes += 1
    return classes


def password_feedback(password: str) -> PasswordFeedback:
    """Rate ``password`` and explain the rating in plain language."""
    if not isinstance(password, str):
        raise TypeError("A password must be text.")
    length = len(password)
    if length < MIN_PASSWORD_LENGTH:
        level = "too short"
        return PasswordFeedback(level=level, message=_MESSAGES[level])

    length_points = sum(
        1 for threshold in (8, 12, 16, 20) if length >= threshold
    )
    score = length_points + max(0, _character_classes(password) - 1)
    if score <= 1:
        level = "weak"
    elif score <= 3:
        level = "fair"
    elif score <= 5:
        level = "good"
    else:
        level = "strong"
    return PasswordFeedback(level=level, message=_MESSAGES[level])
