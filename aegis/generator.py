"""The password generator: strong passwords, made the easy choice.

Every choice here comes from :mod:`secrets` — the operating
system's cryptographic random source, through Python's vetted
wrapper for exactly this job. Nothing is seeded, nothing is
predictable, and a generated password is never logged, printed, or
stored anywhere except the saved login the person chooses to keep.

Controls are plain: a length, and switches for the kinds of
character to include. The defaults (20 characters, every kind on)
are set so the easiest choice is already a strong one. Whatever
kinds are switched on are guaranteed to appear at least once, so a
short password with symbols on really does contain a symbol.
"""

from __future__ import annotations

import string
from secrets import choice as _secure_choice
from secrets import randbelow as _secure_randbelow

__all__ = [
    "DEFAULT_GENERATED_LENGTH",
    "MIN_GENERATED_LENGTH",
    "MAX_GENERATED_LENGTH",
    "generate_password",
]

DEFAULT_GENERATED_LENGTH = 20
MIN_GENERATED_LENGTH = 8
MAX_GENERATED_LENGTH = 256

_LOWER = string.ascii_lowercase
_UPPER = string.ascii_uppercase
_DIGITS = string.digits
# A conservative symbol set: strong, and safe to paste anywhere —
# no quotes, no backslash, no space, nothing a shell or a form
# field is likely to mangle.
_SYMBOLS = "!@#$%^&*()-_=+[]{}<>?"


def generate_password(
    length=DEFAULT_GENERATED_LENGTH,
    *,
    use_lowercase=True,
    use_uppercase=True,
    use_digits=True,
    use_symbols=True,
) -> str:
    """Generate one strong password.

    Raises:
        ValueError: if the length is outside the accepted range,
            or if every kind of character is switched off.
    """
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("A length must be a whole number.")
    if length < MIN_GENERATED_LENGTH or length > MAX_GENERATED_LENGTH:
        raise ValueError(
            "Pick a length between %d and %d characters."
            % (MIN_GENERATED_LENGTH, MAX_GENERATED_LENGTH)
        )
    pools = []
    if use_lowercase:
        pools.append(_LOWER)
    if use_uppercase:
        pools.append(_UPPER)
    if use_digits:
        pools.append(_DIGITS)
    if use_symbols:
        pools.append(_SYMBOLS)
    if not pools:
        raise ValueError(
            "Pick at least one kind of character to make a password from."
        )
    if length < len(pools):
        raise ValueError(
            "That length is too short to fit every kind of character "
            "you picked."
        )

    alphabet = "".join(pools)
    # One guaranteed character from each chosen kind, then the rest
    # from the whole alphabet, then a secure shuffle so the
    # guaranteed characters land anywhere.
    chars = [_secure_choice(pool) for pool in pools]
    chars.extend(
        _secure_choice(alphabet) for _ in range(length - len(chars))
    )
    for i in range(len(chars) - 1, 0, -1):
        j = _secure_randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)
