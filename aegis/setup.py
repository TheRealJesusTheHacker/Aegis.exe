"""The words Aegis says at setup, kept in one place.

These texts are shown before a person stores anything in a vault:
the warning about losing a master password, the guidance that goes
with the recovery key, and the printable sheet the key is printed
on. They are written in plain language on purpose, and the wording
here is the wording the interface shows — reviewed like code.
"""

__all__ = [
    "MASTER_PASSWORD_WARNING",
    "RECOVERY_KEY_GUIDANCE",
    "printable_recovery_sheet",
]

MASTER_PASSWORD_WARNING = (
    "Before you store anything, read this.\n"
    "\n"
    "If you lose your master password, nobody can open your vault. "
    "Not Sentinel, not a support line, not anyone. There is no back "
    "door and no reset — that is what makes Aegis a shield.\n"
    "\n"
    "Your recovery key is the one way back in. Print it, and keep "
    "the printed copy somewhere safe."
)

RECOVERY_KEY_GUIDANCE = (
    "This is your recovery key — the only way back into your vault "
    "if you forget your master password. Print this page now and "
    "keep it somewhere physically safe: a locked drawer, a safe, "
    "with your important papers. Anyone who finds this key can open "
    "your vault, so don't save it in a photo, an email, or a note "
    "on this computer."
)

_SIGN_OFF = "It does not open — for anyone but you."


def printable_recovery_sheet(vault_name: str, recovery_key: str) -> str:
    """Build the plain-text sheet a recovery key is printed on.

    The sheet carries the vault name, a recap of the master password
    warning, the key itself in its large grouped display form, the
    guidance for keeping it, and the sign-off line.
    """
    lines = [
        "AEGIS.EXE",
        "Recovery Key Sheet",
        "",
        "Vault: %s" % vault_name,
        "",
        MASTER_PASSWORD_WARNING,
        "",
        "Your recovery key:",
        "",
        recovery_key,
        "",
        RECOVERY_KEY_GUIDANCE,
        "",
        _SIGN_OFF,
        "",
    ]
    return "\n".join(lines)
