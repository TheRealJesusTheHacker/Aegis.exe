"""AEGIS.EXE — Sentinel Safeguard LLC file encryption & password manager.

It does not open. Aegis seals files, folders, and every login you
own behind one master password — AES-256 vaults, Argon2id key
derivation, local-first, no forced cloud, and no backdoor for
anyone, including us.
"""

from . import errors
from .errors import (
    AegisError,
    EntryNotFoundError,
    InvalidEntryNameError,
    UnlockError,
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
from .kdf import DEFAULT_PARAMS, KdfParams
from .passwords import MIN_PASSWORD_LENGTH, PasswordFeedback, password_feedback
from .recovery import (
    RECOVERY_KEY_BYTES,
    format_recovery_key,
    generate_recovery_key,
    recovery_key_to_bytes,
)
from .setup import (
    MASTER_PASSWORD_WARNING,
    RECOVERY_KEY_GUIDANCE,
    printable_recovery_sheet,
)
from .vault import CreatedVault, Vault, VaultSession

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "errors",
    "AegisError",
    "EntryNotFoundError",
    "InvalidEntryNameError",
    "UnlockError",
    "VaultChangedOnDiskError",
    "VaultExistsError",
    "VaultFormatError",
    "VaultLockedError",
    "VaultSaveError",
    "VaultTamperedError",
    "WeakPasswordError",
    "WrongPasswordError",
    "WrongRecoveryKeyError",
    "DEFAULT_PARAMS",
    "KdfParams",
    "MIN_PASSWORD_LENGTH",
    "PasswordFeedback",
    "password_feedback",
    "RECOVERY_KEY_BYTES",
    "format_recovery_key",
    "generate_recovery_key",
    "recovery_key_to_bytes",
    "MASTER_PASSWORD_WARNING",
    "RECOVERY_KEY_GUIDANCE",
    "printable_recovery_sheet",
    "CreatedVault",
    "Vault",
    "VaultSession",
]
