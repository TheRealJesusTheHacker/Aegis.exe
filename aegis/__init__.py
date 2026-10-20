"""AEGIS.EXE — Sentinel Safeguard LLC file encryption & password manager.

It does not open. Aegis seals files, folders, and every login you
own behind one master password — AES-256 vaults, Argon2id key
derivation, local-first, no forced cloud, and no backdoor for
anyone, including us.
"""

from . import errors
from .clipboard import (
    DEFAULT_CLEAR_AFTER_SECONDS,
    AutoClearClipboard,
    MemoryClipboard,
)
from .credentials import STORE_ENTRY_NAME, CredentialEntry, CredentialStore, CredentialSummary
from .errors import (
    AegisError,
    CredentialNotFoundError,
    EntryNotFoundError,
    InvalidCredentialError,
    InvalidEntryNameError,
    PasswordStoreDamagedError,
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
from .generator import (
    DEFAULT_GENERATED_LENGTH,
    MAX_GENERATED_LENGTH,
    MIN_GENERATED_LENGTH,
    generate_password,
)
from .idle import DEFAULT_IDLE_SECONDS, IdleGuard
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
from .transfer import export_sealed_copy, import_from_vault
from .vault import CreatedVault, Vault, VaultSession

__version__ = "0.3.0"

__all__ = [
    "__version__",
    "errors",
    "AegisError",
    "CredentialNotFoundError",
    "EntryNotFoundError",
    "InvalidCredentialError",
    "InvalidEntryNameError",
    "PasswordStoreDamagedError",
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
    "STORE_ENTRY_NAME",
    "CredentialEntry",
    "CredentialStore",
    "CredentialSummary",
    "DEFAULT_GENERATED_LENGTH",
    "MAX_GENERATED_LENGTH",
    "MIN_GENERATED_LENGTH",
    "generate_password",
    "DEFAULT_CLEAR_AFTER_SECONDS",
    "AutoClearClipboard",
    "MemoryClipboard",
    "DEFAULT_IDLE_SECONDS",
    "IdleGuard",
    "export_sealed_copy",
    "import_from_vault",
]
