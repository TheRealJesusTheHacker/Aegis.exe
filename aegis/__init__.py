"""AEGIS.EXE — Sentinel Safeguard LLC file encryption & password manager.

It does not open. Aegis seals files, folders, and every login you
own behind one master password — AES-256 vaults, Argon2id key
derivation, local-first, no forced cloud, and no backdoor for
anyone, including us.
"""

from . import errors
from .armor import (
    ARMOR_PASSWORD_NOTE,
    ARMOR_SUFFIX,
    ArmorFileInfo,
    ArmorManifest,
    armor_manifest,
    seal_tree,
    unseal_tree,
)
from .clipboard import (
    DEFAULT_CLEAR_AFTER_SECONDS,
    AutoClearClipboard,
    MemoryClipboard,
)
from .credentials import STORE_ENTRY_NAME, CredentialEntry, CredentialStore, CredentialSummary
from .errors import (
    AegisError,
    ArmorRefusalError,
    CredentialNotFoundError,
    DocumentTooLargeError,
    EntryNotFoundError,
    InvalidCredentialError,
    InvalidEntryNameError,
    InvalidStrongboxEntryError,
    PasswordStoreDamagedError,
    SealedExistsError,
    SealedFormatError,
    SealedSaveError,
    SealedSourceError,
    SealedTamperedError,
    StrongboxDamagedError,
    StrongboxNotFoundError,
    UnlockError,
    VaultChangedOnDiskError,
    VaultExistsError,
    VaultFormatError,
    VaultLockedError,
    VaultRolledBackError,
    VaultSaveError,
    VaultTamperedError,
    WeakPasswordError,
    WrongFilePasswordError,
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
from .locksend import (
    DEFAULT_SEALED_NAME,
    LOCK_AND_SEND_PASSWORD_NOTE,
    SEALED_FILE_SUFFIX,
    open_sealed_file,
    read_sealed_file,
    seal_file,
)
from .passwords import MIN_PASSWORD_LENGTH, PasswordFeedback, password_feedback
from .recovery import (
    RECOVERY_KEY_BYTES,
    format_recovery_key,
    generate_recovery_key,
    recovery_key_to_bytes,
)
from .sealed import ARMOR_MAGIC, SEND_MAGIC
from .setup import (
    MASTER_PASSWORD_WARNING,
    RECOVERY_KEY_GUIDANCE,
    printable_recovery_sheet,
)
from .strongbox import (
    KIND_CODE,
    KIND_DOCUMENT,
    KIND_KEY,
    KIND_LABELS,
    KIND_NOTE,
    MAX_DOCUMENT_BYTES,
    STRONGBOX_ENTRY_NAME,
    Strongbox,
    StrongboxEntry,
    StrongboxSummary,
)
from .transfer import export_sealed_copy, import_from_vault
from .vault import CreatedVault, Vault, VaultSession

__version__ = "1.0.6"

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
    "VaultRolledBackError",
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
    "STRONGBOX_ENTRY_NAME",
    "MAX_DOCUMENT_BYTES",
    "KIND_CODE",
    "KIND_KEY",
    "KIND_NOTE",
    "KIND_DOCUMENT",
    "KIND_LABELS",
    "Strongbox",
    "StrongboxEntry",
    "StrongboxSummary",
    "SEALED_FILE_SUFFIX",
    "DEFAULT_SEALED_NAME",
    "LOCK_AND_SEND_PASSWORD_NOTE",
    "seal_file",
    "read_sealed_file",
    "open_sealed_file",
    "ARMOR_SUFFIX",
    "ARMOR_PASSWORD_NOTE",
    "ArmorFileInfo",
    "ArmorManifest",
    "armor_manifest",
    "seal_tree",
    "unseal_tree",
    "SEND_MAGIC",
    "ARMOR_MAGIC",
    "ArmorRefusalError",
    "DocumentTooLargeError",
    "InvalidStrongboxEntryError",
    "StrongboxDamagedError",
    "StrongboxNotFoundError",
    "WrongFilePasswordError",
    "SealedFormatError",
    "SealedTamperedError",
    "SealedExistsError",
    "SealedSaveError",
    "SealedSourceError",
]
