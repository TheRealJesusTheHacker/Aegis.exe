"""Key derivation parameters and derivation for Aegis vaults.

Aegis uses Argon2id (via the vetted ``argon2-cffi`` library) to turn
a master password or a recovery key into the key-encryption key that
wraps the vault key. Parameters are stored in each vault's header so
future versions can raise them without breaking older vaults.

On open, parameters read from a header are validated *before* any
derivation runs: the floors keep a tampered header from silently
weakening a vault, and the ceilings bound what a hostile header
can demand. The bound is finite, not small: a header sitting
exactly at the ceilings (1 GiB of memory, 10 passes, 16 lanes)
is accepted and derived, so opening a hostile file someone was
induced to try can cost up to about a gigabyte of memory and
many seconds — anything beyond the ceilings is refused before
any derivation runs. The real tamper defense is the
authenticated sealing itself — altered parameters derive a different
key and the unwrap simply fails.
"""

from __future__ import annotations

from dataclasses import dataclass

import argon2.low_level

from .errors import VaultFormatError

__all__ = ["KdfParams", "DEFAULT_PARAMS", "derive_key", "validate_params"]

# Parameter policy (floors and ceilings enforced on open).
MIN_MEMORY_KIB = 8192
MAX_MEMORY_KIB = 1048576  # 1 GiB
MIN_TIME_COST = 1
MAX_TIME_COST = 10
MIN_PARALLELISM = 1
MAX_PARALLELISM = 16
SALT_BYTES = 16
KEY_BYTES = 32


@dataclass(frozen=True)
class KdfParams:
    """Argon2id parameters for one vault."""

    memory_kib: int
    time_cost: int
    parallelism: int
    hash_len: int = KEY_BYTES


# RFC 9106 first recommended profile: 64 MiB, 3 passes, 4 lanes.
DEFAULT_PARAMS = KdfParams(memory_kib=65536, time_cost=3, parallelism=4)


def validate_params(params: KdfParams) -> None:
    """Check ``params`` against the floor/ceiling policy.

    Raises:
        VaultFormatError: if any field is not an int or is out of range.
    """
    if not isinstance(params, KdfParams):
        raise VaultFormatError()
    for value in (
        params.memory_kib,
        params.time_cost,
        params.parallelism,
        params.hash_len,
    ):
        # bool is a subclass of int; reject it explicitly.
        if type(value) is not int:
            raise VaultFormatError()
    if not MIN_MEMORY_KIB <= params.memory_kib <= MAX_MEMORY_KIB:
        raise VaultFormatError()
    if not MIN_TIME_COST <= params.time_cost <= MAX_TIME_COST:
        raise VaultFormatError()
    if not MIN_PARALLELISM <= params.parallelism <= MAX_PARALLELISM:
        raise VaultFormatError()
    if params.hash_len != KEY_BYTES:
        raise VaultFormatError()


def derive_key(secret: bytes, salt: bytes, params: KdfParams) -> bytes:
    """Derive a key-encryption key from ``secret`` using Argon2id.

    Args:
        secret: The raw secret bytes (a UTF-8 password, or the raw
            recovery-key bytes).
        salt: The per-vault, per-credential salt (at least 16 bytes).
        params: The vault's stored KDF parameters.

    Returns:
        ``params.hash_len`` bytes of derived key material.
    """
    validate_params(params)
    if len(salt) < SALT_BYTES:
        raise VaultFormatError()
    return argon2.low_level.hash_secret_raw(
        secret=bytes(secret),
        salt=bytes(salt),
        time_cost=params.time_cost,
        memory_cost=params.memory_kib,
        parallelism=params.parallelism,
        hash_len=params.hash_len,
        type=argon2.low_level.Type.ID,
    )
