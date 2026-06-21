import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from vault_format import (
    KDF_ARGON2ID,
    KDF_PBKDF2_SHA256,
    VaultFormatError,
    b64decode_bytes,
    build_metadata,
    canonical_metadata_bytes,
    decode_vault,
    encode_vault,
)


try:
    from argon2.low_level import Type, hash_secret_raw

    ARGON2_AVAILABLE = True
except Exception:
    Type = None
    hash_secret_raw = None
    ARGON2_AVAILABLE = False


AES_KEY_BYTES = 32
SALT_BYTES = 32
AES_GCM_NONCE_BYTES = 12

ARGON2ID_DEFAULTS = {
    "time_cost": 3,
    "memory_cost_kib": 65536,
    "parallelism": 2,
    "hash_len": AES_KEY_BYTES,
}
ARGON2ID_LIMITS = {
    "time_cost": (1, 8),
    "memory_cost_kib": (19_456, 262_144),
    "parallelism": (1, 8),
}

PBKDF2_DEFAULTS = {
    "iterations": 600_000,
    "hash": "sha256",
    "length": AES_KEY_BYTES,
}
PBKDF2_ITERATION_LIMITS = (100_000, 5_000_000)


class CryptoConfigurationError(Exception):
    """Raised when a vault uses a KDF that is not available in this install."""


class WrongPasswordOrCorruptVault(Exception):
    """Raised when authentication fails or the vault cannot be safely decrypted."""


def default_kdf() -> tuple[str, dict[str, Any]]:
    if ARGON2_AVAILABLE:
        return KDF_ARGON2ID, dict(ARGON2ID_DEFAULTS)
    return KDF_PBKDF2_SHA256, dict(PBKDF2_DEFAULTS)


def derive_key(password: str, salt: bytes, kdf_type: str, kdf_params: dict[str, Any]) -> bytes:
    password_bytes = _password_to_bytes(password)

    if kdf_type == KDF_ARGON2ID:
        if not ARGON2_AVAILABLE:
            raise CryptoConfigurationError(
                "This vault uses Argon2id, but argon2-cffi is not installed."
            )

        hash_len = int(kdf_params.get("hash_len", AES_KEY_BYTES))
        if hash_len != AES_KEY_BYTES:
            raise VaultFormatError("Unsupported Argon2id key length.")

        time_cost = _bounded_int(
            kdf_params,
            "time_cost",
            ARGON2ID_DEFAULTS["time_cost"],
            *ARGON2ID_LIMITS["time_cost"],
        )
        memory_cost = _bounded_int(
            kdf_params,
            "memory_cost_kib",
            ARGON2ID_DEFAULTS["memory_cost_kib"],
            *ARGON2ID_LIMITS["memory_cost_kib"],
        )
        parallelism = _bounded_int(
            kdf_params,
            "parallelism",
            ARGON2ID_DEFAULTS["parallelism"],
            *ARGON2ID_LIMITS["parallelism"],
        )

        return hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=Type.ID,
        )

    if kdf_type == KDF_PBKDF2_SHA256:
        if kdf_params.get("hash", "sha256") != "sha256":
            raise VaultFormatError("Unsupported PBKDF2 hash.")

        length = int(kdf_params.get("length", AES_KEY_BYTES))
        if length != AES_KEY_BYTES:
            raise VaultFormatError("Unsupported PBKDF2 key length.")

        iterations = _bounded_int(
            kdf_params,
            "iterations",
            PBKDF2_DEFAULTS["iterations"],
            *PBKDF2_ITERATION_LIMITS,
        )

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(password_bytes)

    raise VaultFormatError("Unsupported KDF type.")


def encrypt_archive_data(archive_data: bytes, password: str) -> bytes:
    if not archive_data:
        raise ValueError("Archive data is empty.")

    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(AES_GCM_NONCE_BYTES)
    kdf_type, kdf_params = default_kdf()
    metadata = build_metadata(
        kdf_type=kdf_type,
        kdf_params=kdf_params,
        salt=salt,
        nonce=nonce,
    )

    # The exact metadata bytes are authenticated as AES-GCM associated data.
    metadata_bytes = canonical_metadata_bytes(metadata)

    key = derive_key(password, salt, kdf_type, kdf_params)
    ciphertext = AESGCM(key).encrypt(nonce, archive_data, metadata_bytes)
    return encode_vault(metadata, ciphertext)


def decrypt_vault_data(vault_data: bytes, password: str) -> bytes:
    try:
        payload = decode_vault(vault_data)
        metadata = payload.metadata
        salt = b64decode_bytes(metadata["salt"], "salt")
        nonce = b64decode_bytes(metadata["nonce"], "nonce")
        key = derive_key(password, salt, metadata["kdf"], metadata["kdf_params"])
        return AESGCM(key).decrypt(nonce, payload.ciphertext, payload.metadata_bytes)
    except CryptoConfigurationError:
        raise
    except (InvalidTag, VaultFormatError, ValueError, KeyError, TypeError) as exc:
        raise WrongPasswordOrCorruptVault("Wrong password or corrupted vault.") from exc


def _password_to_bytes(password: str) -> bytes:
    if not isinstance(password, str) or password == "":
        raise ValueError("Password must not be empty.")
    return password.encode("utf-8")


def _bounded_int(
    params: dict[str, Any],
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    try:
        value = int(params.get(name, default))
    except (TypeError, ValueError) as exc:
        raise VaultFormatError(f"Invalid KDF parameter: {name}.") from exc

    if value < minimum or value > maximum:
        raise VaultFormatError(f"Unsupported KDF parameter value: {name}.")
    return value
