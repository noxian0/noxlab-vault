import base64
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAGIC = b"NOXVAULT1"
VERSION = 1
MAX_METADATA_SIZE = 16 * 1024

KDF_ARGON2ID = "argon2id"
KDF_PBKDF2_SHA256 = "pbkdf2-hmac-sha256"
SUPPORTED_KDFS = {KDF_ARGON2ID, KDF_PBKDF2_SHA256}


class VaultFormatError(Exception):
    """Raised when a vault file cannot be parsed as a supported NOXLAB vault."""


@dataclass(frozen=True)
class VaultPayload:
    metadata: dict[str, Any]
    metadata_bytes: bytes
    ciphertext: bytes


def b64encode_bytes(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64decode_bytes(value: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise VaultFormatError(f"Invalid base64 value for {field_name}.") from exc


def canonical_metadata_bytes(metadata: dict[str, Any]) -> bytes:
    return json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_metadata(
    *,
    kdf_type: str,
    kdf_params: dict[str, Any],
    salt: bytes,
    nonce: bytes,
) -> dict[str, Any]:
    return {
        "version": VERSION,
        "kdf": kdf_type,
        "kdf_params": kdf_params,
        "salt": b64encode_bytes(salt),
        "nonce": b64encode_bytes(nonce),
    }


def validate_metadata(metadata: dict[str, Any]) -> None:
    if metadata.get("version") != VERSION:
        raise VaultFormatError("Unsupported vault version.")

    kdf_type = metadata.get("kdf")
    if kdf_type not in SUPPORTED_KDFS:
        raise VaultFormatError("Unsupported KDF type.")

    if not isinstance(metadata.get("kdf_params"), dict):
        raise VaultFormatError("Invalid KDF parameters.")

    salt = b64decode_bytes(_require_string(metadata, "salt"), "salt")
    nonce = b64decode_bytes(_require_string(metadata, "nonce"), "nonce")

    if len(salt) < 16:
        raise VaultFormatError("Invalid salt length.")
    if len(nonce) != 12:
        raise VaultFormatError("Invalid AES-GCM nonce length.")


def encode_vault(metadata: dict[str, Any], ciphertext: bytes) -> bytes:
    validate_metadata(metadata)
    metadata_bytes = canonical_metadata_bytes(metadata)

    if len(metadata_bytes) > MAX_METADATA_SIZE:
        raise VaultFormatError("Vault metadata is too large.")
    if not ciphertext:
        raise VaultFormatError("Vault ciphertext is empty.")

    return MAGIC + struct.pack(">I", len(metadata_bytes)) + metadata_bytes + ciphertext


def decode_vault(data: bytes) -> VaultPayload:
    header_size = len(MAGIC) + 4
    if len(data) < header_size:
        raise VaultFormatError("Vault file is too small.")

    if data[: len(MAGIC)] != MAGIC:
        raise VaultFormatError("Invalid vault magic header.")

    metadata_size = struct.unpack(">I", data[len(MAGIC) : header_size])[0]
    if metadata_size == 0 or metadata_size > MAX_METADATA_SIZE:
        raise VaultFormatError("Invalid vault metadata length.")

    metadata_start = header_size
    metadata_end = metadata_start + metadata_size
    if len(data) <= metadata_end:
        raise VaultFormatError("Vault file is missing encrypted data.")

    metadata_bytes = data[metadata_start:metadata_end]
    ciphertext = data[metadata_end:]

    try:
        metadata = json.loads(metadata_bytes.decode("utf-8"))
    except Exception as exc:
        raise VaultFormatError("Vault metadata is not valid JSON.") from exc

    if not isinstance(metadata, dict):
        raise VaultFormatError("Vault metadata must be an object.")

    validate_metadata(metadata)
    return VaultPayload(metadata=metadata, metadata_bytes=metadata_bytes, ciphertext=ciphertext)


def read_vault_file(path: Path) -> VaultPayload:
    return decode_vault(path.read_bytes())


def write_vault_file(path: Path, metadata: dict[str, Any], ciphertext: bytes) -> None:
    path.write_bytes(encode_vault(metadata, ciphertext))


def _require_string(metadata: dict[str, Any], key: str) -> str:
    value = metadata.get(key)
    if not isinstance(value, str):
        raise VaultFormatError(f"Missing or invalid {key}.")
    return value
