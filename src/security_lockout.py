import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from vault_format import MAGIC, decode_vault


MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 5 * 60 * 60
STATE_VERSION = 1


@dataclass(frozen=True)
class LockoutStatus:
    blocked: bool
    failed_attempts: int
    attempts_remaining: int
    blocked_until: float | None


def vault_lockout_id(vault_data: bytes) -> str:
    try:
        payload = decode_vault(vault_data)
        identity_material = MAGIC + payload.metadata_bytes
    except Exception:
        identity_material = vault_data[:4096]

    return hashlib.sha256(b"noxvault-lockout-v1:" + identity_material).hexdigest()


def check_lockout(vault_id: str) -> LockoutStatus:
    state = _load_state()
    entry = _vaults(state).get(vault_id, {})
    status = _status_from_entry(entry)

    if entry and not status.blocked and status.failed_attempts <= 0:
        _vaults(state).pop(vault_id, None)
        _save_state(state)

    return status


def record_failure(vault_id: str) -> LockoutStatus:
    state = _load_state()
    vaults = _vaults(state)
    entry = vaults.get(vault_id, {})
    current = _status_from_entry(entry)

    if current.blocked:
        return current

    failed_attempts = current.failed_attempts + 1
    blocked_until = None
    if failed_attempts >= MAX_FAILED_ATTEMPTS:
        failed_attempts = MAX_FAILED_ATTEMPTS
        blocked_until = _now() + LOCKOUT_SECONDS

    vaults[vault_id] = {
        "failed_attempts": failed_attempts,
        "blocked_until": blocked_until,
    }
    _save_state(state)
    return _status_from_entry(vaults[vault_id])


def record_success(vault_id: str) -> None:
    state = _load_state()
    vaults = _vaults(state)
    if vault_id in vaults:
        vaults.pop(vault_id, None)
        _save_state(state)


def format_blocked_until(timestamp: float | None) -> str:
    if timestamp is None:
        return "unknown time"
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")


def _status_from_entry(entry: dict[str, Any]) -> LockoutStatus:
    now = _now()
    failed_attempts = int(entry.get("failed_attempts", 0) or 0)
    blocked_until = entry.get("blocked_until")

    if isinstance(blocked_until, (int, float)) and blocked_until > now:
        return LockoutStatus(
            blocked=True,
            failed_attempts=min(failed_attempts, MAX_FAILED_ATTEMPTS),
            attempts_remaining=0,
            blocked_until=float(blocked_until),
        )

    if isinstance(blocked_until, (int, float)) and blocked_until <= now:
        failed_attempts = 0
        blocked_until = None

    failed_attempts = max(0, min(failed_attempts, MAX_FAILED_ATTEMPTS))
    return LockoutStatus(
        blocked=False,
        failed_attempts=failed_attempts,
        attempts_remaining=max(0, MAX_FAILED_ATTEMPTS - failed_attempts),
        blocked_until=None,
    )


def _load_state() -> dict[str, Any]:
    path = _state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"version": STATE_VERSION, "vaults": {}}
    except Exception:
        return {"version": STATE_VERSION, "vaults": {}}

    if not isinstance(data, dict):
        return {"version": STATE_VERSION, "vaults": {}}
    if not isinstance(data.get("vaults"), dict):
        data["vaults"] = {}
    data["version"] = STATE_VERSION
    return data


def _save_state(state: dict[str, Any]) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(prefix="security_state_", suffix=".tmp", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True, separators=(",", ":"))
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def _state_path() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "NOXLAB VAULT" / "security_state.json"
    return Path.home() / ".noxlab_vault" / "security_state.json"


def _vaults(state: dict[str, Any]) -> dict[str, Any]:
    vaults = state.setdefault("vaults", {})
    if not isinstance(vaults, dict):
        state["vaults"] = {}
    return state["vaults"]


def _now() -> float:
    return time.time()
