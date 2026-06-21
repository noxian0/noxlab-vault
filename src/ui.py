import getpass
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

from archive_utils import (
    ArchiveError,
    create_zip_archive,
    extract_zip_archive,
    list_archive_conflicts,
    validate_zip_bytes,
)
from crypto import CryptoConfigurationError, WrongPasswordOrCorruptVault, decrypt_vault_data, encrypt_archive_data


APP_NAME = "NOXLAB VAULT"
VAULT_EXTENSION = ".noxvault"

RED = "\033[31m"
BRIGHT_RED = "\033[91m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


ASCII_HEADER = r"""
 _   _  ___  __  __ _      _    ____     __     ___    _   _ _  _____
| \ | |/ _ \ \ \/ /| |    / \  | __ )    \ \   / / \  | | | | ||_   _|
|  \| | | | | \  / | |   / _ \ |  _ \     \ \ / / _ \ | | | | |  | |
| |\  | |_| | /  \ | |__/ ___ \| |_) |     \ V / ___ \| |_| | |__| |
|_| \_|\___/ /_/\_\|____/_/   \_\____/      \_/_/   \_\\___/|____|_|
"""


class ActivityLog:
    def __init__(self) -> None:
        self._lines: list[str] = []

    def add(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"{timestamp} - {message}"
        self._lines.append(line)
        print(f"{DIM}[activity] {message}{RESET}")

    def show_recent(self) -> None:
        if not self._lines:
            return
        print(f"\n{BOLD}Activity Log{RESET}")
        for line in self._lines[-8:]:
            print(f"  {line}")


def run_app() -> None:
    _enable_windows_ansi()
    activity_log = ActivityLog()

    while True:
        _print_header()
        activity_log.show_recent()
        _print_menu()
        choice = input("Select option: ").strip()

        try:
            if choice == "1":
                create_vault_flow(activity_log)
            elif choice == "2":
                open_vault_flow(activity_log)
            elif choice == "3":
                verify_vault_flow(activity_log)
            elif choice == "4":
                show_security_notes()
            elif choice == "0":
                print("Exit.")
                return
            else:
                print("Unknown option.")
        except KeyboardInterrupt:
            print("\nCancelled.")

        _pause()


def create_vault_flow(activity_log: ActivityLog) -> None:
    print_panel("Create Vault")
    input_paths = _ask_input_paths()
    vault_path = _ask_save_vault_path()
    password = _ask_new_password()

    print(f"\n{BRIGHT_RED}If you forget this password, the vault cannot be recovered.{RESET}")
    if not _confirm("Create encrypted vault now?", default=False):
        print("Cancelled.")
        return

    temp_dir: Path | None = None
    try:
        temp_dir = Path(tempfile.mkdtemp(prefix="noxvault_create_"))
        archive_path = temp_dir / "payload.zip"

        print("Creating temporary archive...")
        stats = create_zip_archive(input_paths, archive_path)

        archive_data = archive_path.read_bytes()
        print("Encrypting archive with AES-256-GCM...")
        vault_data = encrypt_archive_data(archive_data, password)
        del archive_data

        _delete_file_quietly(archive_path)
        vault_path.parent.mkdir(parents=True, exist_ok=True)
        vault_path.write_bytes(vault_data)

        activity_log.add("vault created")
        print(
            f"Vault created. Protected {stats.files} file(s) and "
            f"{stats.directories} folder entry/entries."
        )
    except (ArchiveError, OSError, ValueError) as exc:
        print(f"Create failed: {exc}")
    except CryptoConfigurationError as exc:
        print(f"Crypto setup error: {exc}")
    finally:
        _cleanup_temp_dir(temp_dir, activity_log)
        password = ""


def open_vault_flow(activity_log: ActivityLog) -> None:
    print_panel("Open / Extract Vault")
    vault_path = _ask_existing_file("Vault file", expected_suffix=VAULT_EXTENSION)
    password = getpass.getpass("Password: ")
    output_dir = _ask_output_folder()

    temp_dir: Path | None = None
    try:
        vault_data = vault_path.read_bytes()
        print("Decrypting vault...")
        archive_data = decrypt_vault_data(vault_data, password)
        validate_zip_bytes(archive_data)

        temp_dir = Path(tempfile.mkdtemp(prefix="noxvault_extract_"))
        archive_path = temp_dir / "payload.zip"
        archive_path.write_bytes(archive_data)
        del archive_data

        conflicts = list_archive_conflicts(archive_path, output_dir)
        overwrite = False
        if conflicts:
            print(
                f"Warning: extraction would overwrite {len(conflicts)} existing "
                "file or folder path(s)."
            )
            overwrite = _confirm("Overwrite existing paths?", default=False)
            if not overwrite:
                print("Extraction cancelled before writing files.")
                return

        stats = extract_zip_archive(archive_path, output_dir, overwrite=overwrite)
        activity_log.add("vault opened")
        print(f"Vault extracted. Restored {stats.files} file(s).")
    except WrongPasswordOrCorruptVault:
        activity_log.add("wrong password/corrupt vault")
        print("Wrong password or corrupted vault.")
    except CryptoConfigurationError as exc:
        print(f"Crypto setup error: {exc}")
    except (ArchiveError, OSError) as exc:
        print(f"Open failed: {exc}")
    finally:
        _cleanup_temp_dir(temp_dir, activity_log)
        password = ""


def verify_vault_flow(activity_log: ActivityLog) -> None:
    print_panel("Verify Vault")
    vault_path = _ask_existing_file("Vault file", expected_suffix=VAULT_EXTENSION)
    password = getpass.getpass("Password: ")

    try:
        vault_data = vault_path.read_bytes()
        print("Verifying vault...")
        archive_data = decrypt_vault_data(vault_data, password)
        validate_zip_bytes(archive_data)
        activity_log.add("vault verified")
        print("Vault verified successfully. No files were extracted.")
    except WrongPasswordOrCorruptVault:
        activity_log.add("wrong password/corrupt vault")
        print("Wrong password or corrupted vault.")
    except CryptoConfigurationError as exc:
        print(f"Crypto setup error: {exc}")
    except (ArchiveError, OSError) as exc:
        print(f"Verify failed: {exc}")
    finally:
        password = ""


def show_security_notes() -> None:
    print_panel("About / Security Notes")
    print(
        "NOXLAB VAULT is local only. Nothing is uploaded.\n"
        "Vault data is encrypted with AES-256-GCM.\n"
        "Argon2id is used for password key derivation when available.\n"
        "PBKDF2-HMAC-SHA256 is used as a fallback.\n"
        "The password is required to unlock the vault.\n"
        "Forgotten passwords cannot be recovered.\n"
        "Weak passwords can be guessed.\n"
        "Malware on this PC can still access files while they are unlocked.\n"
        "Do not store the password next to the vault file."
    )


def print_panel(title: str) -> None:
    print(f"\n{BRIGHT_RED}{BOLD}== {title} =={RESET}")


def evaluate_password_strength(password: str) -> tuple[str, list[str]]:
    warnings: list[str] = []
    score = 0

    if len(password) >= 16:
        score += 3
    elif len(password) >= 12:
        score += 2
    else:
        warnings.append("Use at least 12 characters. A long passphrase is better.")

    categories = [
        any(char.islower() for char in password),
        any(char.isupper() for char in password),
        any(char.isdigit() for char in password),
        any(not char.isalnum() for char in password),
    ]
    score += sum(categories)

    if len(password) < 16:
        warnings.append("16+ characters or a long passphrase is recommended.")
    if sum(categories) < 3:
        warnings.append("Mix character types or use several random words.")
    if password.lower() in {"password", "password123", "noxlab", "noxlabvault"}:
        warnings.append("This password is too easy to guess.")

    if score >= 6 and len(password) >= 16:
        return "strong", warnings
    if score >= 4 and len(password) >= 12:
        return "usable", warnings
    return "weak", warnings


def _ask_input_paths() -> list[Path]:
    print("Enter one file or folder path per line. Press Enter on a blank line when done.")
    paths: list[Path] = []

    while True:
        raw_value = input("Path: ").strip()
        if raw_value == "":
            break

        path = Path(_strip_quotes(raw_value)).expanduser()
        if not path.exists():
            print("Path does not exist.")
            continue
        paths.append(path)

    if not paths:
        raise ArchiveError("No files or folders were selected.")
    return paths


def _ask_save_vault_path() -> Path:
    while True:
        raw_value = input(f"Save vault as ({VAULT_EXTENSION}): ").strip()
        if raw_value == "":
            print("Save path is required.")
            continue

        path = Path(_strip_quotes(raw_value)).expanduser()
        if path.suffix.lower() != VAULT_EXTENSION:
            path = path.with_suffix(VAULT_EXTENSION)

        if path.exists() and not _confirm("Vault file exists. Overwrite it?", default=False):
            continue

        return path.resolve()


def _ask_existing_file(label: str, *, expected_suffix: str | None = None) -> Path:
    while True:
        raw_value = input(f"{label}: ").strip()
        path = Path(_strip_quotes(raw_value)).expanduser()

        if not path.is_file():
            print("File does not exist.")
            continue

        if expected_suffix and path.suffix.lower() != expected_suffix:
            print(f"Expected a {expected_suffix} file.")
            continue

        return path.resolve()


def _ask_output_folder() -> Path:
    while True:
        raw_value = input("Output folder: ").strip()
        if raw_value == "":
            print("Output folder is required.")
            continue
        return Path(_strip_quotes(raw_value)).expanduser().resolve()


def _ask_new_password() -> str:
    while True:
        password = getpass.getpass("Password: ")
        confirmation = getpass.getpass("Confirm password: ")

        if password != confirmation:
            print("Passwords do not match.")
            continue
        if password == "":
            print("Password must not be empty.")
            continue

        strength, warnings = evaluate_password_strength(password)
        print(f"Password strength: {strength}")
        for warning in warnings:
            print(f"- {warning}")

        if strength == "weak":
            print(f"{BRIGHT_RED}Weak passwords reduce vault security.{RESET}")
            if not _confirm("Continue with this weak password?", default=False):
                continue

        return password


def _confirm(prompt: str, *, default: bool) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        answer = input(f"{prompt} {suffix}: ").strip().lower()
        if answer == "":
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Please answer yes or no.")


def _cleanup_temp_dir(temp_dir: Path | None, activity_log: ActivityLog) -> None:
    if temp_dir is None:
        return
    try:
        shutil.rmtree(temp_dir)
        activity_log.add("temporary files cleaned")
    except OSError:
        print(f"Warning: temporary files could not be cleaned: {temp_dir}")


def _delete_file_quietly(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _strip_quotes(value: str) -> str:
    return value.strip().strip('"').strip("'")


def _print_header() -> None:
    print(f"{BRIGHT_RED}{ASCII_HEADER}{RESET}")
    print(f"{BRIGHT_RED}{BOLD}{APP_NAME}{RESET}")
    print(f"{RED}Discord: noxian_ | GitHub: noxian0{RESET}")
    print(f"{BRIGHT_RED}If you forget your password, the vault cannot be recovered.{RESET}")


def _print_menu() -> None:
    print(
        "\n"
        "1. Create New Vault\n"
        "2. Open / Extract Vault\n"
        "3. Verify Vault\n"
        "4. Security Notes\n"
        "0. Exit"
    )


def _pause() -> None:
    input("\nPress Enter to continue...")


def _enable_windows_ansi() -> None:
    if os.name != "nt":
        return
    os.system("")
