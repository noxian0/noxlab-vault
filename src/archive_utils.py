import io
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence


@dataclass(frozen=True)
class ArchiveStats:
    files: int
    directories: int
    bytes_total: int


class ArchiveError(Exception):
    """Raised when creating, validating, or extracting the plaintext archive fails."""


def create_zip_archive(input_paths: Sequence[Path], archive_path: Path) -> ArchiveStats:
    paths = [Path(path).expanduser().resolve() for path in input_paths]
    if not paths:
        raise ArchiveError("No files or folders were selected.")

    for path in paths:
        if not path.exists():
            raise ArchiveError("One or more selected paths do not exist.")

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    used_top_names: set[str] = set()
    files = 0
    directories = 0
    bytes_total = 0

    with zipfile.ZipFile(
        archive_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as zip_file:
        for source in paths:
            top_name = _reserve_top_name(source.name, used_top_names)

            if source.is_file():
                zip_file.write(source, _to_zip_name([top_name]))
                files += 1
                bytes_total += source.stat().st_size
                continue

            if source.is_dir():
                directories += 1
                _add_directory_entry(zip_file, top_name)
                for item in source.rglob("*"):
                    if item == archive_path:
                        continue

                    relative = item.relative_to(source)
                    zip_name = _to_zip_name([top_name, *relative.parts])

                    if item.is_dir():
                        directories += 1
                        _add_directory_entry(zip_file, zip_name)
                    elif item.is_file():
                        zip_file.write(item, zip_name)
                        files += 1
                        bytes_total += item.stat().st_size

    if files == 0 and directories == 0:
        raise ArchiveError("Selected folders did not contain any files or directories.")

    return ArchiveStats(files=files, directories=directories, bytes_total=bytes_total)


def create_zip_from_directory_contents(source_dir: Path, archive_path: Path) -> ArchiveStats:
    source = source_dir.expanduser().resolve()
    if not source.is_dir():
        raise ArchiveError("Workspace folder does not exist.")

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    files = 0
    directories = 0
    bytes_total = 0

    with zipfile.ZipFile(
        archive_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as zip_file:
        for item in sorted(source.rglob("*"), key=lambda path: path.relative_to(source).as_posix().lower()):
            if item == archive_path:
                continue

            relative = item.relative_to(source)
            zip_name = _to_zip_name(relative.parts)

            if item.is_dir():
                directories += 1
                _add_directory_entry(zip_file, zip_name)
            elif item.is_file():
                zip_file.write(item, zip_name)
                files += 1
                bytes_total += item.stat().st_size

    return ArchiveStats(files=files, directories=directories, bytes_total=bytes_total)


def validate_zip_bytes(archive_data: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(archive_data), mode="r") as zip_file:
            bad_member = zip_file.testzip()
            if bad_member is not None:
                raise ArchiveError("Decrypted archive integrity check failed.")
    except zipfile.BadZipFile as exc:
        raise ArchiveError("Decrypted data is not a valid archive.") from exc


def list_archive_conflicts(archive_path: Path, output_dir: Path) -> list[Path]:
    output_base = output_dir.expanduser().resolve()
    conflicts: list[Path] = []

    with zipfile.ZipFile(archive_path, mode="r") as zip_file:
        for member in zip_file.infolist():
            target = _safe_member_target(output_base, member.filename)
            if target.exists():
                conflicts.append(target)

    return conflicts


def extract_zip_archive(archive_path: Path, output_dir: Path, *, overwrite: bool = False) -> ArchiveStats:
    output_base = output_dir.expanduser().resolve()
    output_base.mkdir(parents=True, exist_ok=True)

    files = 0
    directories = 0
    bytes_total = 0

    with zipfile.ZipFile(archive_path, mode="r") as zip_file:
        for member in zip_file.infolist():
            target = _safe_member_target(output_base, member.filename)

            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                directories += 1
                continue

            if target.exists() and not overwrite:
                raise ArchiveError("Extraction would overwrite existing files.")

            target.parent.mkdir(parents=True, exist_ok=True)
            with zip_file.open(member, mode="r") as source, target.open("wb") as destination:
                shutil.copyfileobj(source, destination)

            files += 1
            bytes_total += member.file_size

    return ArchiveStats(files=files, directories=directories, bytes_total=bytes_total)


def _reserve_top_name(name: str, used_names: set[str]) -> str:
    safe_name = name.strip() or "selected"
    candidate = safe_name
    counter = 2

    while candidate.lower() in used_names:
        path = Path(safe_name)
        suffix = path.suffix
        stem = path.stem if suffix else safe_name
        candidate = f"{stem}_{counter}{suffix}"
        counter += 1

    used_names.add(candidate.lower())
    return candidate


def _add_directory_entry(zip_file: zipfile.ZipFile, zip_name: str) -> None:
    name = zip_name if zip_name.endswith("/") else f"{zip_name}/"
    zip_file.writestr(name, b"")


def _to_zip_name(parts: Iterable[str]) -> str:
    return PurePosixPath(*parts).as_posix()


def _safe_member_target(output_base: Path, member_name: str) -> Path:
    if not member_name or "\\" in member_name:
        raise ArchiveError("Archive contains an unsafe path.")

    pure_path = PurePosixPath(member_name)
    if pure_path.is_absolute():
        raise ArchiveError("Archive contains an absolute path.")

    parts = pure_path.parts
    if any(part in {"", ".", ".."} for part in parts):
        raise ArchiveError("Archive contains a parent-directory reference.")
    if any(":" in part for part in parts):
        raise ArchiveError("Archive contains a Windows drive reference.")

    target = output_base.joinpath(*parts).resolve()
    if not _is_relative_to(target, output_base):
        raise ArchiveError("Archive contains a path outside the output folder.")

    return target


def _is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False
