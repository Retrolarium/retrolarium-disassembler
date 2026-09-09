"""Acquire and verify pinned external disassembly tools."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import urllib.request
import zipfile


LOCK_PATH = Path(__file__).resolve().parent / "toolchains" / "disassembly.lock.json"


class ToolchainError(RuntimeError):
    """A toolchain archive or installation failed verification."""


def load_lock(path: Path = LOCK_PATH) -> dict[str, object]:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolchainError(f"cannot read disassembly lock: {exc}") from exc
    if lock.get("schema_version") != 1:
        raise ToolchainError("unsupported disassembly lock schema")
    return lock


def entry(lock: dict[str, object], key: str) -> dict[str, object]:
    value = lock.get(key)
    if not isinstance(value, dict):
        raise ToolchainError(f"disassembly lock has no {key} object")
    for field in ("archive", "url", "size", "sha256"):
        if field not in value:
            raise ToolchainError(f"{key} lock entry has no {field}")
    return value


def sha256_file(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def verify_archive(path: Path, expected: dict[str, object]) -> None:
    if not path.is_file():
        raise ToolchainError(f"archive not found: {path}")
    expected_size = int(expected["size"])
    if path.stat().st_size != expected_size:
        raise ToolchainError(
            f"{path.name} size is {path.stat().st_size}, expected {expected_size}"
        )
    actual = sha256_file(path)
    wanted = str(expected["sha256"]).lower()
    if actual != wanted:
        raise ToolchainError(f"{path.name} SHA-256 is {actual}, expected {wanted}")


def download(expected: dict[str, object], cache: Path) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / str(expected["archive"])
    if destination.is_file():
        verify_archive(destination, expected)
        return destination
    temporary = destination.with_suffix(destination.suffix + ".part")
    request = urllib.request.Request(
        str(expected["url"]), headers={"User-Agent": "retrolarium-kit/0.1"}
    )
    try:
        with urllib.request.urlopen(request) as response, temporary.open("wb") as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
        verify_archive(temporary, expected)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def safe_extract(archive: Path, destination: Path) -> None:
    root = destination.resolve()
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            target = (root / member.filename).resolve()
            try:
                target.relative_to(root)
            except ValueError as exc:
                raise ToolchainError(f"unsafe ZIP member: {member.filename}") from exc
            unix_mode = member.external_attr >> 16
            if stat.S_ISLNK(unix_mode):
                raise ToolchainError(f"symbolic link in toolchain ZIP: {member.filename}")
        bundle.extractall(root)


def property_value(path: Path, key: str) -> str | None:
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.startswith(key + "="):
            return raw.split("=", 1)[1]
    return None


def toolchain_status(ghidra_home: Path) -> dict[str, object]:
    lock = load_lock()
    ghidra = entry(lock, "ghidra")
    loader = entry(lock, "nes_loader")
    application = ghidra_home / "Ghidra" / "application.properties"
    extension = ghidra_home / "Ghidra" / "Extensions" / "GhidraNes" / "extension.properties"
    headless = ghidra_home / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    for path in (application, extension, headless):
        if not path.is_file():
            raise ToolchainError(f"installed component not found: {path}")
    actual_version = property_value(application, "application.version")
    if actual_version != ghidra["version"]:
        raise ToolchainError(
            f"Ghidra version is {actual_version}, expected {ghidra['version']}"
        )
    if property_value(extension, "name") != loader["name"]:
        raise ToolchainError("installed NES loader identity does not match lock")
    return {
        "status": "ready",
        "ghidra_home": str(ghidra_home.resolve()),
        "ghidra_version": actual_version,
        "nes_loader": loader["name"],
        "nes_loader_version": loader["version"],
        "headless": str(headless.resolve()),
    }


def install_toolchain(tool_root: Path) -> dict[str, object]:
    tool_root = tool_root.resolve()
    cache = tool_root / "cache"
    ghidra_home = tool_root / "ghidra"
    if ghidra_home.exists():
        return toolchain_status(ghidra_home)

    lock = load_lock()
    ghidra_entry = entry(lock, "ghidra")
    loader_entry = entry(lock, "nes_loader")
    ghidra_archive = download(ghidra_entry, cache)
    loader_archive = download(loader_entry, cache)
    staging = tool_root / "install-staging"
    extension_staging = tool_root / "extension-staging"
    if staging.exists():
        shutil.rmtree(staging)
    if extension_staging.exists():
        shutil.rmtree(extension_staging)
    staging.mkdir(parents=True)
    extension_staging.mkdir(parents=True)
    try:
        safe_extract(ghidra_archive, staging)
        source = staging / str(ghidra_entry["install_directory"])
        if not source.is_dir():
            raise ToolchainError("Ghidra archive root does not match lock")
        safe_extract(loader_archive, extension_staging)
        candidates = list(extension_staging.rglob("extension.properties"))
        if len(candidates) != 1:
            raise ToolchainError(
                f"expected one GhidraNes extension, found {len(candidates)}"
            )
        destination = source / "Ghidra" / "Extensions" / "GhidraNes"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(candidates[0].parent), destination)
        source.replace(ghidra_home)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if extension_staging.exists():
            shutil.rmtree(extension_staging)
    return toolchain_status(ghidra_home)
