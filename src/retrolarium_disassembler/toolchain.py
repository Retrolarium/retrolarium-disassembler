"""Acquire and verify pinned external disassembly tools."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
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
    snes_backend = entry(lock, "snes_backend")
    spc700_backend = entry(lock, "spc700_backend")
    application = ghidra_home / "Ghidra" / "application.properties"
    extension = ghidra_home / "Ghidra" / "Extensions" / "GhidraNes" / "extension.properties"
    snes_root = (
        ghidra_home
        / "Ghidra"
        / "Extensions"
        / str(snes_backend["name"])
    )
    snes_properties = snes_root / "extension.properties"
    snes_language = snes_root / "data" / "languages" / "65816.ldefs"
    snes_compiled = snes_root / "data" / "languages" / "65816.sla"
    snes_license = snes_root / "LICENSE.upstream"
    spc700_root = (
        ghidra_home
        / "Ghidra"
        / "Extensions"
        / str(spc700_backend["name"])
    )
    spc700_properties = spc700_root / "extension.properties"
    spc700_language = spc700_root / "data" / "languages" / "spc700.ldefs"
    spc700_compiled = spc700_root / "data" / "languages" / "spc700.sla"
    spc700_license = spc700_root / "LICENSE.upstream"
    headless = ghidra_home / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    for path in (
        application,
        extension,
        headless,
        snes_properties,
        snes_language,
        snes_compiled,
        snes_license,
        spc700_properties,
        spc700_language,
        spc700_compiled,
        spc700_license,
    ):
        if not path.is_file():
            raise ToolchainError(f"installed component not found: {path}")
    actual_version = property_value(application, "application.version")
    if actual_version != ghidra["version"]:
        raise ToolchainError(
            f"Ghidra version is {actual_version}, expected {ghidra['version']}"
        )
    if property_value(extension, "name") != loader["name"]:
        raise ToolchainError("installed NES loader identity does not match lock")
    if property_value(snes_properties, "name") != snes_backend["name"]:
        raise ToolchainError("installed SNES backend identity does not match lock")
    if property_value(snes_properties, "retrolarium.sourceCommit") != snes_backend["commit"]:
        raise ToolchainError("installed SNES backend commit does not match lock")
    if str(snes_backend["language_id"]) not in snes_language.read_text(
        encoding="utf-8"
    ):
        raise ToolchainError("installed SNES language id does not match lock")
    if property_value(spc700_properties, "name") != spc700_backend["name"]:
        raise ToolchainError("installed SPC700 backend identity does not match lock")
    if property_value(spc700_properties, "retrolarium.sourceCommit") != spc700_backend["commit"]:
        raise ToolchainError("installed SPC700 backend commit does not match lock")
    if str(spc700_backend["language_id"]) not in spc700_language.read_text(
        encoding="utf-8"
    ):
        raise ToolchainError("installed SPC700 language id does not match lock")
    return {
        "status": "ready",
        "ghidra_home": str(ghidra_home.resolve()),
        "ghidra_version": actual_version,
        "nes_loader": loader["name"],
        "nes_loader_version": loader["version"],
        "snes_backend": snes_backend["name"],
        "snes_backend_commit": snes_backend["commit"],
        "snes_language": snes_backend["language_id"],
        "spc700_backend": spc700_backend["name"],
        "spc700_backend_commit": spc700_backend["commit"],
        "spc700_language": spc700_backend["language_id"],
        "headless": str(headless.resolve()),
    }


def install_snes_backend(
    ghidra_home: Path,
    archive: Path,
    expected: dict[str, object],
    staging: Path,
) -> None:
    """Install only the pinned MIT 65816 processor files, not its ROM loader."""
    install_processor_backend(
        ghidra_home,
        archive,
        expected,
        staging,
        specification_name="65816.slaspec",
        language_definition_name="65816.ldefs",
        description="Pinned W65C816 language for Retrolarium SNES analysis",
    )


def install_spc700_backend(
    ghidra_home: Path,
    archive: Path,
    expected: dict[str, object],
    staging: Path,
) -> None:
    """Install the pinned MIT SPC700 processor language."""
    install_processor_backend(
        ghidra_home,
        archive,
        expected,
        staging,
        specification_name="spc700.slaspec",
        language_definition_name="spc700.ldefs",
        description="Pinned SPC700 language for proven SNES audio programs",
    )


def install_processor_backend(
    ghidra_home: Path,
    archive: Path,
    expected: dict[str, object],
    staging: Path,
    *,
    specification_name: str,
    language_definition_name: str,
    description: str,
) -> None:
    destination = (
        ghidra_home / "Ghidra" / "Extensions" / str(expected["name"])
    )
    if destination.exists():
        return
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    try:
        safe_extract(archive, staging)
        source = staging / str(expected["source_directory"])
        languages = source / "data" / "languages"
        license_path = source / "LICENSE"
        if not languages.is_dir() or not license_path.is_file():
            raise ToolchainError("processor backend archive layout does not match lock")
        destination.mkdir(parents=True)
        shutil.copytree(languages, destination / "data" / "languages")
        shutil.copyfile(license_path, destination / "LICENSE.upstream")
        (destination / "Module.manifest").write_text(
            f"MODULE NAME: {expected['name']}\nMODULE DEPENDENCIES:\n    Ghidra\n",
            encoding="utf-8",
            newline="\n",
        )
        (destination / "extension.properties").write_text(
            "\n".join(
                (
                    f"name={expected['name']}",
                    f"description={description}",
                    "author=upstream authors; packaged by Retrolarium",
                    "createdOn=2026-09-10",
                    f"version={load_lock()['ghidra']['version']}",
                    f"retrolarium.sourceCommit={expected['commit']}",
                    f"retrolarium.languageId={expected['language_id']}",
                    "",
                )
            ),
            encoding="utf-8",
            newline="\n",
        )
        suffix = ".bat" if os.name == "nt" else ""
        compiler = ghidra_home / "support" / f"sleigh{suffix}"
        specification = destination / "data" / "languages" / specification_name
        language_definition = (
            destination / "data" / "languages" / language_definition_name
        )
        if (
            not compiler.is_file()
            or not specification.is_file()
            or not language_definition.is_file()
        ):
            raise ToolchainError("Ghidra SLEIGH compiler or processor source is missing")
        result = subprocess.run(
            [str(compiler.resolve()), str(specification.resolve())],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
        compiled = specification.with_suffix(".sla")
        if result.returncode or not compiled.is_file():
            tail = "\n".join(result.stdout.splitlines()[-60:])
            raise ToolchainError(
                f"processor SLEIGH compilation failed with exit code "
                f"{result.returncode}\n{tail}"
            )
    except Exception:
        if destination.exists():
            shutil.rmtree(destination)
        raise
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def install_toolchain(tool_root: Path) -> dict[str, object]:
    tool_root = tool_root.resolve()
    cache = tool_root / "cache"
    ghidra_home = tool_root / "ghidra"
    lock = load_lock()
    ghidra_entry = entry(lock, "ghidra")
    loader_entry = entry(lock, "nes_loader")
    snes_entry = entry(lock, "snes_backend")
    spc700_entry = entry(lock, "spc700_backend")
    if ghidra_home.exists():
        snes_archive = download(snes_entry, cache)
        spc700_archive = download(spc700_entry, cache)
        install_snes_backend(
            ghidra_home,
            snes_archive,
            snes_entry,
            tool_root / "snes-extension-staging",
        )
        install_spc700_backend(
            ghidra_home,
            spc700_archive,
            spc700_entry,
            tool_root / "spc700-extension-staging",
        )
        return toolchain_status(ghidra_home)
    ghidra_archive = download(ghidra_entry, cache)
    loader_archive = download(loader_entry, cache)
    snes_archive = download(snes_entry, cache)
    spc700_archive = download(spc700_entry, cache)
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
        install_snes_backend(
            source,
            snes_archive,
            snes_entry,
            tool_root / "snes-extension-staging",
        )
        install_spc700_backend(
            source,
            spc700_archive,
            spc700_entry,
            tool_root / "spc700-extension-staging",
        )
        source.replace(ghidra_home)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if extension_staging.exists():
            shutil.rmtree(extension_staging)
    return toolchain_status(ghidra_home)
