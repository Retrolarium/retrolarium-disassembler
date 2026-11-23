"""Acquire and verify pinned external disassembly tools."""

from __future__ import annotations

import json
from importlib import resources
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time
import urllib.request
import zipfile

from retrolarium_disassembler.files import sha256_file
from retrolarium_disassembler.java import JavaError, java_environment
from retrolarium_disassembler import __version__


LOCK_PATH = Path(__file__).resolve().parent / "toolchains" / "disassembly.lock.json"
# A download that sends nothing for this many seconds has stalled.
DOWNLOAD_TIMEOUT = 60
# Written into each installed directory: the lock entries it was installed
# from, so a changed lock reinstalls it.
INSTALL_MARKER = ".retrolarium-installed.json"
_MARKER_FIELDS = ("version", "commit", "archive", "sha256")


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


def verify_archive(path: Path, expected: dict[str, object]) -> None:
    if not path.is_file():
        raise ToolchainError(f"archive not found: {path}")
    expected_size = int(expected["size"])
    if path.stat().st_size != expected_size:
        raise ToolchainError(f"{path.name} size is {path.stat().st_size}, expected {expected_size}")
    actual = sha256_file(path)
    wanted = str(expected["sha256"]).lower()
    if actual != wanted:
        raise ToolchainError(f"{path.name} SHA-256 is {actual}, expected {wanted}")


def download(expected: dict[str, object], cache: Path) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / str(expected["archive"])
    if destination.is_file():
        try:
            verify_archive(destination, expected)
            return destination
        except ToolchainError:
            # A truncated or damaged download: fetched again, not kept.
            destination.unlink()
    temporary = destination.with_suffix(destination.suffix + ".part")
    if str(expected["url"]).startswith("package:"):
        relative = str(expected["url"])[len("package:") :]
        if not relative.startswith("toolchains/backends/") or ".." in Path(relative).parts or "\\" in relative:
            raise ToolchainError("invalid bundled processor path")
        try:
            source = resources.files("retrolarium_disassembler").joinpath(relative)
            with resources.as_file(source) as path:
                verify_archive(path, expected)
                shutil.copyfile(path, temporary)
            verify_archive(temporary, expected)
            os.replace(temporary, destination)
            return destination
        finally:
            temporary.unlink(missing_ok=True)
    request = urllib.request.Request(
        str(expected["url"]), headers={"User-Agent": f"retrolarium-disassembler/{__version__}"}
    )
    try:
        try:
            with (
                urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as response,
                temporary.open("wb") as output,
            ):
                total = 0
                read = getattr(response, "read1", response.read)
                while block := read(min(1024 * 1024, int(expected["size"]) - total + 1)):
                    total += len(block)
                    if total > int(expected["size"]):
                        raise ToolchainError(f"{expected['archive']} download exceeds its pinned size")
                    output.write(block)
        except OSError as exc:
            # URLError and TimeoutError are OSErrors: a stalled server ends here too.
            raise ToolchainError(f"cannot download {expected['url']}: {exc}") from exc
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
        # zipfile drops the Unix modes: the launchers (support/sleigh,
        # analyzeHeadless, launch.sh) must stay executable on Linux and macOS.
        if os.name != "nt":
            for member in bundle.infolist():
                mode = (member.external_attr >> 16) & 0o777
                if mode and not member.is_dir():
                    (root / member.filename).chmod(mode)


def install_identity(**entries: dict[str, object]) -> dict[str, object]:
    """What a marker records of the lock entries a directory was installed from."""
    return {
        "schema_version": 1,
        "components": {
            name: {field: str(value[field]) for field in _MARKER_FIELDS if field in value}
            for name, value in sorted(entries.items())
        },
    }


def read_install_marker(directory: Path) -> dict[str, object] | None:
    """The identity a directory was installed with; None for an install older
    than the markers (or one whose marker cannot be read)."""
    try:
        marker = json.loads((directory / INSTALL_MARKER).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return marker if isinstance(marker, dict) else None


def write_install_marker(directory: Path, identity: dict[str, object]) -> None:
    (directory / INSTALL_MARKER).write_text(
        json.dumps(identity, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )


def replace_directory(new: Path, destination: Path) -> None:
    """Put a fully built directory in place of the installed one: the old one
    is renamed aside first and removed only once the new one is in place."""
    if not destination.exists():
        os.replace(new, destination)
        return
    old = destination.with_name(f"{destination.name}.old-{time.time_ns()}")
    os.replace(destination, old)
    try:
        os.replace(new, destination)
    except BaseException:
        os.replace(old, destination)
        raise
    shutil.rmtree(old, ignore_errors=True)


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
    snes_root = ghidra_home / "Ghidra" / "Extensions" / str(snes_backend["name"])
    snes_properties = snes_root / "extension.properties"
    snes_language = snes_root / "data" / "languages" / "65816.ldefs"
    snes_compiled = snes_root / "data" / "languages" / "65816.sla"
    snes_license = snes_root / "LICENSE.upstream"
    spc700_root = ghidra_home / "Ghidra" / "Extensions" / str(spc700_backend["name"])
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
            raise ToolchainError(
                f"Ghidra is not installed completely ({path} is missing): "
                "run rldisasm ghidra install, or pass --ghidra-home with a complete installation"
            )
    actual_version = property_value(application, "application.version")
    if actual_version != ghidra["version"]:
        raise ToolchainError(f"Ghidra version is {actual_version}, expected {ghidra['version']}")
    if property_value(extension, "name") != loader["name"]:
        raise ToolchainError("installed NES loader identity does not match lock")
    if property_value(snes_properties, "name") != snes_backend["name"]:
        raise ToolchainError("installed SNES backend identity does not match lock")
    if property_value(snes_properties, "retrolarium.sourceCommit") != snes_backend["commit"]:
        raise ToolchainError("installed SNES backend commit does not match lock")
    if str(snes_backend["language_id"]) not in snes_language.read_text(encoding="utf-8"):
        raise ToolchainError("installed SNES language id does not match lock")
    if property_value(spc700_properties, "name") != spc700_backend["name"]:
        raise ToolchainError("installed SPC700 backend identity does not match lock")
    if property_value(spc700_properties, "retrolarium.sourceCommit") != spc700_backend["commit"]:
        raise ToolchainError("installed SPC700 backend commit does not match lock")
    if str(spc700_backend["language_id"]) not in spc700_language.read_text(encoding="utf-8"):
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
    """Install, or rebuild when its marker names another lock entry. An install
    without a marker (older than the markers) is kept."""
    destination = ghidra_home / "Ghidra" / "Extensions" / str(expected["name"])
    identity = install_identity(**{str(expected["name"]): expected})
    if destination.exists():
        marker = read_install_marker(destination)
        if marker is None or marker == identity:
            return
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    installed = destination
    # Built beside the installed extension (the same file system) and swapped
    # in only once compiled.
    destination = installed.with_name(f".{installed.name}.new")
    if destination.exists():
        shutil.rmtree(destination)
    finished = False
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
        language_definition = destination / "data" / "languages" / language_definition_name
        if not compiler.is_file() or not specification.is_file() or not language_definition.is_file():
            raise ToolchainError("Ghidra SLEIGH compiler or processor source is missing")
        from retrolarium_disassembler.ghidra import run_launcher

        result = run_launcher([str(compiler.resolve()), str(specification.resolve())], cwd=destination)
        compiled = specification.with_suffix(".sla")
        if result.returncode or not compiled.is_file():
            tail = "\n".join(result.stdout.splitlines()[-60:])
            raise ToolchainError(f"processor SLEIGH compilation failed with exit code {result.returncode}\n{tail}")
        write_install_marker(destination, identity)
        replace_directory(destination, installed)
        finished = True
    finally:
        # Interrupted too (Ctrl+C): a half-built extension would pass for an
        # installed one next time.
        if not finished and destination.exists():
            shutil.rmtree(destination)
        if staging.exists():
            shutil.rmtree(staging)


def install_toolchain(tool_root: Path, *, reinstall: bool = False) -> dict[str, object]:
    """Install the locked toolchain under tool_root. An install made from
    another lock is rebuilt beside the old one and swapped in; one older than
    the install markers is kept unless reinstall says to rebuild it."""
    try:
        java_environment(tool_root / "ghidra")
    except JavaError as error:
        raise ToolchainError(str(error)) from error
    tool_root = tool_root.resolve()
    cache = tool_root / "cache"
    ghidra_home = tool_root / "ghidra"
    lock = load_lock()
    ghidra_entry = entry(lock, "ghidra")
    loader_entry = entry(lock, "nes_loader")
    snes_entry = entry(lock, "snes_backend")
    spc700_entry = entry(lock, "spc700_backend")
    identity = install_identity(ghidra=ghidra_entry, nes_loader=loader_entry)
    marker = read_install_marker(ghidra_home) if ghidra_home.exists() else None
    if ghidra_home.exists() and not reinstall and (marker is None or marker == identity):
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
        try:
            return toolchain_status(ghidra_home)
        except ToolchainError as exc:
            if marker is not None:
                raise
            raise ToolchainError(
                f"{exc}; {ghidra_home} predates the install markers: run ghidra install --reinstall to replace it"
            ) from exc
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
            raise ToolchainError(f"expected one GhidraNes extension, found {len(candidates)}")
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
        write_install_marker(source, identity)
        replace_directory(source, ghidra_home)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if extension_staging.exists():
            shutil.rmtree(extension_staging)
    return toolchain_status(ghidra_home)
