#!/usr/bin/env python3
"""Build pinned open-game fixtures in isolated Docker workspaces."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Iterable


FIXTURES_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = FIXTURES_ROOT.parents[1]
CONFIG_PATH = FIXTURES_ROOT / "projects.json"
LOCK_PATH = FIXTURES_ROOT / "upstreams.lock.json"
STATE_PATH = FIXTURES_ROOT / ".state" / "build-results.json"


class FixtureError(RuntimeError):
    """Expected fixture configuration or build failure."""


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        config = json.load(stream)
    if config.get("schema_version") != 1:
        raise FixtureError("unsupported projects.json schema")
    return config


def load_lock(path: Path = LOCK_PATH) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        lock = json.load(stream)
    if lock.get("schema_version") != 1:
        raise FixtureError("unsupported upstreams.lock.json schema")
    return lock


def within(root: Path, relative: str) -> Path:
    if not relative or Path(relative).is_absolute():
        raise FixtureError(f"path must be non-empty and relative: {relative!r}")
    root = root.resolve()
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise FixtureError(f"path escapes fixture root: {relative}") from exc
    return candidate


def run(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    display = subprocess.list2cmdline(argv)
    print(f"+ {display}", flush=True)
    return subprocess.run(argv, cwd=cwd, check=True, text=True)


def capture(argv: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(
        argv,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_tree_sha256(root: Path) -> str:
    if not root.is_dir():
        raise FixtureError(f"local source directory not found: {root}")
    digest = hashlib.sha256()
    files = sorted(
        (path for path in root.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    if not files:
        raise FixtureError(f"local source directory is empty: {root}")
    for path in files:
        if path.is_symlink():
            raise FixtureError(f"local source must not contain symlinks: {path}")
        relative = path.relative_to(root).as_posix().encode("utf-8")
        payload = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def project_map(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    projects = config.get("projects")
    if not isinstance(projects, list):
        raise FixtureError("projects must be a list")
    mapped: dict[str, dict[str, Any]] = {}
    for project in projects:
        project_id = project.get("id")
        if not isinstance(project_id, str) or not project_id:
            raise FixtureError("every project needs an id")
        if project_id in mapped:
            raise FixtureError(f"duplicate project id: {project_id}")
        mapped[project_id] = project
    return mapped


def repository_map(lock: dict[str, Any]) -> dict[str, dict[str, Any]]:
    repositories = lock.get("repositories")
    if not isinstance(repositories, list):
        raise FixtureError("repositories must be a list")
    mapped: dict[str, dict[str, Any]] = {}
    for repository in repositories:
        repository_id = repository.get("id")
        if not isinstance(repository_id, str) or not repository_id:
            raise FixtureError("every locked repository needs an id")
        if repository_id in mapped:
            raise FixtureError(f"duplicate locked repository id: {repository_id}")
        mapped[repository_id] = repository
    return mapped


def validate_lock(config: dict[str, Any], lock: dict[str, Any]) -> None:
    for project_id, project in project_map(config).items():
        source_kind = project.get("source_kind", "upstream")
        if source_kind not in {"upstream", "local"}:
            raise FixtureError(f"{project_id}: unknown source kind: {source_kind}")
        if source_kind == "local" and not project.get("source_sha256"):
            raise FixtureError(f"{project_id}: local source needs source_sha256")
    projects = {
        project_id: project
        for project_id, project in project_map(config).items()
        if project.get("source_kind", "upstream") == "upstream"
    }
    repositories = repository_map(lock)
    if projects.keys() != repositories.keys():
        raise FixtureError("projects.json and upstreams.lock.json ids differ")
    for project_id, project in projects.items():
        repository = repositories[project_id]
        if project["source"] != repository["path"]:
            raise FixtureError(f"{project_id}: source path differs from lock")
        if project["commit"] != repository["commit"]:
            raise FixtureError(f"{project_id}: source commit differs from lock")


def selected_projects(
    config: dict[str, Any], requested: Iterable[str]
) -> list[dict[str, Any]]:
    mapped = project_map(config)
    ids = list(requested)
    if not ids or ids == ["all"]:
        return list(mapped.values())
    missing = sorted(set(ids) - mapped.keys())
    if missing:
        raise FixtureError(f"unknown project(s): {', '.join(missing)}")
    return [mapped[project_id] for project_id in ids]


def source_status(project: dict[str, Any]) -> tuple[Path, str, bool]:
    source = within(FIXTURES_ROOT, project["source"])
    if project.get("source_kind", "upstream") == "local":
        actual = source_tree_sha256(source)
        expected = project.get("source_sha256")
        if actual != expected:
            raise FixtureError(
                f"{project['id']}: local source sha256 is {actual}, expected {expected}"
            )
        return source, actual, False
    if not (source / ".git").exists():
        raise FixtureError(f"{project['id']}: upstream source is not cloned")
    actual = capture(["git", "rev-parse", "HEAD"], cwd=source)
    expected = project["commit"]
    dirty = bool(capture(["git", "status", "--porcelain"], cwd=source))
    if actual != expected:
        raise FixtureError(
            f"{project['id']}: expected commit {expected}, found {actual}"
        )
    return source, actual, dirty


def verify_submodules(repository: dict[str, Any], source: Path) -> None:
    for submodule in repository.get("submodules", []):
        submodule_path = within(source, submodule["path"])
        if not (submodule_path / ".git").exists():
            raise FixtureError(
                f"{repository['id']}: submodule is not initialized: {submodule['path']}"
            )
        actual = capture(["git", "rev-parse", "HEAD"], cwd=submodule_path)
        if actual != submodule["commit"]:
            raise FixtureError(
                f"{repository['id']}: submodule {submodule['path']} expected "
                f"{submodule['commit']}, found {actual}"
            )


def fetch_repository(repository: dict[str, Any]) -> None:
    destination = within(FIXTURES_ROOT, repository["path"])
    if destination.exists():
        project = {
            "id": repository["id"],
            "source": repository["path"],
            "commit": repository["commit"],
        }
        _, _, dirty = source_status(project)
        if dirty:
            raise FixtureError(f"{repository['id']}: existing checkout is dirty")
        verify_submodules(repository, destination)
        print(f"OK {repository['id']}: already present", flush=True)
        return

    staging = within(FIXTURES_ROOT, f".cache/clones/{repository['id']}")
    if staging.exists():
        shutil.rmtree(staging)
    staging.parent.mkdir(parents=True, exist_ok=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        run(["git", "clone", "--no-checkout", repository["url"], str(staging)])
        run(["git", "checkout", "--detach", repository["commit"]], cwd=staging)
        run(["git", "submodule", "sync", "--recursive"], cwd=staging)
        run(
            ["git", "submodule", "update", "--init", "--recursive"],
            cwd=staging,
        )
        verify_submodules(repository, staging)
        os.replace(staging, destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    print(f"OK {repository['id']}: fetched {repository['commit'][:12]}", flush=True)


def validate_output_policy(config: dict[str, Any]) -> None:
    policy = config["output_policy"]
    allowed = {
        platform: {suffix.lower() for suffix in suffixes}
        for platform, suffixes in policy["allowed_extensions"].items()
    }
    expected_outputs = {
        within(FIXTURES_ROOT, project["output"]).resolve()
        for project in config["projects"]
    }
    for platform, suffixes in allowed.items():
        output_dir = within(FIXTURES_ROOT, f"{platform}/bin")
        if not output_dir.exists():
            continue
        for entry in output_dir.rglob("*"):
            if entry.is_dir():
                continue
            if entry.resolve() not in expected_outputs:
                raise FixtureError(f"unexpected file in ROM output directory: {entry}")
            if entry.suffix.lower() not in suffixes:
                raise FixtureError(f"non-ROM extension in output directory: {entry}")


def validate_rom(project: dict[str, Any], path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FixtureError(f"{project['id']}: expected ROM not produced: {path}")
    data = path.read_bytes()
    expected_size = project.get("expected_size")
    if expected_size is not None and len(data) != expected_size:
        raise FixtureError(
            f"{project['id']}: expected {expected_size} bytes, got {len(data)}"
        )
    platform = project["platform"]
    if platform == "nes" and not data.startswith(b"NES\x1a"):
        raise FixtureError(f"{project['id']}: missing iNES header")
    if platform == "megadrive":
        if len(data) < 0x200 or b"SEGA" not in data[0x100:0x110]:
            raise FixtureError(f"{project['id']}: missing Mega Drive header")
    if platform == "snes" and len(data) < 0x8000:
        raise FixtureError(f"{project['id']}: implausibly small SNES ROM")
    digest = sha256(path)
    expected_sha256 = project.get("expected_sha256")
    if expected_sha256 is not None and digest != expected_sha256:
        raise FixtureError(
            f"{project['id']}: expected sha256 {expected_sha256}, got {digest}"
        )
    return {"size": len(data), "sha256": digest}


def adapt_asm68k_for_clownassembler(workspace: Path) -> None:
    """Lower a small, semantics-preserving ASM68K dialect subset."""
    for source in sorted(workspace.rglob("*.68k")):
        lines = source.read_text(encoding="utf-8").splitlines(keepends=True)
        local_macros: dict[str, str] = {}
        global_scope = "file"
        output: list[str] = []
        changed = False

        for original in lines:
            newline = (
                "\r\n"
                if original.endswith("\r\n")
                else "\n" if original.endswith("\n") else ""
            )
            line = original.removesuffix(newline)
            if line.lstrip().startswith(";"):
                output.append(original)
                continue

            global_label = re.match(r"^([A-Za-z_.$][\w.$]*):", line)
            if global_label:
                global_scope = re.sub(r"\W", "_", global_label.group(1))

            macro = re.match(r"^(\s*)@(\w+)(:?)\s+macro\b(.*)$", line, re.I)
            if macro:
                old_name = macro.group(2)
                new_name = f"__rt_{global_scope}_{old_name}"
                local_macros[old_name.lower()] = new_name
                line = (
                    f"{macro.group(1)}{new_name}{macro.group(3)} macro"
                    f"{macro.group(4)}"
                )

            for old_name, new_name in local_macros.items():
                line = re.sub(
                    rf"^(\s*)(purge\s+)?@{re.escape(old_name)}(?=\s|$)",
                    lambda match: f"{match.group(1)}{match.group(2) or ''}{new_name}",
                    line,
                    flags=re.I,
                )

            hexadecimal = re.match(
                r"^(\s*(?:[A-Za-z_.$@][\w.$@]*:\s*)?)hex\s+([0-9A-Fa-f]+)(\s*(?:;.*)?)$",
                line,
                re.I,
            )
            if hexadecimal:
                digits = hexadecimal.group(2)
                if len(digits) % 2:
                    raise FixtureError(f"odd number of hex digits in {source}: {digits}")
                values = ",".join(
                    f"${digits[index:index + 2]}" for index in range(0, len(digits), 2)
                )
                line = f"{hexadecimal.group(1)}dc.b {values}{hexadecimal.group(3)}"

            if re.match(r"^\s*inform\s", line, re.I):
                line = f"; retrolarium: omitted build diagnostic: {line.lstrip()}"

            modulo_equ = re.match(
                r"^(\s*[A-Za-z_.$@][\w.$@]*\s*:\s*equ\s+)(.+)%([^%]+)$",
                line,
                re.I,
            )
            if modulo_equ:
                left = modulo_equ.group(2).strip()
                right = modulo_equ.group(3).strip()
                line = (
                    f"{modulo_equ.group(1)}({left})-(({left})/({right}))*({right})"
                )

            line = re.sub(
                r"#-([A-Za-z_.$@][\w.$@]*)/([0-9]+)",
                r"#(-(\1/\2))",
                line,
            )
            transformed = line + newline
            changed |= transformed != original
            output.append(transformed)

        if changed:
            source.write_text("".join(output), encoding="utf-8", newline="")


def prepare_workspace(project: dict[str, Any], source: Path) -> Path:
    workspace = within(FIXTURES_ROOT, f".work/{project['id']}")
    if workspace.exists():
        shutil.rmtree(workspace)
    shutil.copytree(source, workspace, ignore=shutil.ignore_patterns(".git"))
    workspace_directory = workspace.relative_to(REPOSITORY_ROOT).as_posix()
    for relative_patch in project.get("patches", []):
        patch = within(FIXTURES_ROOT, relative_patch)
        run(
            ["git", "apply", f"--directory={workspace_directory}", str(patch)],
            cwd=REPOSITORY_ROOT,
        )
    for adapter in project.get("adapters", []):
        if adapter == "asm68k-clownassembler":
            adapt_asm68k_for_clownassembler(workspace)
        else:
            raise FixtureError(f"{project['id']}: unknown source adapter: {adapter}")
    return workspace


def atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp"
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        shutil.copyfile(source, temporary)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def build_toolchain(config: dict[str, Any], toolchain_id: str) -> None:
    try:
        toolchain = config["toolchains"][toolchain_id]
    except KeyError as exc:
        raise FixtureError(f"unknown toolchain: {toolchain_id}") from exc
    context = within(FIXTURES_ROOT, toolchain["context"])
    run(["docker", "build", "--tag", toolchain["image"], str(context)])


def build_project(config: dict[str, Any], project: dict[str, Any]) -> dict[str, Any]:
    validate_output_policy(config)
    source, source_identity, dirty = source_status(project)
    if dirty:
        raise FixtureError(f"{project['id']}: upstream checkout is dirty")
    builder = config["builders"][project["builder"]]
    toolchain_id = builder.get("toolchain")
    command = builder.get("command")
    if not toolchain_id or not command:
        raise FixtureError(f"{project['id']}: builder is not implemented yet")
    toolchain = config["toolchains"][toolchain_id]
    workspace = prepare_workspace(project, source)
    built = within(workspace, project["source_output"])
    built.unlink(missing_ok=True)
    mount = f"type=bind,source={workspace},target=/work"
    run(
        [
            "docker",
            "run",
            "--rm",
            "--mount",
            mount,
            "--workdir",
            "/work",
            toolchain["image"],
            *command,
        ]
    )
    result = validate_rom(project, built)
    destination = within(FIXTURES_ROOT, project["output"])
    atomic_copy(built, destination)
    result.update(
        {
            "id": project["id"],
            "builder": project["builder"],
            "toolchain_image": toolchain["image"],
            "output": project["output"],
        }
    )
    identity_key = (
        "source_sha256"
        if project.get("source_kind", "upstream") == "local"
        else "source_commit"
    )
    result[identity_key] = source_identity
    print(
        f"OK {project['id']}: {result['size']} bytes "
        f"sha256={result['sha256']}",
        flush=True,
    )
    return result


def write_results(results: list[dict[str, Any]]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {"schema_version": 1, "results": results}
    temporary = STATE_PATH.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, STATE_PATH)


def verify_outputs(
    config: dict[str, Any], projects: Iterable[dict[str, Any]]
) -> None:
    validate_output_policy(config)
    for project in projects:
        output = within(FIXTURES_ROOT, project["output"])
        result = validate_rom(project, output)
        print(
            f"OK {project['id']}: {result['size']} bytes "
            f"sha256={result['sha256']}",
            flush=True,
        )


def doctor(config: dict[str, Any], lock: dict[str, Any]) -> None:
    validate_lock(config, lock)
    repositories = repository_map(lock)
    validate_output_policy(config)
    for project in config["projects"]:
        source, source_identity, dirty = source_status(project)
        if project.get("source_kind", "upstream") == "upstream":
            verify_submodules(repositories[project["id"]], source)
        builder = config["builders"][project["builder"]]
        state = "ready" if builder.get("toolchain") and builder.get("command") else "pending"
        print(
            f"{project['id']}: source={source} snapshot={source_identity[:12]} "
            f"dirty={str(dirty).lower()} builder={state}"
        )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    subparsers.add_parser("doctor", help="validate clones and output policy")
    fetch_parser = subparsers.add_parser("fetch", help="clone pinned upstream sources")
    fetch_parser.add_argument("project", nargs="*", help="fixture id(s), or all")
    toolchain_parser = subparsers.add_parser("toolchain", help="build a Docker toolchain")
    toolchain_parser.add_argument("id", choices=sorted(load_config()["toolchains"]))
    build_parser = subparsers.add_parser("build", help="build one or more fixtures")
    build_parser.add_argument("project", nargs="+", help="fixture id(s), or all")
    verify_parser = subparsers.add_parser("verify", help="verify built ROM outputs")
    verify_parser.add_argument("project", nargs="*", help="fixture id(s), or all")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        config = load_config()
        lock = load_lock()
        validate_lock(config, lock)
        if args.subcommand == "doctor":
            doctor(config, lock)
        elif args.subcommand == "fetch":
            repositories = repository_map(lock)
            projects = selected_projects(config, args.project)
            for project in projects:
                if project.get("source_kind", "upstream") == "local":
                    source, identity, _ = source_status(project)
                    print(
                        f"OK {project['id']}: local source={source} "
                        f"sha256={identity}",
                        flush=True,
                    )
                else:
                    fetch_repository(repositories[project["id"]])
        elif args.subcommand == "toolchain":
            build_toolchain(config, args.id)
        elif args.subcommand == "build":
            results = [
                build_project(config, project)
                for project in selected_projects(config, args.project)
            ]
            write_results(results)
        elif args.subcommand == "verify":
            verify_outputs(config, selected_projects(config, args.project))
        else:
            raise AssertionError(args.subcommand)
    except (FixtureError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
