"""Transactional creation of a ready-to-open Studio workspace from a game ROM."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any

from .games import extract_game, inspect_game, validate_game
from .pipeline import disassemble_nes
from .studio_project import (
    StudioProjectError,
    build_studio_project,
    create_studio_project,
    load_studio_project,
    validate_studio_project,
    verify_studio_project,
)


SUPPORTED_PRESETS = frozenset({"castle-excellent", "pacman", "smb1",
                               "solomons-key"})


def _project_id(game: str, revision: str) -> str:
    value = re.sub(r"[^a-z0-9.-]+", "-", f"{game}-{revision}".lower()).strip("-")
    if not value:
        raise StudioProjectError("recognized game did not produce a project identifier")
    return value


def create_game_studio_preset(
    rom: Path,
    output_directory: Path,
    *,
    ghidra_home: Path,
    build: bool = True,
    build_container: str | None = None,
    toolchain_cache: Path | None = None,
    legacy_castle_levels: Path | None = None,
) -> dict[str, Any]:
    """Create a complete supported-game Studio without publishing partial output."""

    rom = rom.resolve()
    if not rom.is_file():
        raise StudioProjectError(f"source game image does not exist: {rom}")
    output = output_directory.resolve()
    if output.exists():
        raise StudioProjectError(
            f"Studio output directory already exists; choose a new directory: {output}"
        )
    output.parent.mkdir(parents=True, exist_ok=True)

    inspection = inspect_game(rom)
    game = str(inspection["game"])
    if game not in SUPPORTED_PRESETS:
        raise StudioProjectError(
            "ready Studio presets are currently limited to Castle Excellent / "
            "Castlequest, Pac-Man, Super Mario Bros. 1, and Solomon's Key"
        )
    revision = str(inspection["revision"])
    if legacy_castle_levels is not None:
        if game != "castle-excellent":
            raise StudioProjectError(
                "legacy Castle levels can only be imported into a Castle Studio"
            )
        legacy_castle_levels = legacy_castle_levels.resolve()
        if not legacy_castle_levels.is_file():
            raise StudioProjectError(
                f"legacy Castle levels document does not exist: {legacy_castle_levels}"
            )
        try:
            legacy_identity = json.loads(
                legacy_castle_levels.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise StudioProjectError(
                f"cannot read legacy Castle levels document: {exc}"
            ) from exc
        if not isinstance(legacy_identity, dict) \
                or legacy_identity.get("schema") != "retrolarium.castle-levels":
            raise StudioProjectError(
                "legacy Castle levels document must use retrolarium.castle-levels"
            )
        validation = validate_game(rom, legacy_castle_levels)
        if validation["status"] != "valid":
            raise StudioProjectError("legacy Castle levels document is not valid")
    profile_version = int(inspection["profile_version"])
    identifier = _project_id(game, revision)
    project_name = f"{inspection['name']} ({revision})"
    project_filename = f"{identifier}.rlj"

    staging = Path(tempfile.mkdtemp(
        prefix=f".{output.name}.rlj-stage-", dir=output.parent
    ))
    published = False
    try:
        disassemble_nes(
            rom,
            staging,
            ghidra_home.resolve(),
            build_container=build_container,
        )
        if game == "castle-excellent":
            resource_documents = (
                staging / "documents" / "levels.json",
                staging / "documents" / "graphics.json",
            )
            if legacy_castle_levels is None:
                extract_game(rom, resource_documents[0], resource="levels")
            else:
                resource_documents[0].parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(legacy_castle_levels, resource_documents[0])
            extract_game(
                rom, resource_documents[1], resource="resource-bundle"
            )
        elif game == "solomons-key":
            resource_documents = (
                staging / "documents" / "levels.json",
                staging / "documents" / "room-art.json",
                staging / "documents" / "animations.json",
                staging / "documents" / "audio.json",
                staging / "documents" / "presentation.json",
                staging / "documents" / "text.json",
                staging / "documents" / "graphics.json",
            )
            extract_game(rom, resource_documents[0], resource="levels")
            extract_game(rom, resource_documents[1], resource="room-art")
            extract_game(rom, resource_documents[2], resource="animations")
            extract_game(rom, resource_documents[3], resource="audio")
            extract_game(
                rom, resource_documents[4], resource="presentation"
            )
            extract_game(rom, resource_documents[5], resource="text")
            extract_game(
                rom, resource_documents[6], resource="resource-bundle"
            )
        else:
            resource_documents = (staging / "documents" / "resources.json",)
            extract_game(rom, resource_documents[0])
        staged_project = staging / project_filename
        create_studio_project(
            staging / "manifest.json",
            staged_project,
            project_id=identifier,
            name=project_name,
            profile=f"{game}.v{profile_version}",
            source_mode="binary-profile",
            resource_documents=resource_documents,
        )
        validation = validate_studio_project(staged_project)
        build_result: dict[str, Any] | None = None
        verification: dict[str, Any] | None = None
        if build:
            build_result = build_studio_project(
                staged_project,
                container=build_container,
                toolchain_cache=toolchain_cache,
            )
            verification = verify_studio_project(staged_project)
            if verification["status"] != "current":
                raise StudioProjectError("new Studio preset did not verify current")

        os.replace(staging, output)
        final_project = output / project_filename
        try:
            final_inspection = load_studio_project(final_project)
            if build:
                verification = verify_studio_project(final_project)
                if verification["status"] != "current":
                    raise StudioProjectError(
                        "relocated Studio preset did not verify current"
                    )
        except Exception:
            os.replace(output, staging)
            raise
        published = True
        return {
            "schema": "retrolarium.studio-preset-result",
            "schema_version": 1,
            "status": "ready",
            "game": game,
            "revision": revision,
            "project_file": str(final_project),
            "enabled_tabs": validation["enabled_tabs"],
            "built": build_result is not None,
            "artifact": None if verification is None else verification["artifact"],
            "workspace": final_inspection["workspace"],
        }
    finally:
        if not published:
            shutil.rmtree(staging, ignore_errors=True)
