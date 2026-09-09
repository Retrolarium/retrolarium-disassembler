"""First end-to-end NES disassembly pipeline."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess

from .ca65 import emit_project
from .facts import load_ghidra_facts
from .ghidra import run_nes_analysis
from .ines import InesImage, load_ines, nrom_projections
from .pointers import (
    accepted_pointer_tables,
    detect_pointer_candidates,
    write_pointer_report,
)


class PipelineError(RuntimeError):
    """A pipeline stage failed its explicit contract."""


def sha256_file(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def first_difference(left: bytes, right: bytes) -> int | None:
    for index, (first, second) in enumerate(zip(left, right)):
        if first != second:
            return index
    if len(left) != len(right):
        return min(len(left), len(right))
    return None


def verify_exact(original: Path, rebuilt: Path) -> dict[str, object]:
    original_bytes = original.read_bytes()
    rebuilt_bytes = rebuilt.read_bytes()
    difference = first_difference(original_bytes, rebuilt_bytes)
    result: dict[str, object] = {
        "schema_version": 1,
        "status": "exact" if difference is None else "mismatch",
        "original_size": len(original_bytes),
        "rebuilt_size": len(rebuilt_bytes),
        "original_sha256": hashlib.sha256(original_bytes).hexdigest(),
        "rebuilt_sha256": hashlib.sha256(rebuilt_bytes).hexdigest(),
        "first_difference": difference,
    }
    if difference is not None:
        raise PipelineError(
            f"rebuilt image differs at file offset {difference:#x}: "
            f"{result['original_sha256']} != {result['rebuilt_sha256']}"
        )
    return result


def build_in_container(project: Path, image: str) -> Path:
    project = project.resolve()
    command = [
        "docker",
        "run",
        "--rm",
        "--mount",
        f"type=bind,source={project},target=/work",
        "--workdir",
        "/work",
        image,
        "make",
        "all",
    ]
    result = subprocess.run(command, text=True)
    if result.returncode:
        raise PipelineError(f"ca65 container build failed with {result.returncode}")
    rebuilt = project / "build" / "rebuilt.nes"
    if not rebuilt.is_file():
        raise PipelineError(f"expected rebuilt image was not produced: {rebuilt}")
    return rebuilt


def image_manifest(image: InesImage) -> dict[str, object]:
    return {
        "sha256": image.sha256,
        "size": len(image.data),
        "format": "ines",
        "mapper": image.mapper,
        "mirroring": image.mirroring,
        "battery": image.battery,
        "regions": [asdict(item) for item in image.regions],
        "projections": [asdict(item) for item in nrom_projections(image)],
    }


def disassemble_nrom(
    rom: Path,
    output: Path,
    ghidra_home: Path,
    *,
    build_container: str | None = None,
) -> dict[str, object]:
    rom = rom.resolve()
    output = output.resolve()
    image = load_ines(rom)
    # Reject unsupported containers and mappers before starting the expensive
    # external analysis backend.
    nrom_projections(image)
    analysis_dir = output / "analysis"
    generated_dir = output / "generated"
    script_directory = Path(__file__).resolve().parent / "ghidra_scripts"
    artifacts = run_nes_analysis(
        rom, analysis_dir, ghidra_home.resolve(), script_directory
    )
    facts = load_ghidra_facts(artifacts.facts, image)
    pointer_candidates = detect_pointer_candidates(image, facts)
    write_pointer_report(analysis_dir / "pointers.json", image, pointer_candidates)
    emission = emit_project(generated_dir, image, facts, pointer_candidates)
    report = json.loads(artifacts.report.read_text(encoding="utf-8"))
    manifest: dict[str, object] = {
        "schema_version": 1,
        "task": "nes.disassemble",
        "mode": "blind",
        "input": image_manifest(image),
        "backend": {
            "id": "ghidra",
            "language": report["language"],
            "compiler": report["compiler"],
            "facts_sha256": sha256_file(artifacts.facts),
        },
        "facts": {
            "instruction_count": len(facts),
            "instruction_bytes": emission.instruction_bytes,
            "pointer_bytes": emission.pointer_bytes,
            "raw_prg_bytes": emission.raw_bytes,
            "labels": emission.labels,
            "diagnostics": list(emission.diagnostics),
        },
        "pointers": {
            "candidate_count": sum(
                candidate.schema_id != "nes.interrupt_vectors"
                for candidate in pointer_candidates
            ),
            "accepted_count": len(accepted_pointer_tables(pointer_candidates)),
            "accepted_by_schema": {
                schema_id: sum(
                    candidate.schema_id == schema_id
                    for candidate in accepted_pointer_tables(pointer_candidates)
                )
                for schema_id in ("nes.u16le", "nes.split_lo_hi")
            },
            "report": "analysis/pointers.json",
        },
        "source": {
            "dialect": "ca65",
            "directory": "generated",
            "coverage": "complete",
            "whole_rom_fallback": False,
        },
        "verification": {"status": "not-run"},
    }
    if build_container is not None:
        rebuilt = build_in_container(generated_dir, build_container)
        manifest["verification"] = verify_exact(rom, rebuilt)
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest
