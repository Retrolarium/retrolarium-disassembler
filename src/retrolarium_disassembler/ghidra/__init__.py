"""Headless Ghidra backend with explicit paths and disposable projects."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


class GhidraError(RuntimeError):
    """The external Ghidra backend could not produce valid artifacts."""


@dataclass(frozen=True)
class GhidraArtifacts:
    facts: Path
    report: Path
    log: Path


def find_headless(ghidra_home: Path) -> Path:
    suffix = ".bat" if os.name == "nt" else ""
    candidate = ghidra_home / "support" / f"analyzeHeadless{suffix}"
    if not candidate.is_file():
        raise GhidraError(f"analyzeHeadless not found under {ghidra_home}")
    return candidate.resolve()


def run_nes_analysis(
    image: Path,
    workspace: Path,
    ghidra_home: Path,
    script_directory: Path,
) -> GhidraArtifacts:
    image = image.resolve()
    if not image.is_file():
        raise GhidraError(f"input ROM not found: {image}")
    headless = find_headless(ghidra_home)
    script_directory = script_directory.resolve()
    if not script_directory.is_dir():
        raise GhidraError(f"Ghidra scripts not found: {script_directory}")

    workspace.mkdir(parents=True, exist_ok=True)
    facts = workspace / "instructions.tsv"
    report = workspace / "program.json"
    log = workspace / "headless.log"
    projects = workspace / "ghidra-projects"
    projects.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nes_", dir=projects) as project_dir:
        command = [
            str(headless),
            project_dir,
            "retrolarium_nes",
            "-import",
            str(image),
            "-overwrite",
            "-analysisTimeoutPerFile",
            "600",
            "-scriptPath",
            str(script_directory),
            "-postScript",
            "InspectProgram.java",
            str(report.resolve()),
            "-postScript",
            "ExportInstructionFacts.java",
            str(facts.resolve()),
            "-deleteProject",
        ]
        result = subprocess.run(
            command,
            cwd=workspace,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
    log.write_text(result.stdout, encoding="utf-8", newline="\n")
    if result.returncode:
        tail = "\n".join(result.stdout.splitlines()[-60:])
        raise GhidraError(
            f"Ghidra headless failed with exit code {result.returncode}\n{tail}"
        )
    if not facts.is_file() or not report.is_file():
        raise GhidraError("Ghidra completed without required fact artifacts")
    try:
        metadata = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GhidraError(f"invalid Ghidra program report: {exc}") from exc
    if metadata.get("language") != "6502:LE:16:default":
        raise GhidraError(f"unexpected Ghidra language: {metadata.get('language')}")
    try:
        shutil.rmtree(projects)
    except OSError:
        pass
    return GhidraArtifacts(facts=facts, report=report, log=log)
