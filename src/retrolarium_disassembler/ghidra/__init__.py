"""Headless Ghidra backend with explicit paths and disposable projects."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import tempfile


class GhidraError(RuntimeError):
    """The external Ghidra backend could not produce valid artifacts."""


@dataclass(frozen=True)
class GhidraArtifacts:
    facts: Path
    report: Path
    log: Path
    orphan_facts: Path | None = None


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
    return _run_analysis(
        image,
        workspace,
        ghidra_home,
        script_directory,
        project_name="retrolarium_nes",
        project_prefix="nes_",
        expected_language="6502:LE:16:default",
        import_arguments=(),
        seed_script="SeedNesVectors.java",
        export_block=None,
    )


def run_megadrive_analysis(
    image: Path,
    workspace: Path,
    ghidra_home: Path,
    script_directory: Path,
    *,
    seed_plan: Path,
    probe_orphans: bool = False,
) -> GhidraArtifacts:
    if not seed_plan.is_file():
        raise GhidraError(f"Mega Drive decoder seed plan not found: {seed_plan}")
    return _run_analysis(
        image,
        workspace,
        ghidra_home,
        script_directory,
        project_name="retrolarium_megadrive_m68k",
        project_prefix="megadrive_m68k_",
        expected_language="68000:BE:32:default",
        import_arguments=(
            "-loader",
            "BinaryLoader",
            "-loader-blockName",
            "ROM",
            "-loader-baseAddr",
            "0",
            "-processor",
            "68000:BE:32:default",
        ),
        seed_script="SeedMegaDriveVectors.java",
        seed_arguments=(str(seed_plan.resolve()),),
        export_block="ROM",
        probe_m68k_orphans=probe_orphans,
    )


def run_z80_analysis(
    image: Path,
    workspace: Path,
    ghidra_home: Path,
    script_directory: Path,
    *,
    base_address: int = 0,
    seed_plan: Path | None = None,
) -> GhidraArtifacts:
    if seed_plan is not None and not seed_plan.is_file():
        raise GhidraError(f"Z80 decoder seed plan not found: {seed_plan}")
    return _run_analysis(
        image,
        workspace,
        ghidra_home,
        script_directory,
        project_name="retrolarium_megadrive_z80",
        project_prefix="megadrive_z80_",
        expected_language="z80:LE:16:default",
        import_arguments=(
            "-loader",
            "BinaryLoader",
            "-loader-blockName",
            "Z80_RAM",
            "-loader-baseAddr",
            f"0x{base_address:04X}",
            "-processor",
            "z80:LE:16:default",
        ),
        seed_script="SeedZ80Entry.java",
        seed_arguments=((str(seed_plan.resolve()),) if seed_plan is not None else ()),
        export_block="Z80_RAM",
    )


def run_spc700_analysis(
    image: Path,
    workspace: Path,
    ghidra_home: Path,
    script_directory: Path,
    *,
    base_address: int = 0,
) -> GhidraArtifacts:
    image = image.resolve()
    if not image.is_file():
        raise GhidraError(f"SPC700 payload not found: {image}")
    if not 0 <= base_address <= 0xFFFF:
        raise GhidraError("SPC700 base address exceeds the 16-bit address space")
    if image.stat().st_size > 0x10000 - base_address:
        raise GhidraError("SPC700 payload exceeds the 64 KiB address space")
    return _run_analysis(
        image,
        workspace,
        ghidra_home,
        script_directory,
        project_name="retrolarium_snes_spc700",
        project_prefix="snes_spc700_",
        expected_language="SPC700:LE:16:default",
        import_arguments=(
            "-loader",
            "BinaryLoader",
            "-loader-blockName",
            "SPC700_RAM",
            "-loader-baseAddr",
            f"0x{base_address:04X}",
            "-processor",
            "SPC700:LE:16:default",
        ),
        seed_script="SeedSpc700Entry.java",
        export_block="SPC700_RAM",
    )


def run_snes_bank_analysis(
    image: Path,
    workspace: Path,
    ghidra_home: Path,
    script_directory: Path,
    *,
    base_address: int,
    entry_address: int,
    context_plan: Path,
) -> GhidraArtifacts:
    if not 0 <= base_address <= 0xFFFFFF:
        raise GhidraError("SNES bank base exceeds the 24-bit address space")
    if not base_address <= entry_address <= 0xFFFFFF:
        raise GhidraError("SNES entry precedes its bank or exceeds 24 bits")
    context_plan = context_plan.resolve()
    if not context_plan.is_file():
        raise GhidraError(f"SNES context plan not found: {context_plan}")
    return _run_analysis(
        image,
        workspace,
        ghidra_home,
        script_directory,
        project_name="retrolarium_snes_w65c816",
        project_prefix="snes_w65c816_",
        expected_language="65816:LE:24:snes",
        import_arguments=(
            "-loader",
            "BinaryLoader",
            "-loader-blockName",
            "SNES_ROM",
            "-loader-baseAddr",
            f"0x{base_address:06X}",
            "-processor",
            "65816:LE:24:snes",
        ),
        seed_script="SeedSnesBank.java",
        seed_arguments=(
            "SNES_ROM",
            f"{entry_address:06X}",
            str(context_plan),
        ),
        export_block="SNES_ROM",
    )


def _run_analysis(
    image: Path,
    workspace: Path,
    ghidra_home: Path,
    script_directory: Path,
    *,
    project_name: str,
    project_prefix: str,
    expected_language: str,
    import_arguments: tuple[str, ...],
    seed_script: str,
    export_block: str | None,
    seed_arguments: tuple[str, ...] = (),
    probe_m68k_orphans: bool = False,
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
    orphan_facts = workspace / "unused-probes.tsv" if probe_m68k_orphans else None
    if orphan_facts is not None:
        orphan_facts.unlink(missing_ok=True)
    export_arguments = [str(facts.resolve())]
    if export_block is not None:
        export_arguments.append(export_block)
    with tempfile.TemporaryDirectory(prefix=project_prefix) as project_dir:
        command = [
            str(headless),
            project_dir,
            project_name,
            "-import",
            str(image),
            *import_arguments,
            "-overwrite",
            "-analysisTimeoutPerFile",
            "600",
            "-scriptPath",
            str(script_directory),
            "-preScript",
            seed_script,
            *seed_arguments,
            "-postScript",
            "InspectProgram.java",
            str(report.resolve()),
            "-postScript",
            "ExportInstructionFacts.java",
            *export_arguments,
            *(["-postScript", "ProbeM68kUnusedCode.java", str(orphan_facts.resolve())]
              if orphan_facts is not None else []),
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
    script_error = "REPORT SCRIPT ERROR:" in result.stdout
    if result.returncode or script_error:
        tail = "\n".join(result.stdout.splitlines()[-60:])
        reason = (
            "reported a script error"
            if script_error and not result.returncode
            else f"failed with exit code {result.returncode}"
        )
        raise GhidraError(
            f"Ghidra headless {reason}\n{tail}"
        )
    if not facts.is_file() or not report.is_file():
        raise GhidraError("Ghidra completed without required fact artifacts")
    if orphan_facts is not None and not orphan_facts.is_file():
        raise GhidraError("Ghidra completed without speculative M68K facts")
    try:
        metadata = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GhidraError(f"invalid Ghidra program report: {exc}") from exc
    if metadata.get("language") != expected_language:
        raise GhidraError(f"unexpected Ghidra language: {metadata.get('language')}")
    return GhidraArtifacts(facts=facts, report=report, log=log, orphan_facts=orphan_facts)
