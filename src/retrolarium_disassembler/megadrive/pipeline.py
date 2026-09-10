"""Mega Drive analysis pipeline with versioned, backend-neutral artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .facts import InstructionFact, load_megadrive_ghidra_facts
from .ghidra import run_megadrive_analysis
from .megadrive import load_megadrive
from .toolchain import toolchain_status


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_instructions(
    path: Path, input_sha256: str, facts: dict[int, InstructionFact]
) -> None:
    instructions = []
    for fact in (facts[offset] for offset in sorted(facts)):
        instructions.append(
            {
                "id": f"megadrive.m68k.{fact.cpu_address:06X}",
                "cpu_id": "m68k",
                "address_space": "m68k",
                "physical_offset": fact.physical_offset,
                "logical_address": fact.cpu_address,
                "length": fact.length,
                "bytes": fact.raw.hex(" ").upper(),
                "mnemonic": fact.mnemonic,
                "operands": fact.operands,
                "flows": [
                    {"address_space": "m68k", "logical_address": target}
                    for target in fact.flows
                ],
                "flow_type": fact.flow_type,
                "backend": {
                    "space": fact.backend_space,
                    "block": fact.backend_block,
                    "symbol": fact.backend_symbol,
                    "function": fact.backend_function,
                },
            }
        )
    document = {
        "schema": "retrolarium.instructions",
        "schema_version": 1,
        "platform": "megadrive",
        "input_sha256": input_sha256,
        "cpu_id": "m68k",
        "address_space": "m68k",
        "instructions": instructions,
    }
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def analyze_m68k(
    rom: Path, output: Path, ghidra_home: Path
) -> dict[str, object]:
    image = load_megadrive(rom)
    toolchain_status(ghidra_home)
    output = output.resolve()
    program_root = output / "m68k"
    program_root.mkdir(parents=True, exist_ok=True)
    analysis_input = program_root / "analysis-input.bin"
    analysis_input.write_bytes(image.data)
    scripts = Path(__file__).resolve().parent / "ghidra_scripts"
    artifacts = run_megadrive_analysis(
        analysis_input, program_root, ghidra_home.resolve(), scripts
    )
    facts = load_megadrive_ghidra_facts(artifacts.facts, image)
    instructions = program_root / "instructions.json"
    _write_instructions(instructions, image.sha256, facts)
    report = json.loads(artifacts.report.read_text(encoding="utf-8"))
    manifest: dict[str, object] = {
        "schema": "retrolarium.megadrive.analysis",
        "schema_version": 1,
        "task": "megadrive.analyze",
        "input": {
            "sha256": image.sha256,
            "size": len(image.data),
            "format": "megadrive-cartridge",
        },
        "programs": [
            {
                "cpu_id": "m68k",
                "address_space": "m68k",
                "byte_order": "big",
                "language": report["language"],
                "compiler": report["compiler"],
                "analysis_input": "m68k/analysis-input.bin",
                "analysis_input_sha256": _sha256(analysis_input),
                "raw_facts": "m68k/instructions.tsv",
                "raw_facts_sha256": _sha256(artifacts.facts),
                "instructions": "m68k/instructions.json",
                "instructions_sha256": _sha256(instructions),
                "instruction_count": len(facts),
                "report": "m68k/program.json",
                "report_sha256": _sha256(artifacts.report),
            }
        ],
    }
    manifest_path = output / "analysis.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest
