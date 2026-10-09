"""Blind SNES analysis and exact-first source-project orchestration."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

from retrolarium_core.contracts import validate_snes_disassembly_manifest
from retrolarium_disasm.facts import InstructionFact, load_spc700_ghidra_facts
from retrolarium_disasm.ghidra import run_spc700_analysis
from retrolarium_disasm.verify import verify_exact
from retrolarium_core.snes import image_manifest, load_snes
from retrolarium_disasm.snes.analysis import analysis_manifest, analyze_snes
from retrolarium_disasm.snes.emit import EmissionResult, emit_project
from retrolarium_disasm.snes.pointers import (
    accepted_pointer_tables,
    detect_pointer_candidates,
    write_pointer_report,
)
from retrolarium_disasm.snes.symbols import generate_symbols, write_symbol_report
from retrolarium_disasm.snes.spc700 import CrossCpuCopy, detect_spc700_copies, payload_for_copy
from retrolarium_disasm.toolchain import toolchain_status


class SnesPipelineError(RuntimeError):
    """A blind SNES pipeline stage failed its declared invariant."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def build_snes_in_container(project: Path, container: str) -> Path:
    project = project.resolve()
    command = [
        "docker",
        "run",
        "--rm",
        "--mount",
        f"type=bind,source={project},target=/work",
        "--workdir",
        "/work",
        container,
        "make",
        "all",
    ]
    result = subprocess.run(command, text=True)
    if result.returncode:
        raise SnesPipelineError(
            f"SNES ca65 container build failed with {result.returncode}"
        )
    rebuilt = project / "build" / "rebuilt.sfc"
    if not rebuilt.is_file():
        raise SnesPipelineError(f"expected rebuilt image was not produced: {rebuilt}")
    return rebuilt


def _emission_record(result: EmissionResult, path: Path) -> dict[str, object]:
    return {
        "path": "generated/emission.json",
        "sha256": _sha256(path),
        "bank_units": list(result.bank_units),
        "instruction_bytes": result.instruction_bytes,
        "instruction_fallback_bytes": result.instruction_fallback_bytes,
        "pointer_bytes": result.pointer_bytes,
        "header_bytes": result.header_bytes,
        "raw_bytes": result.raw_bytes,
        "labels": result.labels,
        "diagnostics": list(result.diagnostics),
    }


def _write_spc700_instructions(
    path: Path,
    input_sha256: str,
    cpu_id: str,
    facts: dict[int, InstructionFact],
) -> None:
    document = {
        "schema": "retrolarium.instructions",
        "schema_version": 1,
        "platform": "snes",
        "input_sha256": input_sha256,
        "cpu_id": cpu_id,
        "address_space": "spc700-ram",
        "instructions": [
            {
                "id": f"snes.{cpu_id}.{fact.cpu_address:04X}",
                "cpu_id": cpu_id,
                "address_space": "spc700-ram",
                "physical_offset": fact.physical_offset,
                "logical_address": fact.cpu_address,
                "length": fact.length,
                "bytes": fact.raw.hex(" ").upper(),
                "mnemonic": fact.mnemonic,
                "operands": fact.operands,
                "flows": [
                    {
                        "address_space": "spc700-ram",
                        "logical_address": target,
                    }
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
            for fact in (facts[offset] for offset in sorted(facts))
        ],
    }
    _write_json(path, document)


def _edge_record(copy: CrossCpuCopy, payload: str) -> dict[str, object]:
    return {
        "id": copy.edge_id,
        "schema_id": copy.schema_id,
        "kind": "memory_copy",
        "source": {
            "cpu_id": copy.source_cpu_id,
            "address_space": copy.source_space,
            "start": copy.source_start,
            "end": copy.source_end,
            "physical_start": copy.source_physical_start,
            "physical_end": copy.source_physical_end,
        },
        "target": {
            "cpu_id": copy.target_cpu_id,
            "address_space": copy.target_space,
            "start": copy.target_start,
            "end": copy.target_end,
        },
        "size": copy.size,
        "payload": payload,
        "payload_sha256": copy.payload_sha256,
        "evidence": [
            {
                "cpu_id": "w65c816",
                "address_space": "snes-rom",
                "logical_address": address,
            }
            for address in copy.evidence_addresses
        ],
        "confidence": copy.confidence,
    }


def _extract_spc700_programs(
    output: Path,
    image,
    copies: tuple[CrossCpuCopy, ...],
    ghidra_home: Path | None,
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    programs: list[dict[str, object]] = []
    edges: list[dict[str, object]] = []
    assets: list[dict[str, object]] = []
    if ghidra_home is not None and copies:
        toolchain_status(ghidra_home.resolve())
    scripts = Path(__file__).resolve().parents[1] / "ghidra" / "scripts"
    for index, copy in enumerate(copies):
        cpu_id = f"spc700.{index:02d}"
        root = output / "spc700" / f"program{index:02d}"
        root.mkdir(parents=True, exist_ok=True)
        analysis_input = root / "analysis-input.bin"
        analysis_input.write_bytes(payload_for_copy(image, copy))
        relative_input = analysis_input.relative_to(output).as_posix()
        program: dict[str, object] = {
            "cpu_id": cpu_id,
            "address_space": "spc700-ram",
            "byte_order": "little",
            "language": "SPC700:LE:16:default",
            "analysis_input": relative_input,
            "analysis_input_sha256": _sha256(analysis_input),
            "load_address": copy.target_start,
            "size": copy.size,
            "derived_from": copy.edge_id,
            "status": "extracted",
        }
        if ghidra_home is not None:
            artifacts = run_spc700_analysis(
                analysis_input,
                root,
                ghidra_home.resolve(),
                scripts,
                base_address=copy.target_start,
            )
            facts = load_spc700_ghidra_facts(
                artifacts.facts,
                analysis_input.read_bytes(),
                base_address=copy.target_start,
            )
            instructions = root / "instructions.json"
            _write_spc700_instructions(
                instructions, image.sha256, cpu_id, facts
            )
            report = json.loads(artifacts.report.read_text(encoding="utf-8"))
            program.update(
                {
                    "status": "analyzed",
                    "compiler": report["compiler"],
                    "raw_facts": artifacts.facts.relative_to(output).as_posix(),
                    "raw_facts_sha256": _sha256(artifacts.facts),
                    "instructions": instructions.relative_to(output).as_posix(),
                    "instructions_sha256": _sha256(instructions),
                    "instruction_count": len(facts),
                    "report": artifacts.report.relative_to(output).as_posix(),
                    "report_sha256": _sha256(artifacts.report),
                }
            )
        programs.append(program)
        edges.append(_edge_record(copy, relative_input))
        assets.append(
            {
                "id": f"snes.asset.spc700.{index:02d}",
                "kind": "spc700-program",
                "path": f"analysis/{relative_input}",
                "sha256": copy.payload_sha256,
                "size": copy.size,
                "status": "proven",
                "derived_from": copy.edge_id,
            }
        )
    return programs, edges, assets


def disassemble_snes(
    rom: Path,
    output: Path,
    *,
    ghidra_home: Path | None = None,
    build_container: str | None = None,
) -> dict[str, object]:
    rom = rom.resolve()
    output = output.resolve()
    image = load_snes(rom)
    analysis = analyze_snes(image)
    pointers = detect_pointer_candidates(image, analysis)
    symbols = generate_symbols(image, analysis, pointers)
    copies = detect_spc700_copies(image, analysis)

    analysis_dir = output / "analysis"
    generated_dir = output / "generated"
    w65c816_dir = analysis_dir / "w65c816"
    w65c816_dir.mkdir(parents=True, exist_ok=True)
    w65c816_input = w65c816_dir / "analysis-input.sfc"
    w65c816_input.write_bytes(image.data)
    state_path = analysis_dir / "state-analysis.json"
    pointers_path = analysis_dir / "pointers.json"
    symbols_path = analysis_dir / "symbols.json"
    _write_json(state_path, analysis_manifest(analysis))
    write_pointer_report(pointers_path, image, pointers)
    write_symbol_report(symbols_path, image, symbols)
    spc_programs, edges, assets = _extract_spc700_programs(
        analysis_dir, image, copies, ghidra_home
    )
    evidence = {
        "schema": "retrolarium.cross-cpu-evidence",
        "schema_version": 1,
        "platform": "snes",
        "input_sha256": image.sha256,
        "edges": edges,
        "opaque_policy": (
            "ROM bytes without complete static upload evidence remain raw assets"
        ),
    }
    evidence_path = analysis_dir / "cross-cpu-evidence.json"
    _write_json(evidence_path, evidence)
    programs: list[dict[str, object]] = [
        {
            "cpu_id": "w65c816",
            "address_space": "snes-rom",
            "byte_order": "little",
            "language": "65816:LE:24:snes",
            "analysis_input": "w65c816/analysis-input.sfc",
            "analysis_input_sha256": _sha256(w65c816_input),
            "instructions": "state-analysis.json",
            "instructions_sha256": _sha256(state_path),
            "instruction_count": len(analysis.instructions),
            "status": "independent-state-analysis",
        },
        *spc_programs,
    ]
    analysis_document = {
        "schema": "retrolarium.snes.analysis",
        "schema_version": 1,
        "task": "snes.analyze",
        "input": {
            "sha256": image.sha256,
            "rom_sha256": image.rom_sha256,
            "size": len(image.container_data),
            "rom_size": len(image.data),
            "mapping": image.header.map_mode,
        },
        "programs": programs,
    }
    analysis_path = analysis_dir / "analysis.json"
    _write_json(analysis_path, analysis_document)
    emission = emit_project(generated_dir, image, analysis, pointers, symbols)

    portable_input = image_manifest(image)
    portable_input["source"] = None
    manifest: dict[str, object] = {
        "schema": "retrolarium.snes.disassembly",
        "schema_version": 1,
        "task": "snes.disassemble",
        "mode": "blind",
        "input": portable_input,
        "analysis": {
            "path": "analysis/analysis.json",
            "sha256": _sha256(analysis_path),
            "program_count": len(programs),
        },
        "pointers": {
            "path": "analysis/pointers.json",
            "sha256": _sha256(pointers_path),
            "candidate_count": len(pointers),
            "accepted_count": len(accepted_pointer_tables(pointers)),
        },
        "symbols": {
            "path": "analysis/symbols.json",
            "sha256": _sha256(symbols_path),
            "count": len(symbols),
        },
        "cross_cpu_evidence": {
            "path": "analysis/cross-cpu-evidence.json",
            "sha256": _sha256(evidence_path),
            "edge_count": len(edges),
        },
        "assets": {
            "schema": "retrolarium.assets",
            "schema_version": 1,
            "items": assets,
        },
        "source": {
            "dialect": "ca65",
            "directory": "generated",
            "units": [f"generated/{unit}" for unit in emission.bank_units],
            "header_unit": "generated/src/header.asm",
            "coverage": {
                "rom_bytes": len(image.data),
                "copier_header_bytes": len(image.copier_header),
                "instruction_bytes": emission.instruction_bytes,
                "instruction_fallback_bytes": emission.instruction_fallback_bytes,
                "pointer_bytes": emission.pointer_bytes,
                "header_bytes": emission.header_bytes,
                "raw_bytes": emission.raw_bytes,
            },
            "whole_rom_fallback": False,
            "emission": _emission_record(
                emission, generated_dir / "emission.json"
            ),
        },
        "operations": {
            "build": {
                "id": "retrolarium.project.build",
                "runner": "retrolarium-kit",
                "toolchain_suite": "nes",
                "recipe": "ca65-ld65-v1",
                "project_directory": "generated",
                "source": "main.asm",
                "linker_config": "linker.cfg",
                "object": "build/main.o",
                "map": "build/rebuilt.map",
                "argv": ["make", "all"],
                "output": "generated/build/rebuilt.sfc",
                "default_container": build_container,
            },
            "verify": {
                "id": "retrolarium.project.verify",
                "artifact": "generated/build/rebuilt.sfc",
                "expected_sha256": image.sha256,
                "expected_size": len(image.container_data),
            },
            "launch": {
                "id": "retrolarium.project.launch",
                "artifact": "generated/build/rebuilt.sfc",
                "platform": "snes",
                "default_machine": "snes",
                "supported_machines": ["snes", "snespal"],
                "supported_modes": ["interactive-plan", "smoke"],
            },
        },
        "verification": {"status": "not-run"},
    }
    if build_container is not None:
        rebuilt = build_snes_in_container(generated_dir, build_container)
        verification = verify_exact(rom, rebuilt)
        verification["checksum_status"] = load_snes(rebuilt).checksum_status
        manifest["verification"] = verification
    validate_snes_disassembly_manifest(manifest, output)
    _write_json(output / "retrolarium-project.json", manifest)
    return manifest
