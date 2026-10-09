"""First end-to-end NES disassembly pipeline."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess

from retrolarium_disasm.nes.ca65 import emit_project
from retrolarium_core.contracts import validate_disassembly_manifest
from retrolarium_disasm.facts import InstructionFact, load_ghidra_facts
from retrolarium_disasm.ghidra import GhidraArtifacts, _run_analysis, run_nes_analysis
from retrolarium_core.ines import (
    InesImage,
    PrgAnalysisTarget,
    cpu_to_prg_offset,
    load_ines,
    mapper_profile,
    mapper_projections,
    nrom_projections,
    prg_analysis_targets,
)
from retrolarium_disasm.nes.pointers import (
    PointerCandidate,
    accepted_code_entry_tables,
    accepted_pointer_tables,
    detect_banked_pointer_candidates,
    write_pointer_report,
)
from retrolarium_disasm.toolchain import toolchain_status
from retrolarium_disasm.verify import verify_exact


class PipelineError(RuntimeError):
    """A pipeline stage failed its explicit contract."""


def sha256_file(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


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
        "mapper_profile": mapper_profile(image).profile_id,
        "mirroring": image.mirroring,
        "battery": image.battery,
        "regions": [asdict(item) for item in image.regions],
        "projections": [asdict(item) for item in mapper_projections(image)],
    }


def asset_manifest(image: InesImage) -> dict[str, object]:
    regions = {region.name: region for region in image.regions}
    items: list[dict[str, object]] = [
        {
            "id": "nes.container.header",
            "kind": "container_header",
            "path": "generated/assets/header.bin",
            "asset_file_offset": 0,
            "rom_file_offset": regions["header"].file_offset,
            "size": len(image.header),
            "sha256": regions["header"].sha256,
        }
    ]
    if image.trainer:
        items.append(
            {
                "id": "nes.container.trainer",
                "kind": "trainer",
                "path": "generated/assets/trainer.bin",
                "asset_file_offset": 0,
                "rom_file_offset": regions["trainer"].file_offset,
                "size": len(image.trainer),
                "sha256": regions["trainer"].sha256,
            }
        )
    chr_region = regions.get("chr")
    if chr_region is not None:
        for projection in mapper_projections(image):
            if projection.region != "chr":
                continue
            payload = image.chr[
                projection.physical_start:projection.physical_end + 1
            ]
            items.append(
                {
                    "id": f"nes.chr.bank{projection.bank:02d}",
                    "kind": "chr_bank",
                    "path": "generated/assets/chr.bin",
                    "asset_file_offset": projection.physical_start,
                    "rom_file_offset": (
                        chr_region.file_offset + projection.physical_start
                    ),
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "address": {
                        "space": projection.cpu_space,
                        "start": projection.cpu_start,
                        "end": projection.cpu_end,
                        "bank": projection.bank,
                        "selector": projection.selector,
                    },
                }
            )
    return {
        "schema": "retrolarium.assets",
        "schema_version": 1,
        "items": items,
    }


def _write_instruction_facts(
    path: Path, image: InesImage, facts: dict[int, InstructionFact]
) -> None:
    instructions = []
    for fact in (facts[offset] for offset in sorted(facts)):
        instructions.append(
            {
                "id": (
                    f"nes.prg.bank{fact.bank:02d}."
                    f"{fact.cpu_address:04X}"
                ),
                "physical_offset": fact.physical_offset,
                "bank": fact.bank,
                "cpu_address": fact.cpu_address,
                "length": fact.length,
                "bytes": fact.raw.hex(" ").upper(),
                "mnemonic": fact.mnemonic,
                "operands": fact.operands,
                "flows": [
                    {"bank": fact.bank, "cpu_address": target}
                    for target in fact.flows
                ],
                "flow_type": fact.flow_type,
                "backend_space": fact.backend_space,
                "backend_block": fact.backend_block,
                "backend_symbol": fact.backend_symbol,
                "backend_function": fact.backend_function,
            }
        )
    document = {
        "schema": "retrolarium.nes.instructions",
        "schema_version": 1,
        "input_sha256": image.sha256,
        "instructions": instructions,
    }
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


MAX_ENTRY_SEED_PASSES = 1
MAX_ENTRY_SEEDS_PER_BANK = 256


def _script_directory() -> Path:
    return Path(__file__).resolve().parents[1] / "ghidra" / "scripts"


def _run_seeded_nes_analysis(
    image: Path,
    workspace: Path,
    ghidra_home: Path,
    script_directory: Path,
    seed_plan: Path,
) -> GhidraArtifacts:
    """Rerun NES analysis with a plan of extra code entry points.

    The plan is passed to the vector seed script as its first argument; one
    hexadecimal CPU address per line.
    """
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
        seed_arguments=(str(seed_plan.resolve()),),
        export_block=None,
    )


def _bank_record(
    image: InesImage,
    target: PrgAnalysisTarget,
    output: Path,
    analysis_input: Path,
    artifacts: GhidraArtifacts,
    bank_facts: dict[int, InstructionFact],
) -> dict[str, object]:
    report = json.loads(artifacts.report.read_text(encoding="utf-8"))
    return {
        "bank": target.bank,
        "physical_start": target.physical_start,
        "physical_end": target.physical_end,
        "cpu_start": target.cpu_start,
        "analysis_input": analysis_input.relative_to(output).as_posix(),
        "analysis_input_sha256": target.image.sha256,
        "synthesized_mapper_zero_view": target.synthesized,
        "language": report["language"],
        "compiler": report["compiler"],
        "instruction_count": len(bank_facts),
        "facts": artifacts.facts.relative_to(output).as_posix(),
        "facts_sha256": sha256_file(artifacts.facts),
    }


def _analyze_prg_banks(
    image: InesImage,
    output: Path,
    ghidra_home: Path,
) -> tuple[dict[int, InstructionFact], list[dict[str, object]], Path]:
    targets = prg_analysis_targets(image)
    toolchain_status(ghidra_home)
    script_directory = _script_directory()
    combined_facts: dict[int, InstructionFact] = {}
    banks: list[dict[str, object]] = []
    for target in targets:
        bank_directory = output / "banks" / f"bank{target.bank:02d}"
        bank_directory.mkdir(parents=True, exist_ok=True)
        analysis_input = bank_directory / "analysis-input.nes"
        analysis_input.write_bytes(target.image.data)
        artifacts = run_nes_analysis(
            analysis_input,
            bank_directory,
            ghidra_home.resolve(),
            script_directory,
        )
        bank_facts = load_ghidra_facts(artifacts.facts, image, bank=target.bank)
        overlap = set(combined_facts) & set(bank_facts)
        if overlap:
            first = min(overlap)
            raise PipelineError(f"PRG analyses overlap at physical offset {first:#x}")
        combined_facts.update(bank_facts)
        banks.append(
            _bank_record(image, target, output, analysis_input, artifacts, bank_facts)
        )
    facts_path = output / "instructions.json"
    output.mkdir(parents=True, exist_ok=True)
    _write_instruction_facts(facts_path, image, combined_facts)
    return combined_facts, banks, facts_path


def dispatch_entry_seeds(
    image: InesImage,
    facts: dict[int, InstructionFact],
    candidates: tuple[PointerCandidate, ...],
) -> dict[int, tuple[int, ...]]:
    """Undecoded targets of accepted dispatch tables, grouped by PRG bank."""
    targets = {target.bank: target for target in prg_analysis_targets(image)}
    seeds: dict[int, set[int]] = {}
    for candidate in accepted_code_entry_tables(candidates):
        target = targets.get(candidate.bank)
        if target is None:
            continue
        for entry in candidate.entries:
            try:
                local = cpu_to_prg_offset(target.image, entry.target)
            except ValueError:
                continue
            if target.physical_start + local in facts:
                continue
            seeds.setdefault(candidate.bank, set()).add(entry.target)
    return {
        bank: tuple(sorted(addresses)[:MAX_ENTRY_SEEDS_PER_BANK])
        for bank, addresses in sorted(seeds.items())
    }


def _reanalyze_with_entry_seeds(
    image: InesImage,
    output: Path,
    ghidra_home: Path,
    facts: dict[int, InstructionFact],
    banks: list[dict[str, object]],
    seeds: dict[int, tuple[int, ...]],
    pass_number: int,
) -> tuple[dict[int, InstructionFact], list[dict[str, object]], Path]:
    """Rerun only the banks that gained entry points; keep other banks as-is."""
    script_directory = _script_directory()
    targets = {target.bank: target for target in prg_analysis_targets(image)}
    combined = dict(facts)
    records = {int(record["bank"]): record for record in banks}
    for bank, addresses in seeds.items():
        target = targets[bank]
        bank_directory = output / "banks" / f"bank{bank:02d}" / f"pass{pass_number}"
        bank_directory.mkdir(parents=True, exist_ok=True)
        analysis_input = bank_directory / "analysis-input.nes"
        analysis_input.write_bytes(target.image.data)
        seed_plan = bank_directory / "entry-seeds.txt"
        seed_plan.write_text(
            "".join(f"{address:04X}\n" for address in addresses),
            encoding="utf-8",
            newline="\n",
        )
        artifacts = _run_seeded_nes_analysis(
            analysis_input,
            bank_directory,
            ghidra_home.resolve(),
            script_directory,
            seed_plan,
        )
        bank_facts = load_ghidra_facts(artifacts.facts, image, bank=bank)
        for offset in [
            offset
            for offset in combined
            if target.physical_start <= offset <= target.physical_end
        ]:
            del combined[offset]
        combined.update(bank_facts)
        decoded = sum(
            target.physical_start + cpu_to_prg_offset(target.image, address)
            in bank_facts
            for address in addresses
        )
        record = _bank_record(
            image, target, output, analysis_input, artifacts, bank_facts
        )
        record["entry_seed_pass"] = {
            "pass": pass_number,
            "plan": seed_plan.relative_to(output).as_posix(),
            "requested": len(addresses),
            "decoded": decoded,
        }
        records[bank] = record
    facts_path = output / "instructions.json"
    _write_instruction_facts(facts_path, image, combined)
    return combined, [records[bank] for bank in sorted(records)], facts_path


def _analyze_with_dispatch_passes(
    image: InesImage,
    output: Path,
    ghidra_home: Path,
) -> tuple[
    dict[int, InstructionFact],
    list[dict[str, object]],
    Path,
    tuple[PointerCandidate, ...],
]:
    facts, banks, facts_path = _analyze_prg_banks(image, output, ghidra_home)
    candidates = detect_banked_pointer_candidates(image, facts)
    attempted: set[tuple[int, int]] = set()
    for pass_number in range(2, 2 + MAX_ENTRY_SEED_PASSES):
        seeds = {
            bank: tuple(
                address for address in addresses if (bank, address) not in attempted
            )
            for bank, addresses in dispatch_entry_seeds(
                image, facts, candidates
            ).items()
        }
        seeds = {bank: addresses for bank, addresses in seeds.items() if addresses}
        if not seeds:
            break
        attempted.update(
            (bank, address) for bank, addresses in seeds.items() for address in addresses
        )
        facts, banks, facts_path = _reanalyze_with_entry_seeds(
            image, output, ghidra_home, facts, banks, seeds, pass_number
        )
        candidates = detect_banked_pointer_candidates(image, facts)
    return facts, banks, facts_path, candidates


def analyze_mapper_banks(
    rom: Path,
    output: Path,
    ghidra_home: Path,
) -> dict[str, object]:
    """Analyze every canonical PRG projection in an isolated Ghidra Program."""
    rom = rom.resolve()
    output = output.resolve()
    image = load_ines(rom)
    combined_facts, banks, facts_path = _analyze_prg_banks(
        image, output, ghidra_home
    )
    manifest = {
        "schema": "retrolarium.nes.analysis",
        "schema_version": 1,
        "task": "nes.analyze",
        "mode": "blind",
        "input": image_manifest(image),
        "backend": {"id": "ghidra", "banks": banks},
        "facts": {
            "instruction_count": len(combined_facts),
            "path": facts_path.relative_to(output).as_posix(),
            "sha256": sha256_file(facts_path),
        },
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest


def disassemble_nes(
    rom: Path,
    output: Path,
    ghidra_home: Path,
    *,
    build_container: str | None = None,
) -> dict[str, object]:
    rom = rom.resolve()
    output = output.resolve()
    image = load_ines(rom)
    analysis_dir = output / "analysis"
    generated_dir = output / "generated"
    facts, banks, facts_path, pointer_candidates = _analyze_with_dispatch_passes(
        image, analysis_dir, ghidra_home
    )
    write_pointer_report(analysis_dir / "pointers.json", image, pointer_candidates)
    emission = emit_project(generated_dir, image, facts, pointer_candidates)
    targets = prg_analysis_targets(image)
    source_units = (
        ["generated/src/prg.asm"]
        if len(targets) == 1
        else [
            f"generated/src/prg-bank{target.bank:02d}.asm"
            for target in targets
        ]
    )
    symbols_path = generated_dir / "symbols.json"
    manifest: dict[str, object] = {
        "schema": "retrolarium.nes.disassembly",
        "schema_version": 1,
        "task": "nes.disassemble",
        "mode": "blind",
        "input": image_manifest(image),
        "backend": {
            "id": "ghidra",
            "analysis_root": "analysis",
            "banks": banks,
        },
        "facts": {
            "instruction_count": len(facts),
            "path": "analysis/instructions.json",
            "sha256": sha256_file(facts_path),
            "instruction_bytes": emission.instruction_bytes,
            "pointer_bytes": emission.pointer_bytes,
            "raw_prg_bytes": emission.raw_bytes,
            "labels": emission.labels,
            "diagnostics": list(emission.diagnostics),
        },
        "assets": asset_manifest(image),
        "symbols": {
            "schema": "retrolarium.nes.symbols",
            "schema_version": 1,
            "count": len(emission.symbols),
            "path": "generated/symbols.json",
            "sha256": sha256_file(symbols_path),
        },
        "pointers": {
            "schema": "retrolarium.nes.pointers",
            "schema_version": 1,
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
            "path": "analysis/pointers.json",
            "sha256": sha256_file(analysis_dir / "pointers.json"),
        },
        "source": {
            "dialect": "ca65",
            "directory": "generated",
            "units": source_units,
            "coverage": "complete",
            "whole_rom_fallback": False,
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
                "output": "generated/build/rebuilt.nes",
                "default_container": build_container,
            },
            "verify": {
                "id": "retrolarium.project.verify",
                "artifact": "generated/build/rebuilt.nes",
                "expected_sha256": image.sha256,
                "expected_size": len(image.data),
            },
            "launch": {
                "id": "retrolarium.project.launch",
                "artifact": "generated/build/rebuilt.nes",
                "platform": "nes",
                "default_machine": "nes",
                "supported_machines": ["famicom", "nes", "nespal"],
                "supported_modes": ["interactive-plan", "smoke"],
            },
        },
        "verification": {"status": "not-run"},
    }
    if build_container is not None:
        rebuilt = build_in_container(generated_dir, build_container)
        manifest["verification"] = verify_exact(rom, rebuilt)
    output.mkdir(parents=True, exist_ok=True)
    validate_disassembly_manifest(manifest, output)
    manifest_path = output / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest


def disassemble_nrom(
    rom: Path,
    output: Path,
    ghidra_home: Path,
    *,
    build_container: str | None = None,
) -> dict[str, object]:
    """Compatibility entry point that retains the mapper-0 precondition."""
    image = load_ines(rom.resolve())
    nrom_projections(image)
    return disassemble_nes(
        rom,
        output,
        ghidra_home,
        build_container=build_container,
    )
