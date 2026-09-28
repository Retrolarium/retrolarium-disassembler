"""Mega Drive analysis pipeline with versioned, backend-neutral artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

from .contracts import validate_megadrive_disassembly_manifest
from .facts import (
    InstructionFact,
    load_megadrive_ghidra_facts,
    load_z80_ghidra_facts,
)
from .ghidra import GhidraArtifacts, run_megadrive_analysis, run_z80_analysis
from .megadrive import image_manifest, load_megadrive
from .m68k_abstract import (
    discover_packed_orphan_candidates,
    discover_ram_handler_candidates,
    interpret_known_cfg,
    retain_trusted_instruction_facts,
)
from .m68k_seeds import DecoderSeed, discover_initial_decoder_seeds
from .megadrive_emit import EmitResult, MegaDriveEmitError, emit_project
from .megadrive_pointers import (
    detect_pointer_candidates,
    discover_dispatch_table_seeds,
    write_pointer_report,
)
from .megadrive_symbols import generate_symbols, write_symbol_report
from .megadrive_z80 import (
    CrossCpuCopy, detect_z80_copies, fragment_z80_facts,
    group_z80_copies, z80_im1_handler_seed,
)
from .toolchain import toolchain_status
from .z80_dispatch import Z80DispatchTable, discover_z80_dispatch_tables


MAX_ABSTRACT_PASSES = 12


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_instructions(
    path: Path,
    input_sha256: str,
    facts: dict[int, InstructionFact],
    *,
    cpu_id: str,
    address_space: str,
) -> None:
    instructions = []
    for fact in (facts[offset] for offset in sorted(facts)):
        instructions.append(
            {
                "id": f"megadrive.{cpu_id}.{fact.cpu_address:06X}",
                "cpu_id": cpu_id,
                "address_space": address_space,
                "physical_offset": fact.physical_offset,
                "logical_address": fact.cpu_address,
                "length": fact.length,
                "bytes": fact.raw.hex(" ").upper(),
                "mnemonic": fact.mnemonic,
                "operands": fact.operands,
                "flows": [
                    {"address_space": address_space, "logical_address": target}
                    for target in fact.flows
                ],
                "references": [
                    {
                        "address_space": address_space,
                        "logical_address": reference.address,
                        "type": reference.reference_type,
                        "operand_index": reference.operand_index,
                    }
                    for reference in fact.references
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
        "cpu_id": cpu_id,
        "address_space": address_space,
        "instructions": instructions,
    }
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _program_record(
    output: Path,
    program_root: Path,
    artifacts: GhidraArtifacts,
    instructions: Path,
    facts: dict[int, InstructionFact],
    *,
    cpu_id: str,
    address_space: str,
    byte_order: str,
    analysis_input: Path,
) -> dict[str, object]:
    report = json.loads(artifacts.report.read_text(encoding="utf-8"))
    relative = lambda path: path.relative_to(output).as_posix()
    return {
        "cpu_id": cpu_id,
        "address_space": address_space,
        "byte_order": byte_order,
        "language": report["language"],
        "compiler": report["compiler"],
        "analysis_input": relative(analysis_input),
        "analysis_input_sha256": _sha256(analysis_input),
        "raw_facts": relative(artifacts.facts),
        "raw_facts_sha256": _sha256(artifacts.facts),
        "instructions": relative(instructions),
        "instructions_sha256": _sha256(instructions),
        "instruction_count": len(facts),
        "report": relative(artifacts.report),
        "report_sha256": _sha256(artifacts.report),
        "artifact_root": relative(program_root),
    }


def _edge_record(
    copy: CrossCpuCopy, payload_path: str, *, target_cpu_id: str | None = None
) -> dict[str, object]:
    return {
        "id": copy.edge_id,
        "schema_id": copy.schema_id,
        "kind": "memory_copy",
        "source": {
            "cpu_id": copy.source_cpu_id,
            "address_space": copy.source_space,
            "start": copy.source_start,
            "end": copy.source_end,
        },
        "target": {
            "cpu_id": target_cpu_id or copy.target_cpu_id,
            "address_space": copy.target_space,
            "start": copy.target_start,
            "end": copy.target_end,
        },
        "size": copy.size,
        "payload": payload_path,
        "payload_sha256": copy.payload_sha256,
        "evidence": [
            {
                "cpu_id": "m68k",
                "address_space": "m68k",
                "logical_address": address,
            }
            for address in copy.evidence_addresses
        ],
        "confidence": copy.confidence,
    }


def analyze_megadrive(
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
    seed_plan = program_root / "python-seeds.txt"
    (program_root / "abstract-entrypoints.json").unlink(missing_ok=True)
    initial_seeds = discover_initial_decoder_seeds(image)
    planned_seeds = {seed.address for seed in initial_seeds}
    seed_evidence: dict[int, set[str]] = {}
    seed_kinds: dict[int, set[str]] = {}
    seed_confidence: dict[int, set[str]] = {}
    seed_sources: dict[int, set[int]] = {}
    for seed in initial_seeds:
        seed_evidence.setdefault(seed.address, set()).add(seed.evidence)
        seed_kinds.setdefault(seed.address, set()).add(seed.kind)
        seed_confidence.setdefault(seed.address, set()).add(seed.confidence)
        if seed.source_address is not None:
            seed_sources.setdefault(seed.address, set()).add(
                seed.source_address
            )
    seed_plan.write_text(
        "".join(f"{address:06X}\n" for address in sorted(planned_seeds)),
        encoding="ascii",
        newline="\n",
    )
    abstract_passes = []
    converged = False
    for pass_index in range(MAX_ABSTRACT_PASSES):
        artifacts = run_megadrive_analysis(
            analysis_input,
            program_root,
            ghidra_home.resolve(),
            scripts,
            seed_plan=seed_plan,
        )
        facts = load_megadrive_ghidra_facts(artifacts.facts, image)
        abstract_result = interpret_known_cfg(
            image, facts, additional_entrypoints=planned_seeds
        )
        abstract_candidates = discover_ram_handler_candidates(image, facts)
        orphan_candidates = discover_packed_orphan_candidates(image, facts)
        # Dispatch sites must themselves be trusted code, never an island.
        trusted_facts = retain_trusted_instruction_facts(
            image,
            facts,
            additional_entrypoints=planned_seeds | {
                edge.target_address
                for edge in abstract_result.indirect_edges
                if edge.confidence == "proven"
            },
        )
        # A backend-decoded island is still an orphan until it has a root.
        # Discover packed gaps in the trusted CFG as well as undecoded gaps.
        orphan_candidates = tuple({
            candidate.address: candidate
            for candidate in (
                *orphan_candidates,
                *discover_packed_orphan_candidates(image, trusted_facts),
            )
        }.values())
        dispatch_seeds = list(discover_dispatch_table_seeds(image, trusted_facts))
        # A structurally proven dispatcher can itself be an unreachable code
        # island. Bootstrap only strong tables from backend facts, then make
        # the dispatcher a planned root on the next decoder pass.
        raw_dispatch = discover_dispatch_table_seeds(image, facts)
        decoded_starts = {fact.cpu_address for fact in facts.values()}
        trusted_starts = {fact.cpu_address for fact in trusted_facts.values()}
        by_dispatch: dict[int, list[DecoderSeed]] = {}
        for seed in raw_dispatch:
            if seed.source_address is not None:
                by_dispatch.setdefault(seed.source_address, []).append(seed)
        for site, table_seeds in by_dispatch.items():
            if site in trusted_starts:
                continue
            targets = {seed.address for seed in table_seeds}
            decoded_targets = len(targets & decoded_starts)
            if (
                len(targets) < 4
                or decoded_targets == 0
                or (decoded_targets == 1 and len(table_seeds) < 8)
            ):
                continue
            dispatch_seeds.extend(table_seeds)
            dispatch_seeds.append(DecoderSeed(
                address=site,
                kind="indexed_dispatch_site",
                confidence="high",
                evidence=table_seeds[0].evidence,
                source_address=site,
            ))
        dispatch_targets = {
            seed.address
            for seed in dispatch_seeds
            if seed.address not in planned_seeds
        }
        indirect_targets = {
            edge.target_address
            for edge in abstract_result.indirect_edges
            if edge.confidence == "proven"
            if edge.target_address not in facts
            and edge.target_address not in planned_seeds
        }
        handler_targets = {
            candidate.address
            for candidate in abstract_candidates
            if candidate.confidence == "proven"
            and candidate.address not in facts
            and candidate.address not in planned_seeds
        }
        orphan_targets = {
            candidate.address
            for candidate in orphan_candidates
            if candidate.confidence == "high"
            and candidate.address not in trusted_facts
            and candidate.address not in planned_seeds
        }
        discovered = sorted(
            indirect_targets | handler_targets | orphan_targets
            | dispatch_targets
        )
        for seed in dispatch_seeds:
            if seed.address in discovered:
                seed_evidence.setdefault(seed.address, set()).add(
                    seed.evidence
                )
                seed_kinds.setdefault(seed.address, set()).add(seed.kind)
                seed_confidence.setdefault(seed.address, set()).add(
                    seed.confidence
                )
                seed_sources.setdefault(seed.address, set()).add(
                    seed.source_address
                )
        for edge in abstract_result.indirect_edges:
            if edge.target_address in discovered:
                seed_evidence.setdefault(edge.target_address, set()).add(
                    edge.evidence
                )
                seed_kinds.setdefault(edge.target_address, set()).add(
                    "abstract_indirect_target"
                )
                seed_confidence.setdefault(edge.target_address, set()).add(
                    edge.confidence
                )
                seed_sources.setdefault(edge.target_address, set()).add(
                    edge.source_address
                )
        for candidate in abstract_candidates:
            if candidate.address in discovered:
                seed_evidence.setdefault(candidate.address, set()).add(
                    candidate.evidence
                )
                seed_kinds.setdefault(candidate.address, set()).add(
                    "ram_handler"
                )
                seed_confidence.setdefault(candidate.address, set()).add(
                    candidate.confidence
                )
                seed_sources.setdefault(candidate.address, set()).add(
                    candidate.source_address
                )
        for candidate in orphan_candidates:
            if candidate.address in discovered:
                seed_evidence.setdefault(candidate.address, set()).add(
                    candidate.evidence
                )
                seed_kinds.setdefault(candidate.address, set()).add(
                    "packed_orphan"
                )
                seed_confidence.setdefault(candidate.address, set()).add(
                    candidate.confidence
                )
                seed_sources.setdefault(candidate.address, set()).add(
                    candidate.preceding_address
                )
        abstract_passes.append({
            "pass": pass_index + 1,
            "decoded_instruction_count": len(facts),
            "reached_instruction_count": len(
                abstract_result.reached_addresses
            ),
            "new_seed_addresses": discovered,
            "new_seed_evidence": [
                {
                    "address": address,
                    "evidence": sorted(seed_evidence[address]),
                }
                for address in discovered
            ],
        })
        if not discovered:
            converged = True
            break
        planned_seeds.update(discovered)
        seed_plan.write_text(
            "".join(f"{address:06X}\n" for address in sorted(planned_seeds)),
            encoding="ascii",
            newline="\n",
        )
    if not converged:
        raise ValueError(
            "M68K abstract analysis did not converge after "
            f"{MAX_ABSTRACT_PASSES} decoder passes"
        )
    proven_indirect_targets = {
        edge.target_address
        for edge in abstract_result.indirect_edges
        if edge.confidence == "proven"
    }
    unfiltered_facts = facts
    facts = retain_trusted_instruction_facts(
        image,
        facts,
        additional_entrypoints=planned_seeds | proven_indirect_targets,
    )
    discarded_backend_addresses = sorted(
        fact.cpu_address
        for offset, fact in unfiltered_facts.items()
        if offset not in facts
    )
    abstract_result = interpret_known_cfg(
        image, facts, additional_entrypoints=planned_seeds
    )
    abstract_candidates = discover_ram_handler_candidates(image, facts)
    orphan_candidates = discover_packed_orphan_candidates(image, facts)
    abstract_path = program_root / "abstract-analysis.json"
    abstract_path.write_text(
        json.dumps(
            {
                "schema": "retrolarium.m68k.abstract-analysis",
                "schema_version": 1,
                "input_sha256": image.sha256,
                "converged": converged,
                "passes": abstract_passes,
                "decoder_seed_addresses": sorted(planned_seeds),
                "discarded_backend_instruction_addresses": (
                    discarded_backend_addresses
                ),
                "decoder_seed_evidence": [
                    {
                        "address": address,
                        "kinds": sorted(seed_kinds.get(address, set())),
                        "confidence": sorted(
                            seed_confidence.get(address, set())
                        ),
                        "source_addresses": sorted(
                            seed_sources.get(address, set())
                        ),
                        "evidence": sorted(seed_evidence.get(address, set())),
                    }
                    for address in sorted(planned_seeds)
                ],
                "entrypoint_candidates": [
                    {
                        "address": candidate.address,
                        "source_address": candidate.source_address,
                        "storage_address": candidate.storage_address,
                        "confidence": candidate.confidence,
                        "evidence": candidate.evidence,
                        "already_disassembled": candidate.address in facts,
                    }
                    for candidate in abstract_candidates
                ],
                "orphan_candidates": [
                    {
                        "address": candidate.address,
                        "preceding_address": candidate.preceding_address,
                        "following_address": candidate.following_address,
                        "gap_size": candidate.gap_size,
                        "confidence": candidate.confidence,
                        "evidence": candidate.evidence,
                        "already_disassembled": candidate.address in facts,
                    }
                    for candidate in orphan_candidates
                ],
                "control_flow": {
                    "reached_instruction_count": len(
                        abstract_result.reached_addresses
                    ),
                    "state_updates": abstract_result.state_updates,
                    "widened_addresses": list(
                        abstract_result.widened_addresses
                    ),
                    "unresolved_indirect_addresses": list(
                        abstract_result.unresolved_indirect_addresses
                    ),
                    "indirect_edges": [
                        {
                            "source_address": edge.source_address,
                            "target_address": edge.target_address,
                            "mnemonic": edge.mnemonic,
                            "evidence": edge.evidence,
                            "confidence": edge.confidence,
                            "target_already_disassembled": (
                                edge.target_address in facts
                            ),
                        }
                        for edge in abstract_result.indirect_edges
                    ],
                    "conditional_branches": {
                        "true": sum(
                            decision.outcome.value == "true"
                            for decision in abstract_result.branch_decisions
                        ),
                        "false": sum(
                            decision.outcome.value == "false"
                            for decision in abstract_result.branch_decisions
                        ),
                        "unknown": sum(
                            decision.outcome.value == "unknown"
                            for decision in abstract_result.branch_decisions
                        ),
                        "decisions": [
                            {
                                "source_address": decision.source_address,
                                "target_address": decision.target_address,
                                "fallthrough_address": (
                                    decision.fallthrough_address
                                ),
                                "condition": decision.condition,
                                "outcome": decision.outcome.value,
                            }
                            for decision in abstract_result.branch_decisions
                        ],
                    },
                },
            },
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    instructions = program_root / "instructions.json"
    _write_instructions(
        instructions,
        image.sha256,
        facts,
        cpu_id="m68k",
        address_space="m68k",
    )
    pointer_candidates = detect_pointer_candidates(image, facts)
    pointers_path = output / "pointers.json"
    write_pointer_report(pointers_path, image, pointer_candidates)
    programs = [
        _program_record(
            output,
            program_root,
            artifacts,
            instructions,
            facts,
            cpu_id="m68k",
            address_space="m68k",
            byte_order="big",
            analysis_input=analysis_input,
        )
    ]
    programs[0]["abstract_analysis"] = abstract_path.relative_to(output).as_posix()
    programs[0]["abstract_analysis_sha256"] = _sha256(abstract_path)
    programs[0]["abstract_entrypoint_candidates"] = len(abstract_candidates)
    programs[0]["abstract_orphan_candidates"] = len(orphan_candidates)
    programs[0]["abstract_decoder_seed_count"] = len(planned_seeds)
    if seed_plan.is_file():
        programs[0]["abstract_decoder_seeds"] = (
            seed_plan.relative_to(output).as_posix()
        )
        programs[0]["abstract_decoder_seeds_sha256"] = _sha256(seed_plan)
    edges = []
    z80_symbol_programs = []
    copies = detect_z80_copies(image, facts)
    for index, logical in enumerate(group_z80_copies(copies)):
        z80_root = output / "z80" / f"program{index:02d}"
        z80_root.mkdir(parents=True, exist_ok=True)
        payload = logical.payload(image)
        base_address = logical.target_start
        z80_input = z80_root / "analysis-input.bin"
        z80_input.write_bytes(payload)
        z80_artifacts = run_z80_analysis(
            z80_input,
            z80_root,
            ghidra_home.resolve(),
            scripts,
            base_address=base_address,
        )
        z80_facts = load_z80_ghidra_facts(
            z80_artifacts.facts, payload, base_address=base_address
        )
        dispatch_by_start = {}
        for _ in range(4):
            discovered = discover_z80_dispatch_tables(
                payload, z80_facts, base_address=base_address
            )
            fresh = []
            for table in discovered:
                previous = dispatch_by_start.get(table.logical_start)
                if previous is None:
                    fresh.append(table)
                elif previous != table:
                    # New decoding may only tighten a table or reveal more
                    # sites sharing it; any other change is a contradiction.
                    if (table.lookup_address != previous.lookup_address
                            or previous.targets[:len(table.targets)]
                            != table.targets):
                        raise ValueError(
                            "Z80 dispatch table changed at "
                            f"0x{table.logical_start:04X}"
                        )
                    fresh.append(table)
            if not fresh:
                break
            dispatch_by_start.update(
                (table.logical_start, table) for table in fresh
            )
            dispatch_tables = tuple(
                dispatch_by_start[address] for address in sorted(dispatch_by_start)
            )
            z80_seed_plan = z80_root / "dispatch-seeds.txt"
            plan_lines = [
                f"T {table.logical_start - base_address:04X} "
                f"{table.logical_end - base_address:04X}"
                for table in dispatch_tables
            ]
            seeds = {
                target
                for table in dispatch_tables
                for target in table.targets
            }
            im1_handler = z80_im1_handler_seed(
                z80_facts, base_address, logical.size
            )
            if im1_handler is not None and not any(
                table.logical_start <= im1_handler < table.logical_end
                for table in dispatch_tables
            ):
                seeds.add(im1_handler)
            plan_lines.extend(
                f"S {target - base_address:04X}" for target in sorted(seeds)
            )
            z80_seed_plan.write_text(
                "\n".join(plan_lines) + "\n", encoding="ascii", newline="\n"
            )
            z80_artifacts = run_z80_analysis(
                z80_input,
                z80_root,
                ghidra_home.resolve(),
                scripts,
                base_address=base_address,
                seed_plan=z80_seed_plan,
            )
            z80_facts = load_z80_ghidra_facts(
                z80_artifacts.facts, payload, base_address=base_address
            )
            for table in dispatch_tables:
                if any(
                    fact.cpu_address < table.logical_end
                    and fact.cpu_address + fact.length > table.logical_start
                    for fact in z80_facts.values()
                ):
                    raise ValueError(
                        f"Z80 decoder ignored proven word table "
                        f"0x{table.logical_start:04X}..0x{table.logical_end:04X}"
                    )
        else:
            raise ValueError("Z80 dispatch analysis did not converge")
        dispatch_tables = tuple(
            dispatch_by_start[address] for address in sorted(dispatch_by_start)
        )
        dispatch_path = z80_root / "dispatch-tables.json"
        dispatch_path.write_text(
            json.dumps({
                "schema": "retrolarium.z80.dispatch-tables",
                "schema_version": 1,
                "input_sha256": _sha256(z80_input),
                "tables": [
                    {
                        "logical_start": table.logical_start,
                        "logical_end": table.logical_end,
                        "dispatch_address": table.dispatch_address,
                        "dispatch_addresses": list(
                            table.dispatch_addresses or (table.dispatch_address,)
                        ),
                        "lookup_address": table.lookup_address,
                        "targets": list(table.targets),
                    }
                    for table in dispatch_tables
                ],
            }, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        z80_instructions = z80_root / "instructions.json"
        cpu_id = f"z80.{index:02d}"
        _write_instructions(
            z80_instructions,
            image.sha256,
            z80_facts,
            cpu_id=cpu_id,
            address_space="z80",
        )
        program = _program_record(
            output,
            z80_root,
            z80_artifacts,
            z80_instructions,
            z80_facts,
            cpu_id=cpu_id,
            address_space="z80",
            byte_order="little",
            analysis_input=z80_input,
        )
        program["derived_from"] = [
            copy.edge_id for copy in logical.fragments
        ]
        program["dispatch_tables"] = dispatch_path.relative_to(output).as_posix()
        program["dispatch_tables_sha256"] = _sha256(dispatch_path)
        programs.append(program)
        z80_symbol_programs.append((cpu_id, base_address, z80_facts))
        for fragment_index, copy in enumerate(logical.fragments):
            fragment_path = z80_root / f"fragment{fragment_index:02d}.bin"
            fragment_path.write_bytes(logical.payload(image)[
                copy.target_start - base_address:
                copy.target_end - base_address + 1
            ])
            edges.append(_edge_record(
                copy, fragment_path.relative_to(output).as_posix(),
                target_cpu_id=cpu_id,
            ))

    evidence = {
        "schema": "retrolarium.cross-cpu-evidence",
        "schema_version": 1,
        "platform": "megadrive",
        "input_sha256": image.sha256,
        "edges": edges,
    }
    evidence_path = output / "cross-cpu-evidence.json"
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    symbols = generate_symbols(
        image, facts, pointer_candidates, tuple(z80_symbol_programs)
    )
    symbols_path = output / "symbols.json"
    write_symbol_report(symbols_path, image, symbols)
    manifest: dict[str, object] = {
        "schema": "retrolarium.megadrive.analysis",
        "schema_version": 1,
        "task": "megadrive.analyze",
        "input": {
            "sha256": image.sha256,
            "size": len(image.data),
            "format": "megadrive-cartridge",
        },
        "programs": programs,
        "pointers": {
            "path": "pointers.json",
            "sha256": _sha256(pointers_path),
            "candidate_count": len(pointer_candidates),
            "accepted_count": sum(
                candidate.status == "accepted"
                for candidate in pointer_candidates
            ),
        },
        "symbols": {
            "path": "symbols.json",
            "sha256": _sha256(symbols_path),
            "count": len(symbols),
        },
        "cross_cpu_evidence": {
            "path": "cross-cpu-evidence.json",
            "sha256": _sha256(evidence_path),
            "edge_count": len(edges),
        },
    }
    manifest_path = output / "analysis.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest


def analyze_m68k(
    rom: Path, output: Path, ghidra_home: Path
) -> dict[str, object]:
    """Compatibility name for the complete multi-program analysis pipeline."""
    return analyze_megadrive(rom, output, ghidra_home)


def _build_emitted_project(project: Path, container: str) -> Path:
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
        "sh",
        "-lc",
        "mkdir -p build && asl -xx -n -q -A -L -U -i . "
        "-o build/main.p src/main.s && "
        "p2bin build/main.p rebuilt.bin -p=FF",
    ]
    result = subprocess.run(command, text=True)
    if result.returncode:
        raise MegaDriveEmitError(
            f"ASL container build failed with exit code {result.returncode}"
        )
    rebuilt = project / "rebuilt.bin"
    if not rebuilt.is_file():
        raise MegaDriveEmitError(f"expected rebuilt ROM was not produced: {rebuilt}")
    return rebuilt


def _load_z80_dispatch_tables(path: Path) -> tuple[Z80DispatchTable, ...]:
    if not path.is_file():
        return ()
    document = json.loads(path.read_text(encoding="utf-8"))
    return tuple(
        Z80DispatchTable(
            logical_start=table["logical_start"],
            logical_end=table["logical_end"],
            dispatch_address=table["dispatch_address"],
            lookup_address=table["lookup_address"],
            targets=tuple(table["targets"]),
            dispatch_addresses=tuple(table.get("dispatch_addresses", ())),
        )
        for table in document["tables"]
    )


def _emitted_assets(result: EmitResult) -> dict[str, object]:
    return {
        "schema": "retrolarium.assets",
        "schema_version": 1,
        "items": [
            {**item, "path": f"generated/{item['path']}"}
            for item in result.assets
        ],
    }


def disassemble_megadrive(
    rom: Path,
    output: Path,
    ghidra_home: Path,
    *,
    build_container: str | None = None,
) -> dict[str, object]:
    rom = rom.resolve()
    output = output.resolve()
    image = load_megadrive(rom)
    analysis_root = output / "analysis"
    analysis = analyze_megadrive(rom, analysis_root, ghidra_home)
    m68k_facts = load_megadrive_ghidra_facts(
        analysis_root / "m68k" / "instructions.tsv", image
    )
    abstract_analysis = json.loads(
        (analysis_root / "m68k" / "abstract-analysis.json").read_text(
            encoding="utf-8"
        )
    )
    proven_indirect_targets = {
        edge["target_address"]
        for edge in abstract_analysis["control_flow"]["indirect_edges"]
        if edge["confidence"] == "proven"
    }
    m68k_facts = retain_trusted_instruction_facts(
        image,
        m68k_facts,
        additional_entrypoints=(
            set(abstract_analysis["decoder_seed_addresses"])
            | proven_indirect_targets
        ),
    )
    pointers = detect_pointer_candidates(image, m68k_facts)
    copies = detect_z80_copies(image, m68k_facts)
    z80_programs = []
    z80_dispatch_tables = []
    z80_by_edge = {}
    for index, logical in enumerate(group_z80_copies(copies)):
        payload = logical.payload(image)
        program_root = analysis_root / "z80" / f"program{index:02d}"
        facts = load_z80_ghidra_facts(
            program_root / "instructions.tsv",
            payload,
            base_address=logical.target_start,
        )
        tables = _load_z80_dispatch_tables(program_root / "dispatch-tables.json")
        for copy in logical.fragments:
            fragment_facts = fragment_z80_facts(logical, facts, copy)
            fragment_tables = tuple(
                table for table in tables
                if copy.target_start <= table.logical_start
                and table.logical_end <= copy.target_end + 1
            )
            z80_by_edge[copy.edge_id] = (
                f"z80.{index:02d}", fragment_facts, fragment_tables
            )
    for index, copy in enumerate(copies):
        cpu_id, facts, tables = z80_by_edge[copy.edge_id]
        z80_programs.append((cpu_id, copy.target_start, facts))
        z80_dispatch_tables.append(tables)
    symbols = generate_symbols(image, m68k_facts, pointers, tuple(z80_programs))
    generated = output / "generated"
    emitted = emit_project(
        generated, image, m68k_facts, pointers, symbols, copies,
        tuple(z80_programs),
        tuple(z80_dispatch_tables),
    )

    verification: dict[str, object] = {"status": "not-run"}
    if build_container is not None:
        rebuilt = _build_emitted_project(generated, build_container)
        from .pipeline import verify_exact

        verification = verify_exact(rom, rebuilt)
        verification["checksum_status"] = load_megadrive(rebuilt).checksum_status

    image_record = image_manifest(image)
    # Host input paths are provenance for the inspect command, not part of the
    # portable project contract.
    image_record.pop("source", None)
    manifest: dict[str, object] = {
        "schema": "retrolarium.megadrive.disassembly",
        "schema_version": 1,
        "task": "megadrive.disassemble",
        "mode": "blind",
        "input": image_record,
        "analysis": {
            "path": "analysis/analysis.json",
            "sha256": _sha256(analysis_root / "analysis.json"),
            "program_count": len(analysis["programs"]),
        },
        "pointers": {
            "path": "analysis/pointers.json",
            "sha256": _sha256(analysis_root / "pointers.json"),
        },
        "symbols": {
            "path": "analysis/symbols.json",
            "sha256": _sha256(analysis_root / "symbols.json"),
        },
        "cross_cpu_evidence": {
            "path": "analysis/cross-cpu-evidence.json",
            "sha256": _sha256(analysis_root / "cross-cpu-evidence.json"),
        },
        "assets": _emitted_assets(emitted),
        "source": {
            "dialect": "asl-exact-first",
            "directory": "generated",
            "units": [f"generated/{unit}" for unit in emitted.source_units],
            "coverage": {
                "rom_bytes": len(image.data),
                "vector_bytes": 0x100,
                "instruction_bytes": emitted.instruction_bytes,
                "symbolic_instruction_bytes": emitted.symbolic_instruction_bytes,
                "pointer_bytes": emitted.pointer_bytes,
                "asset_bytes": emitted.asset_bytes,
                "raw_bytes": emitted.raw_bytes,
                "padding_bytes": emitted.padding_bytes,
            },
            # Mnemonics count as verified only once ASL reproduced the ROM.
            "instruction_encoding": (
                "verified-mnemonics-with-exact-byte-fallback"
                if verification.get("status") == "exact"
                else "unverified-mnemonics-with-exact-byte-fallback"
            ),
        },
        "operations": {
            "build": {
                "id": "retrolarium.project.build",
                "runner": "docker" if build_container else "retrolarium-kit",
                "toolchain_suite": "megadrive",
                "recipe": "asl-p2bin-v1",
                "default_container": build_container,
                "project_directory": "generated",
                "source": "src/main.s",
                "object": "build/main.p",
                "z80_prebuild": list(emitted.z80_builds),
                **({"argv": [
                    "sh", "-lc",
                    "mkdir -p build && asl -xx -n -q -A -L -U -i . "
                    "-o build/main.p src/main.s && "
                    "p2bin build/main.p rebuilt.bin -p=FF",
                ]} if build_container else {}),
                "output": "generated/rebuilt.bin",
            },
            "verify": {
                "id": "retrolarium.project.verify",
                "artifact": "generated/rebuilt.bin",
                "expected_size": len(image.data),
                "expected_sha256": image.sha256,
            },
            "launch": {
                "id": "retrolarium.project.launch",
                "platform": "megadrive",
                "artifact": "generated/rebuilt.bin",
                "default_machine": "genesis",
                "supported_machines": ["genesis", "megadriv"],
                "supported_modes": ["interactive-plan", "smoke"],
            },
        },
        "verification": verification,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "retrolarium-project.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    validate_megadrive_disassembly_manifest(manifest, output)
    return manifest
