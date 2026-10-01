"""Iterative, binary-only discovery in an M68K program loaded at a nonzero base.

The address-indexed view is internal to the existing abstract interpreter;
only the original module bytes are imported into the decoder or emitted.
"""
from dataclasses import replace
import csv
import json
from pathlib import Path

from .facts import _load_ghidra_facts
from .ghidra import GhidraArtifacts, run_m68k_overlay_analysis
from .megadrive import MegaDriveImage, M68kVector, parse_megadrive
from .m68k_abstract import (
    interpret_trusted_cfg, discover_packed_orphan_candidates,
    discover_object_field_handler_candidates, discover_ram_handler_candidates,
    MAX_BACKEND_COMPUTED_FLOW_TARGETS,
)
from .megadrive_pointers import discover_dispatch_table_seeds
from .m68k_unused import discover_validated_unused_candidates
from .megadrive_emit import _asm_instruction
from .m68k_seeds import discover_dense_branch_table_seeds, discover_indexed_branch_table_seeds
from .m68k_indexed_dispatch import (discover_register_indexed_dispatch_seeds,
                                  discover_nested_word_dispatch_seeds,
                                  discover_added_index_dispatch_seeds,
                                  discover_dense_absolute_jump_seeds)


def address_view(data: bytes, base: int, entries: tuple[int, ...]) -> MegaDriveImage:
    if base < 0x200 or base + len(data) > 0x1000000:
        raise ValueError("overlay must fit the 24-bit bus above the vector area")
    if not entries or any(e & 1 or not base <= e < base + len(data) - 1 for e in entries):
        raise ValueError("overlay entries must be aligned and backed by module bytes")
    header = bytearray(0x202)
    header[4:8] = (0x200).to_bytes(4, "big")
    header[0x100:0x104] = b"SEGA"
    header[0x1A4:0x1A8] = (0x201).to_bytes(4, "big")
    image = parse_megadrive(bytes(header))
    return replace(image, data=b"\xff" * base + data,
                   header=replace(image.header, rom_end=base + len(data) - 1,
                                  ram_start=0xFF0000, ram_end=0xFFFFFF),
                   vector_table=(M68kVector(0, "stack", 0, 0),) + tuple(
                       M68kVector(i + 1, "overlay_entry", e, e) for i, e in enumerate(entries)))


def analyze_overlay(path: Path, workspace: Path, ghidra_home: Path, scripts: Path,
                    *, base_address: int, entry_addresses: tuple[int, ...],
                    max_passes: int = 32) -> GhidraArtifacts:
    data = path.read_bytes()
    image = address_view(data, base_address, entry_addresses)
    planned = set(entry_addresses)
    planned.update(s.address for s in (
        *discover_dense_branch_table_seeds(image, scan_start=base_address),
        *discover_indexed_branch_table_seeds(image, scan_start=base_address),
        *discover_dense_absolute_jump_seeds(image, scan_start=base_address))
        if base_address <= s.address < base_address + len(data))
    passes = []
    for index in range(max_passes):
        artifacts = run_m68k_overlay_analysis(
            path, workspace, ghidra_home, scripts, base_address=base_address,
            entry_addresses=tuple(sorted(planned)), probe_orphans=True)
        raw = _load_ghidra_facts(artifacts.facts, image.data, lambda a: a,
                               bank=0, address_label="overlay", expected_block="CD_MODULE")
        # The 68000 exposes only 24 address bits, including absolute .w targets.
        facts = {a: replace(f, flows=tuple(t & 0xFFFFFF for t in f.flows),
                            references=tuple(replace(r, address=r.address & 0xFFFFFF)
                                             for r in f.references)) for a, f in raw.items()}
        trusted = interpret_trusted_cfg(image, facts, entrypoints=planned)
        candidates: dict[int, str] = {}
        for fact in trusted.facts.values():
            if fact.flow_type.upper() in {"COMPUTED_JUMP", "COMPUTED_CALL"} and len(fact.flows) > MAX_BACKEND_COMPUTED_FLOW_TARGETS:
                continue
            for target in fact.flows:
                candidates[target] = f"direct flow from {fact.cpu_address:06X}"
        for edge in trusted.interpretation.indirect_edges:
            if edge.confidence == "proven":
                candidates[edge.target_address] = edge.evidence
        for seed in (*discover_dispatch_table_seeds(image, trusted.facts),
                     *discover_register_indexed_dispatch_seeds(image, trusted.facts),
                     *discover_nested_word_dispatch_seeds(image, trusted.facts),
                     *discover_added_index_dispatch_seeds(image, trusted.facts)):
            candidates[seed.address] = seed.evidence
        tables = {}
        for seed in discover_dispatch_table_seeds(image, facts):
            tables.setdefault(seed.source_address, []).append(seed)
        for site, seeds in tables.items():
            targets = {s.address for s in seeds}
            decoded_targets = len(targets & facts.keys())
            if site not in trusted.facts and len(targets) >= 4 and (decoded_targets >= 2 or decoded_targets == 1 and len(seeds) >= 8):
                candidates[site] = seeds[0].evidence
                candidates.update((s.address, s.evidence) for s in seeds)
        probes = _load_ghidra_facts(artifacts.orphan_facts, image.data, lambda a: a,
                                  bank=0, address_label="overlay", expected_block="CD_MODULE",
                                  allow_empty=True, allow_overlaps=True)
        unused, _ = discover_validated_unused_candidates(
            image, trusted.facts, {**probes, **facts}, render_instruction=_asm_instruction)
        candidates.update((c.address, c.evidence) for c in unused)
        for candidate in (*discover_object_field_handler_candidates(image, trusted.facts),
                          *discover_ram_handler_candidates(image, trusted.facts)):
            if candidate.confidence == "proven":
                candidates[candidate.address] = candidate.evidence
        for candidate in discover_packed_orphan_candidates(image, trusted.facts):
            if candidate.confidence == "high":
                candidates[candidate.address] = candidate.evidence
        discovered = {a: why for a, why in candidates.items()
                      if base_address <= a < base_address + len(data) - 1 and not a & 1
                      and a not in planned and a not in trusted.facts}
        passes.append({"pass": index + 1, "decoded": len(facts), "trusted": len(trusted.facts),
                       "new_seeds": discovered})
        (workspace / "decoder-passes.json").write_text(
            json.dumps({"passes": passes, "converged": not discovered}, indent=2) + "\n")
        print(f"  overlay pass {index + 1}: {len(trusted.facts)} trusted, {len(discovered)} new seeds", flush=True)
        if not discovered:
            # Emission and comparison consume only instructions in the trusted CFG.
            with artifacts.facts.open(encoding="utf-8", newline="") as stream:
                reader = csv.DictReader(stream, delimiter="\t")
                fields = reader.fieldnames
                rows = [r for r in reader if int(r["address"], 16) in trusted.facts]
            with artifacts.facts.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fields, delimiter="\t", lineterminator="\n")
                writer.writeheader()
                writer.writerows(rows)
            return artifacts
        planned.update(discovered)
    raise ValueError(f"overlay analysis did not converge after {max_passes} passes")
