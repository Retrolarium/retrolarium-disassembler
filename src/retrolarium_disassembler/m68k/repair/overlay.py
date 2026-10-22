"""Iterative, binary-only discovery in an M68K program loaded at a nonzero base.

The address-indexed view is internal to the existing abstract interpreter;
only the original module bytes are imported into the decoder or emitted.
"""

from dataclasses import asdict, replace
import csv
import hashlib
import json
from pathlib import Path

from retrolarium_disassembler.facts import _load_ghidra_facts
from retrolarium_disassembler.ghidra import GhidraArtifacts, run_m68k_overlay_analysis
from retrolarium_core.megadrive import MegaDriveImage, M68kVector, parse_megadrive
from retrolarium_disassembler.m68k.abstract import (
    interpret_trusted_cfg,
    discover_packed_orphan_candidates,
    discover_object_field_handler_candidates,
    discover_ram_handler_candidates,
    MAX_BACKEND_COMPUTED_FLOW_TARGETS,
)
from retrolarium_disassembler.megadrive.pointers import (
    discover_dispatch_table_seeds,
    can_bootstrap_dispatch_seeds,
    detect_pointer_candidates,
)
from retrolarium_disassembler.m68k.repair.unused import discover_validated_unused_candidates
from retrolarium_disassembler.m68k.dispatch.witness import make_dispatch_handler_validator
from retrolarium_disassembler.m68k.repair.probe_requests import M68kProbeRequests
from retrolarium_disassembler.m68k.repair.fallthrough import M68kFallthroughRepairs
from retrolarium_disassembler.megadrive.emit import _asm_instruction
from retrolarium_disassembler.m68k.seeds import discover_dense_branch_table_seeds, discover_indexed_branch_table_seeds
from retrolarium_disassembler.m68k.callbacks.relative_record import discover_relative_record_callback_seeds
from retrolarium_disassembler.m68k.records.cleared_pool_states import discover_cleared_pool_state_seeds
from retrolarium_disassembler.m68k.callbacks.absolute_ram import discover_absolute_ram_callback_seeds
from retrolarium_disassembler.m68k.records.finite import discover_finite_record_callback_seeds
from retrolarium_disassembler.m68k.dispatch.indexed import (
    discover_register_indexed_dispatch_seeds,
    discover_nested_word_dispatch_seeds,
    discover_added_index_dispatch_seeds,
    discover_dense_absolute_jump_seeds,
)


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
    return replace(
        image,
        data=b"\xff" * base + data,
        header=replace(image.header, rom_end=base + len(data) - 1, ram_start=0xFF0000, ram_end=0xFFFFFF),
        vector_table=(M68kVector(0, "stack", 0, 0),)
        + tuple(M68kVector(i + 1, "overlay_entry", e, e) for i, e in enumerate(entries)),
    )


def _normalize_bus_targets(facts):
    """Raw and pseudo decoders may sign-extend absolute .w operands."""
    return {
        a: replace(
            f,
            flows=tuple(t & 0xFFFFFF for t in f.flows),
            references=tuple(replace(r, address=r.address & 0xFFFFFF) for r in f.references),
        )
        for a, f in facts.items()
    }


def analyze_overlay(
    path: Path,
    workspace: Path,
    ghidra_home: Path,
    scripts: Path,
    *,
    base_address: int,
    entry_addresses: tuple[int, ...],
    max_passes: int = 32,
) -> GhidraArtifacts:
    data = path.read_bytes()
    image = address_view(data, base_address, entry_addresses)
    workspace.mkdir(parents=True, exist_ok=True)
    probe_plan = workspace / "decode-probe-requests.tsv"
    probe_plan.write_text("", encoding="ascii")
    probe_requests = M68kProbeRequests(image, minimum_address=base_address)
    fallthrough_repairs = M68kFallthroughRepairs(image, minimum_address=base_address)
    repair_plan = workspace / "fallthrough-repairs.tsv"
    repair_plan.write_text("", encoding="ascii")
    seen_probe_facts: set[int] = set()

    def request_decode(address, source_address=None, reason="structural handler decode"):
        # The internal image has an FF prefix; only real module bytes may be
        # requested from Ghidra's CD_MODULE block.
        if not isinstance(address, int) or not base_address <= address < base_address + len(data) - 1:
            return False
        return probe_requests.request(address, source_address, reason)

    planned = set(entry_addresses)
    planned.update(
        s.address
        for s in (
            *discover_dense_branch_table_seeds(image, scan_start=base_address),
            *discover_indexed_branch_table_seeds(image, scan_start=base_address),
            *discover_dense_absolute_jump_seeds(image, scan_start=base_address),
        )
        if base_address <= s.address < base_address + len(data)
    )
    passes = []
    for index in range(max_passes):
        artifacts = run_m68k_overlay_analysis(
            path,
            workspace,
            ghidra_home,
            scripts,
            base_address=base_address,
            entry_addresses=tuple(sorted(planned)),
            probe_orphans=True,
            probe_requests=probe_plan,
            fallthrough_repairs=repair_plan,
        )
        raw = _load_ghidra_facts(
            artifacts.facts, image.data, lambda a: a, bank=0, address_label="overlay", expected_block="CD_MODULE"
        )
        # The 68000 exposes only 24 address bits, including absolute .w targets.
        facts = _normalize_bus_targets(raw)
        trusted = interpret_trusted_cfg(image, facts, entrypoints=planned)
        probe_requests.update_known(trusted.facts)
        previous_requests = set(probe_requests.requests)
        probes = _load_ghidra_facts(
            artifacts.orphan_facts,
            image.data,
            lambda a: a,
            bank=0,
            address_label="overlay",
            expected_block="CD_MODULE",
            allow_empty=True,
            allow_overlaps=True,
        )
        probes = _normalize_bus_targets(probes)
        protected_ranges = tuple(
            (p.physical_start, p.physical_end)
            for p in detect_pointer_candidates(image, trusted.facts, scan_start=base_address)
            if p.status == "accepted"
        )
        validate_handler = make_dispatch_handler_validator(
            image,
            trusted.facts,
            {**probes, **facts},
            protected_ranges=protected_ranges,
            render_instruction=_asm_instruction,
            decode_request=request_decode,
        )

        def handler_validator(address):
            accepted = validate_handler(address)
            if not accepted:
                request_decode(address, address, "structural handler hypothesis")
            return accepted

        candidates: dict[int, str] = {}
        for fact in trusted.facts.values():
            if (
                fact.flow_type.upper() in {"COMPUTED_JUMP", "COMPUTED_CALL"}
                and len(fact.flows) > MAX_BACKEND_COMPUTED_FLOW_TARGETS
            ):
                continue
            for target in fact.flows:
                candidates[target] = f"direct flow from {fact.cpu_address:06X}"
        for edge in trusted.interpretation.indirect_edges:
            if edge.confidence == "proven":
                candidates[edge.target_address] = edge.evidence
        for seed in (
            *discover_dispatch_table_seeds(
                image, trusted.facts, handler_validator=handler_validator, entrypoints=trusted.roots
            ),
            *discover_relative_record_callback_seeds(
                image,
                trusted.facts,
                {**probes, **facts},
                protected_ranges=protected_ranges,
                decode_request=request_decode,
            ),
            *discover_cleared_pool_state_seeds(
                image,
                trusted.facts,
                {**probes, **facts},
                protected_ranges=protected_ranges,
                render_instruction=_asm_instruction,
            ),
            *discover_absolute_ram_callback_seeds(
                image,
                trusted.facts,
                {**probes, **facts},
                protected_ranges=protected_ranges,
                decode_request=request_decode,
            ),
            *discover_finite_record_callback_seeds(
                image,
                {**probes, **facts},
                execution_facts=trusted.facts,
                protected_ranges=protected_ranges,
                render_instruction=_asm_instruction,
                forbidden_reads=((0, base_address),),
                decode_request=request_decode,
            ),
            *discover_register_indexed_dispatch_seeds(image, trusted.facts),
            *discover_nested_word_dispatch_seeds(image, trusted.facts),
            *discover_added_index_dispatch_seeds(image, trusted.facts),
        ):
            candidates[seed.address] = seed.evidence
        tables = {}
        for seed in discover_dispatch_table_seeds(
            image, facts, handler_validator=handler_validator, entrypoints=trusted.roots
        ):
            tables.setdefault(seed.source_address, []).append(seed)
        for site, seeds in tables.items():
            if site not in trusted.facts and can_bootstrap_dispatch_seeds(seeds, facts.keys()):
                candidates[site] = seeds[0].evidence
                candidates.update((s.address, s.evidence) for s in seeds)
        unused, _ = discover_validated_unused_candidates(
            image, trusted.facts, {**probes, **facts}, render_instruction=_asm_instruction
        )
        candidates.update((c.address, c.evidence) for c in unused)
        for candidate in (
            *discover_object_field_handler_candidates(image, trusted.facts),
            *discover_ram_handler_candidates(image, trusted.facts),
        ):
            if candidate.confidence == "proven":
                candidates[candidate.address] = candidate.evidence
        for candidate in discover_packed_orphan_candidates(image, trusted.facts):
            if candidate.confidence == "high":
                candidates[candidate.address] = candidate.evidence
        discovered = {
            a: why
            for a, why in candidates.items()
            if base_address <= a < base_address + len(data) - 1
            and not a & 1
            and a not in planned
            and a not in trusted.facts
        }
        new_repairs = fallthrough_repairs.discover(
            facts,
            trusted.facts,
            {**probes, **facts},
            protected_ranges=protected_ranges,
            planned_roots=planned | set(discovered),
            decode_request=request_decode,
        )
        repair_plan.write_text(fallthrough_repairs.plan_text(), encoding="ascii", newline="\n")
        (workspace / "fallthrough-repairs.json").write_text(
            json.dumps(
                {
                    "schema": "retrolarium.m68k.fallthrough-repairs",
                    "schema_version": 1,
                    "input_sha256": hashlib.sha256(data).hexdigest(),
                    "load_base": base_address,
                    "candidate_repair_complete": not fallthrough_repairs.deferred,
                    "repairs": [asdict(repair) for _, repair in sorted(fallthrough_repairs.repairs.items())],
                    "deferred_addresses": sorted(fallthrough_repairs.deferred),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        new_requests = sorted(set(probe_requests.requests) - previous_requests)
        probe_addresses = set(probes) - set(facts)
        new_probe_fact_count = len(probe_addresses - seen_probe_facts)
        seen_probe_facts.update(probe_addresses)
        converged = not (discovered or new_requests or new_repairs)
        probe_plan.write_text(probe_requests.plan_text(), encoding="ascii", newline="\n")
        (workspace / "decode-probe-requests.json").write_text(
            json.dumps(
                {
                    "schema": "retrolarium.m68k.decode-probe-requests",
                    "schema_version": 1,
                    "input_sha256": hashlib.sha256(data).hexdigest(),
                    "load_base": base_address,
                    "candidate_probing_complete": not probe_requests.deferred,
                    "max_requests": probe_requests.max_requests,
                    "max_bytes": probe_requests.max_bytes,
                    "requests": [asdict(request) for _, request in sorted(probe_requests.requests.items())],
                    "deferred_addresses": sorted(probe_requests.deferred),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        passes.append(
            {
                "pass": index + 1,
                "decoded": len(facts),
                "trusted": len(trusted.facts),
                "new_seeds": discovered,
                "new_probe_request_addresses": new_requests,
                "probe_request_count": len(probe_requests.requests),
                "deferred_probe_request_count": len(probe_requests.deferred),
                "new_fallthrough_repair_addresses": [repair.address for repair in new_repairs],
                "fallthrough_repair_count": len(fallthrough_repairs.repairs),
                "deferred_fallthrough_repair_count": len(fallthrough_repairs.deferred),
                "new_probe_fact_count": new_probe_fact_count,
            }
        )
        (workspace / "decoder-passes.json").write_text(
            json.dumps(
                {
                    "passes": passes,
                    "converged": converged,
                    "candidate_repair_complete": not fallthrough_repairs.deferred,
                    "candidate_probing_complete": not probe_requests.deferred,
                },
                indent=2,
            )
            + "\n"
        )
        print(
            f"  overlay pass {index + 1}: {len(trusted.facts)} trusted, "
            f"{len(discovered)} new seeds, {len(new_requests)} new probe requests",
            flush=True,
        )
        if converged:
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
