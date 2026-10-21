"""Stable technical symbols derived from Mega Drive analysis evidence."""

from __future__ import annotations

from retrolarium_disassembler import AnalysisError

from dataclasses import dataclass
import json
from pathlib import Path

from retrolarium_disassembler.facts import InstructionFact
from retrolarium_disassembler.m68k.instructions import pc_displacement_target, pc_indexed_target
from retrolarium_core.megadrive import MegaDriveImage
from retrolarium_disassembler.megadrive.pointers import PointerCandidate
from retrolarium_disassembler.megadrive.structures import (
    discover_long_ff_padding,
    discover_standard_boot_setups,
)


@dataclass(frozen=True)
class TechnicalSymbol:
    symbol_id: str
    name: str
    kind: str
    cpu_id: str
    address_space: str
    logical_address: int
    physical_offset: int
    aliases: tuple[str, ...]
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.symbol_id,
            "name": self.name,
            "kind": self.kind,
            "cpu_id": self.cpu_id,
            "address_space": self.address_space,
            "logical_address": self.logical_address,
            "physical_offset": self.physical_offset,
            "aliases": list(self.aliases),
            "evidence": list(self.evidence),
        }


def _vector_alias(name: str, address: int) -> str:
    suffix = "".join(part.capitalize() for part in name.split("_"))
    return f"Vec_M68K_{suffix}_{address:06X}"


def _symbols_for_program(
    facts: dict[int, InstructionFact],
    *,
    cpu_id: str,
    address_space: str,
    address_width: int,
    base_address: int,
    end_address: int,
    entry_addresses: set[int],
    vector_aliases: dict[int, set[str]] | None = None,
    tables: dict[int, list[str]] | None = None,
    pointer_targets: set[int] | None = None,
) -> list[TechnicalSymbol]:
    vector_aliases = vector_aliases or {}
    tables = tables or {}
    pointer_targets = pointer_targets or set()
    instruction_interiors = {
        address
        for fact in facts.values()
        for address in range(fact.cpu_address + 1, fact.cpu_address + fact.length)
    }
    claims: dict[int, dict[str, set[str]]] = {}

    def claim(address: int, kind: str, evidence: str) -> None:
        # A linear assembly source cannot place a label between the bytes of an
        # already emitted instruction. Ghidra can report such flows when data is
        # misidentified as code; retain the numeric branch target in source.
        if address in instruction_interiors:
            return
        item = claims.setdefault(address, {})
        item.setdefault(kind, set()).add(evidence)

    for address in entry_addresses:
        claim(address, "entry", "program_entry")
    for fact in facts.values():
        if fact.backend_function:
            claim(fact.cpu_address, "subroutine", "backend_function_boundary")
        if cpu_id == "m68k":
            indexed = pc_indexed_target(fact)
            if indexed is not None:
                target = indexed[0]
                kind = "table" if fact.mnemonic.upper() in ("JSR", "JMP") else "offset"
                claim(target, kind, f"pc_indexed_from_{fact.cpu_address:X}")
            displacement_target = pc_displacement_target(fact)
            if displacement_target is not None:
                claim(displacement_target, "offset", f"pc_displacement_from_{fact.cpu_address:X}")
        for target in fact.flows:
            if "CALL" in fact.flow_type:
                claim(target, "subroutine", f"call_from_{fact.cpu_address:X}")
            else:
                claim(target, "location", f"flow_from_{fact.cpu_address:X}")
        for reference in fact.references:
            if "DATA" in reference.reference_type:
                claim(
                    reference.address,
                    "offset",
                    f"data_reference_from_{fact.cpu_address:X}",
                )
    for address, schema_ids in tables.items():
        for schema_id in schema_ids:
            claim(address, "table", f"accepted_pointer_schema:{schema_id}")
    for address in pointer_targets:
        claim(address, "location", "accepted_pointer_target")
    for address, aliases in vector_aliases.items():
        for alias in aliases:
            claim(address, "vector", f"vector_alias:{alias}")

    prefixes = {
        "entry": "Entry",
        "table": "tbl",
        "subroutine": "sub",
        "location": "loc",
        "vector": "Vec",
        "offset": "off",
    }
    priorities = ("entry", "table", "subroutine", "location", "vector", "offset")
    # Z80 programs uploaded to the same addresses keep apart by number: the
    # first is Z80, the next Z80p1, Z80p2 and so on.
    program = cpu_id.partition(".")[2]
    cpu_name = "M68K" if cpu_id == "m68k" else (
        "Z80" if not program.isdigit() or int(program) == 0 else f"Z80p{int(program)}")
    symbols: list[TechnicalSymbol] = []
    for address in sorted(claims):
        if not base_address <= address <= end_address:
            continue
        physical_offset = address - base_address
        kind_claims = claims[address]
        kind = next(item for item in priorities if item in kind_claims)
        name = f"{prefixes[kind]}_{cpu_name}_{address:0{address_width}X}"
        aliases = tuple(sorted(vector_aliases.get(address, set())))
        evidence = tuple(
            sorted(
                evidence
                for values in kind_claims.values()
                for evidence in values
            )
        )
        symbols.append(
            TechnicalSymbol(
                symbol_id=(
                    f"megadrive.{cpu_id}.{kind}.{address:0{address_width}x}"
                ),
                name=name,
                kind=kind,
                cpu_id=cpu_id,
                address_space=address_space,
                logical_address=address,
                physical_offset=physical_offset,
                aliases=aliases,
                evidence=evidence,
            )
        )
    return symbols


def generate_symbols(
    image: MegaDriveImage,
    m68k_facts: dict[int, InstructionFact],
    pointer_candidates: tuple[PointerCandidate, ...],
    z80_programs: tuple[tuple[str, int, dict[int, InstructionFact]], ...] = (),
) -> tuple[TechnicalSymbol, ...]:
    vector_aliases: dict[int, set[str]] = {}
    for vector in image.vector_table[1:]:
        if image.header.rom_start <= vector.address <= image.actual_rom_end:
            vector_aliases.setdefault(vector.address, set()).add(
                _vector_alias(vector.name, vector.address)
            )
    tables: dict[int, list[str]] = {}
    pointer_targets: set[int] = set()
    for candidate in pointer_candidates:
        if candidate.status == "accepted":
            tables.setdefault(candidate.logical_start, []).append(candidate.schema_id)
            pointer_targets.update(entry.target for entry in candidate.entries)
    for setup in discover_standard_boot_setups(image, m68k_facts):
        tables.setdefault(setup.logical_start, []).append(
            "megadrive.standard-boot-setup"
        )
    symbols = _symbols_for_program(
        m68k_facts,
        cpu_id="m68k",
        address_space="m68k",
        address_width=6,
        base_address=image.header.rom_start,
        end_address=image.actual_rom_end,
        entry_addresses={image.reset_address},
        vector_aliases=vector_aliases,
        tables=tables,
        pointer_targets=pointer_targets,
    )
    padding_ranges = discover_long_ff_padding(image, m68k_facts)
    symbols = [
        symbol for symbol in symbols
        if not any(
            start <= symbol.physical_offset < end
            for start, end in padding_ranges
        )
    ]
    for cpu_id, base_address, facts in z80_programs:
        symbols.extend(
            _symbols_for_program(
                facts,
                cpu_id=cpu_id,
                address_space="z80",
                address_width=4,
                base_address=base_address,
                end_address=base_address + max(
                    (fact.physical_offset + fact.length for fact in facts.values()),
                    default=0,
                ) - 1,
                entry_addresses={base_address},
            )
        )
    identifiers = [symbol.symbol_id for symbol in symbols]
    names = [symbol.name for symbol in symbols]
    if len(identifiers) != len(set(identifiers)) or len(names) != len(set(names)):
        raise AnalysisError("generated technical symbols are not unique")
    return tuple(symbols)


def write_symbol_report(
    path: Path, image: MegaDriveImage, symbols: tuple[TechnicalSymbol, ...]
) -> None:
    document = {
        "schema": "retrolarium.symbols",
        "schema_version": 1,
        "platform": "megadrive",
        "input_sha256": image.sha256,
        "symbols": [symbol.as_dict() for symbol in symbols],
    }
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
