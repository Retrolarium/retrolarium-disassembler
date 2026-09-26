"""Explainable big-endian pointer schemas for Mega Drive cartridge ROMs."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re

from .facts import InstructionFact
from .megadrive import MegaDriveImage
from .m68k_seeds import (
    RamCopyRegion,
    discover_ram_copy_regions,
    discover_ram_trampoline_tables,
)


MIN_ENTRIES = 3
MIN_ACCEPTED_ENTRIES = 4
MAX_ENTRIES = 64


@dataclass(frozen=True)
class PointerEntry:
    physical_offset: int
    logical_address: int
    raw_value: int
    target: int
    base_address: int | None = None

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "physical_offset": self.physical_offset,
            "logical_address": self.logical_address,
            "raw_value": self.raw_value,
            "target": self.target,
        }
        if self.base_address is not None:
            result["base_address"] = self.base_address
        return result


@dataclass(frozen=True)
class PointerCandidate:
    candidate_id: str
    schema_id: str
    physical_start: int
    physical_end: int
    logical_start: int
    entry_size: int
    status: str
    score: int
    entries: tuple[PointerEntry, ...]
    evidence: tuple[str, ...]
    contradictions: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.candidate_id,
            "schema_id": self.schema_id,
            "physical_start": self.physical_start,
            "physical_end": self.physical_end,
            "logical_start": self.logical_start,
            "entry_size": self.entry_size,
            "status": self.status,
            "score": self.score,
            "entries": [entry.as_dict() for entry in self.entries],
            "evidence": list(self.evidence),
            "contradictions": list(self.contradictions),
        }


def _instruction_sets(
    facts: dict[int, InstructionFact],
) -> tuple[set[int], set[int], set[int]]:
    occupied: set[int] = set()
    interiors: set[int] = set()
    starts: set[int] = set()
    for fact in facts.values():
        starts.add(fact.cpu_address)
        occupied.update(range(fact.physical_offset, fact.physical_offset + fact.length))
        interiors.update(
            range(fact.physical_offset + 1, fact.physical_offset + fact.length)
        )
    return occupied, interiors, starts


def _referenced_addresses(facts: dict[int, InstructionFact]) -> set[int]:
    return {
        reference.address
        for fact in facts.values()
        for reference in fact.references
        if (
            "DATA" in reference.reference_type
            or "READ" in reference.reference_type
        )
    }


def _indexed_read_addresses(
    facts: dict[int, InstructionFact],
    mnemonics: frozenset[str],
) -> set[int]:
    """Return table bases read through an indexed operand."""
    addresses: set[int] = set()
    for fact in facts.values():
        if fact.mnemonic.upper() not in mnemonics:
            continue
        source = fact.operands.split("|", 1)[0].upper()
        if source.startswith("#") or "(" not in source or ",D" not in source:
            continue
        addresses.update(
            reference.address
            for reference in fact.references
            if (
                "DATA" in reference.reference_type
                or "READ" in reference.reference_type
            )
        )
    return addresses


def _indexed_long_read_addresses(
    facts: dict[int, InstructionFact],
) -> set[int]:
    """Return table bases read as indexed 32-bit values."""
    return _indexed_read_addresses(facts, frozenset({"MOVE.L", "MOVEA.L"}))


def _indexed_word_read_addresses(
    facts: dict[int, InstructionFact],
) -> set[int]:
    """Return table bases read as indexed 16-bit values."""
    return _indexed_read_addresses(
        facts, frozenset({"MOVE.W", "MOVEA.W", "ADDA.W", "ADD.W"})
    )


def _mapped(image: MegaDriveImage, address: int) -> bool:
    return (
        image.header.rom_start <= address <= image.actual_rom_end
        and address & 1 == 0
    )


def _evaluate(
    image: MegaDriveImage,
    schema_id: str,
    entries: tuple[PointerEntry, ...],
    entry_size: int,
    interiors: set[int],
    instruction_starts: set[int],
    referenced_addresses: set[int],
    indexed_read_addresses: set[int],
) -> PointerCandidate | None:
    start = entries[0].physical_offset
    end = entries[-1].physical_offset + entry_size
    logical_start = image.header.rom_start + start
    targets = tuple(entry.target for entry in entries)
    target_starts = sum(target in instruction_starts for target in targets)
    referenced = logical_start in referenced_addresses
    evidence = [
        "all_entries_map_to_file_backed_rom",
        f"entry_count={len(entries)}",
        f"instruction_targets={target_starts}",
    ]
    if referenced:
        evidence.append("table_start_referenced_by_instruction")
    contradictions: list[str] = []
    if any(target - image.header.rom_start in interiors for target in targets):
        contradictions.append("target_inside_instruction")
    if any(logical_start <= target < logical_start + end - start for target in targets):
        contradictions.append("target_inside_own_table")
    all_instruction_targets = target_starts == len(entries)
    if all_instruction_targets:
        evidence.append("all_targets_are_instruction_starts")
    logical_end = image.header.rom_start + end
    indexed_forward_data_table = (
        schema_id in {
            "megadrive.u32be.absolute",
            "megadrive.s16be.target-table_base",
        }
        and logical_start in indexed_read_addresses
        and all(target >= logical_end for target in targets)
    )
    if indexed_forward_data_table:
        evidence.extend((
            "table_read_by_indexed_move_l"
            if entry_size == 4
            else "table_read_by_indexed_word",
            "all_targets_follow_table",
        ))
    if not referenced:
        evidence.append("scan_only_no_table_reference")
    ratio = target_starts / len(entries)
    if not referenced and ratio < 0.75:
        return None
    accepted = (
        len(entries) >= MIN_ACCEPTED_ENTRIES
        and not contradictions
        and (all_instruction_targets or indexed_forward_data_table)
        and referenced
    )
    status = "accepted" if accepted else "rejected" if contradictions else "candidate"
    score = 35 + min(len(entries) * 3, 24) + min(target_starts * 8, 32)
    if referenced:
        score += 10
    if indexed_forward_data_table:
        score += 15
    if contradictions:
        score -= 35
    schema_slug = schema_id.removeprefix("megadrive.").replace(".", "-")
    return PointerCandidate(
        candidate_id=f"Ptr_{schema_slug}_{logical_start:06X}",
        schema_id=schema_id,
        physical_start=start,
        physical_end=end,
        logical_start=logical_start,
        entry_size=entry_size,
        status=status,
        score=max(0, min(score, 100)),
        entries=entries,
        evidence=tuple(evidence),
        contradictions=tuple(contradictions),
    )


def _absolute_candidates(
    image: MegaDriveImage,
    facts: dict[int, InstructionFact],
    width: int,
) -> list[PointerCandidate]:
    occupied, interiors, instruction_starts = _instruction_sets(facts)
    referenced = _referenced_addresses(facts)
    indexed_long_reads = _indexed_long_read_addresses(facts)
    candidates: list[PointerCandidate] = []
    offset = 0x200
    schema_id = f"megadrive.u{width * 8}be.absolute"
    while offset + width <= len(image.data):
        if any(byte in occupied for byte in range(offset, offset + width)):
            offset += 2
            continue
        start = offset
        entries: list[PointerEntry] = []
        while offset + width <= len(image.data) and len(entries) < MAX_ENTRIES:
            if any(byte in occupied for byte in range(offset, offset + width)):
                break
            logical_offset = image.header.rom_start + offset
            if entries and logical_offset in referenced:
                break
            raw = int.from_bytes(image.data[offset:offset + width], "big")
            if not _mapped(image, raw):
                break
            entries.append(
                PointerEntry(
                    physical_offset=offset,
                    logical_address=image.header.rom_start + offset,
                    raw_value=raw,
                    target=raw,
                )
            )
            offset += width
        if len(entries) >= MIN_ENTRIES:
            candidate = _evaluate(
                image,
                schema_id,
                tuple(entries),
                width,
                interiors,
                instruction_starts,
                referenced,
                indexed_long_reads,
            )
            if candidate is not None:
                candidates.append(candidate)
        if offset == start:
            offset += 2
    return candidates


def _relative_candidates(
    image: MegaDriveImage,
    facts: dict[int, InstructionFact],
    base_policy: str,
) -> list[PointerCandidate]:
    occupied, interiors, instruction_starts = _instruction_sets(facts)
    referenced = _referenced_addresses(facts)
    indexed_word_reads = _indexed_word_read_addresses(facts)
    candidates: list[PointerCandidate] = []
    for start in range(0x200, max(0x200, len(image.data) - 5), 2):
        entries: list[PointerEntry] = []
        offset = start
        while offset + 2 <= len(image.data) and len(entries) < MAX_ENTRIES:
            if offset in occupied or offset + 1 in occupied:
                break
            if entries and image.header.rom_start + offset in referenced:
                break
            raw = int.from_bytes(image.data[offset:offset + 2], "big")
            signed = int.from_bytes(image.data[offset:offset + 2], "big", signed=True)
            if base_policy == "table_base":
                base = image.header.rom_start + start
            else:
                base = image.header.rom_start + offset
            target = base + signed
            if not _mapped(image, target):
                break
            entries.append(
                PointerEntry(
                    physical_offset=offset,
                    logical_address=image.header.rom_start + offset,
                    raw_value=raw,
                    target=target,
                    base_address=base,
                )
            )
            offset += 2
        if len(entries) < MIN_ENTRIES:
            continue
        schema_id = f"megadrive.s16be.target-{base_policy}"
        candidate = _evaluate(
            image,
            schema_id,
            tuple(entries),
            2,
            interiors,
            instruction_starts,
            referenced,
            indexed_word_reads,
        )
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _vector_candidate(image: MegaDriveImage) -> PointerCandidate:
    entries = tuple(
        PointerEntry(
            physical_offset=vector.index * 4,
            logical_address=image.header.rom_start + vector.index * 4,
            raw_value=vector.raw_value,
            target=vector.address,
        )
        for vector in image.vector_table[1:]
    )
    return PointerCandidate(
        candidate_id="MegaDriveVectors_000000",
        schema_id="megadrive.m68k-vectors.u32be-masked24",
        physical_start=4,
        physical_end=0x100,
        logical_start=image.header.rom_start + 4,
        entry_size=4,
        status="accepted",
        score=100,
        entries=entries,
        evidence=("cartridge_vector_table", "upper_byte_is_bus-masked"),
        contradictions=(),
    )


def _ram_trampoline_candidates(
    image: MegaDriveImage, facts: dict[int, InstructionFact]
) -> tuple[PointerCandidate, ...]:
    """Promote loader-proven counted u16 function tables."""
    _, interiors, instruction_starts = _instruction_sets(facts)
    candidates = []
    for table in discover_ram_trampoline_tables(image):
        start = table.table_address
        entries = tuple(
            PointerEntry(
                physical_offset=start + 2 + index * 2,
                logical_address=image.header.rom_start + start + 2 + index * 2,
                raw_value=target,
                target=target,
            )
            for index, target in enumerate(table.targets)
        )
        contradictions = []
        if any(
            target - image.header.rom_start in interiors
            for target in table.targets
        ):
            contradictions.append("target_inside_instruction")
        all_targets_decoded = all(
            target in instruction_starts for target in table.targets
        )
        if not all_targets_decoded:
            contradictions.append("target_not_instruction_start")
        status = "accepted" if not contradictions else "rejected"
        candidates.append(PointerCandidate(
            candidate_id=f"Ptr_counted-u16be-absolute_{start:06X}",
            schema_id="megadrive.counted-u16be.absolute",
            physical_start=start,
            physical_end=start + 2 + len(entries) * 2,
            logical_start=image.header.rom_start + start,
            entry_size=2,
            status=status,
            score=100 if status == "accepted" else 65,
            entries=entries,
            evidence=(
                f"loader_at_{table.loader_address:06X}",
                "loader_builds_counted_JMP_abs_l_trampolines_in_RAM",
                f"count_word_plus_one={len(entries)}",
                "instruction_targets="
                f"{sum(target in instruction_starts for target in table.targets)}",
            ),
            contradictions=tuple(contradictions),
        ))
    return tuple(candidates)


_DISPLACEMENT_ADDRESS = re.compile(
    r"\((-?0x[0-9a-f]+|-?\d+),([Aa][0-7])\)\|([Aa][0-7])$", re.I
)
_INDEXED_ADDRESS = re.compile(
    r"\((-?0x[0-9a-f]+|-?\d+),([Aa][0-7]),"
    r"([Dd][0-7])w\*0x1\)\|([Aa][0-7])$", re.I
)
_INDEXED_WORD = re.compile(
    r"\((-?0x[0-9a-f]+|-?\d+),([Aa][0-7]),"
    r"([Dd][0-7])w\*0x1\)\|([Dd][0-7])w$", re.I
)
_IMMEDIATE_TO_DISPLACEMENT = re.compile(
    r"#(-?0x[0-9a-f]+|-?\d+)\|"
    r"\((-?0x[0-9a-f]+|-?\d+),([Aa][0-7])\)$", re.I
)
_INDEXED_TO_DISPLACEMENT = re.compile(
    r".+PC,[Dd][0-7]w\*0x1\)\|"
    r"\((-?0x[0-9a-f]+|-?\d+),([Aa][0-7])\)$", re.I
)
_MOVEQ = re.compile(r"(-?0x[0-9a-f]+|-?\d+)\|([Dd][0-7])$", re.I)


def _animation_reader_fields(
    facts: dict[int, InstructionFact],
) -> dict[tuple[int, str], int]:
    """Find object fields consumed as counted animation pointer schemas."""
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    ordered = sorted(facts.values(), key=lambda item: item.cpu_address)
    fields: dict[tuple[int, str], int] = {}
    for load in ordered:
        if load.mnemonic.upper() != "MOVEA.L":
            continue
        direct = _DISPLACEMENT_ADDRESS.fullmatch(load.operands)
        if direct is None:
            continue
        displacement = int(direct.group(1), 0)
        object_register = direct.group(2).upper()
        sequence_register = direct.group(3).upper()
        indexed_load = by_address.get(load.cpu_address + load.length)
        if indexed_load is None or indexed_load.mnemonic.upper() != "MOVEA.L":
            continue
        indexed = _INDEXED_ADDRESS.fullmatch(indexed_load.operands)
        if (
            indexed is None
            or int(indexed.group(1), 0) != 0
            or indexed.group(2).upper() != sequence_register
            or indexed.group(4).upper() != sequence_register
        ):
            continue
        index_register = indexed.group(3).upper()
        window = [
            fact for fact in ordered
            if indexed_load.cpu_address < fact.cpu_address <= load.cpu_address + 0x40
        ]
        sign_extended_registers = {
            match.group(2).upper()
            for fact in window
            if fact.mnemonic.upper() == "MOVEQ"
            and (match := _MOVEQ.fullmatch(fact.operands)) is not None
            and int(match.group(1), 0) == -1
        }
        has_counted_word_read = any(
            fact.mnemonic.upper() == "MOVE.W"
            and (match := _INDEXED_WORD.fullmatch(fact.operands)) is not None
            and int(match.group(1), 0) == 2
            and match.group(2).upper() == sequence_register
            and match.group(3).upper() == index_register
            and match.group(4).upper() in sign_extended_registers
            for fact in window
        )
        if has_counted_word_read:
            fields[(displacement, object_register)] = load.cpu_address
    return fields


def _animation_roots(
    facts: dict[int, InstructionFact],
    fields: dict[tuple[int, str], int],
    absolute_candidates: tuple[PointerCandidate, ...],
) -> dict[int, tuple[int, int]]:
    accepted_tables = {
        candidate.logical_start: candidate
        for candidate in absolute_candidates
        if candidate.schema_id == "megadrive.u32be.absolute"
        and candidate.status == "accepted"
    }
    roots: dict[int, tuple[int, int]] = {}
    for fact in facts.values():
        if fact.mnemonic.upper() != "MOVE.L":
            continue
        immediate = _IMMEDIATE_TO_DISPLACEMENT.fullmatch(fact.operands)
        if immediate is not None:
            field = (int(immediate.group(2), 0), immediate.group(3).upper())
            if field in fields:
                roots[int(immediate.group(1), 0) & 0xFFFFFF] = (
                    fact.cpu_address, fields[field]
                )
            continue
        indexed = _INDEXED_TO_DISPLACEMENT.fullmatch(fact.operands)
        if indexed is None:
            continue
        field = (int(indexed.group(1), 0), indexed.group(2).upper())
        if field not in fields:
            continue
        for reference in fact.references:
            table = accepted_tables.get(reference.address)
            if table is None:
                continue
            for entry in table.entries:
                roots[entry.target] = (fact.cpu_address, fields[field])
    return roots


def _animation_sequence_candidate(
    image: MegaDriveImage,
    occupied: set[int],
    region: RamCopyRegion,
    sequence: int,
    root: int,
    reader: int,
) -> PointerCandidate | None:
    physical_start = sequence - image.header.rom_start
    if physical_start < 0 or physical_start + 4 > len(image.data):
        return None
    count = image.data[physical_start]
    if not 1 <= count <= MAX_ENTRIES:
        return None
    physical_end = physical_start + 2 + count * 2
    if physical_end > len(image.data):
        return None
    if any(offset in occupied for offset in range(physical_start, physical_end)):
        return None
    entries = []
    runtime_page = region.destination_start & 0xFF0000
    for index in range(count):
        offset = physical_start + 2 + index * 2
        raw = int.from_bytes(image.data[offset:offset + 2], "big")
        runtime_target = runtime_page | raw
        if not region.destination_start <= runtime_target < region.destination_end:
            return None
        target = region.source_start + runtime_target - region.destination_start
        if not _mapped(image, target):
            return None
        entries.append(PointerEntry(
            physical_offset=offset,
            logical_address=image.header.rom_start + offset,
            raw_value=raw,
            target=target,
            base_address=region.source_start,
        ))
    return PointerCandidate(
        candidate_id=f"Ptr_counted-u16be-ram-copy-offset_{sequence:06X}",
        schema_id="megadrive.counted-u16be.ram-copy-offset",
        physical_start=physical_start,
        physical_end=physical_end,
        logical_start=sequence,
        entry_size=2,
        status="accepted",
        score=100,
        entries=tuple(entries),
        evidence=(
            f"animation_pointer_root_{root:06X}",
            f"count_header={count}",
            f"reader_at_{reader:06X}",
            f"rom_{region.source_start:06X}_copied_to_ram_"
            f"{region.destination_start:06X}",
        ),
        contradictions=(),
    )


def _animation_candidates(
    image: MegaDriveImage,
    facts: dict[int, InstructionFact],
    absolute_candidates: tuple[PointerCandidate, ...],
) -> tuple[PointerCandidate, ...]:
    """Recover long animation roots and their counted copied-RAM offsets."""
    regions = tuple(
        region for region in discover_ram_copy_regions(image)
        if region.destination_start & 0xFFFF == 0
        and region.destination_end - region.destination_start <= 0x10000
    )
    fields = _animation_reader_fields(facts)
    if not regions or not fields:
        return ()
    roots = _animation_roots(facts, fields, absolute_candidates)
    referenced = _referenced_addresses(facts)
    occupied, _, _ = _instruction_sets(facts)
    candidates: list[PointerCandidate] = []
    root_boundaries = set(roots) | referenced
    for root in sorted(roots):
        assignment, reader = roots[root]
        physical_start = root - image.header.rom_start
        if physical_start < 0 or physical_start + 4 > len(image.data):
            continue
        entries: list[PointerEntry] = []
        sequences: list[PointerCandidate] = []
        offset = physical_start
        while offset + 4 <= len(image.data) and len(entries) < MAX_ENTRIES:
            logical_offset = image.header.rom_start + offset
            if offset != physical_start and logical_offset in root_boundaries:
                break
            target = int.from_bytes(image.data[offset:offset + 4], "big")
            if not _mapped(image, target) or target < root + 4:
                break
            sequence_candidate = next(
                (
                    candidate
                    for region in regions
                    if (
                        candidate := _animation_sequence_candidate(
                            image, occupied, region, target, root, reader
                        )
                    ) is not None
                ),
                None,
            )
            if sequence_candidate is None:
                break
            entries.append(PointerEntry(
                physical_offset=offset,
                logical_address=logical_offset,
                raw_value=target,
                target=target,
            ))
            sequences.append(sequence_candidate)
            offset += 4
        if not entries:
            continue
        sequence_ranges = sorted(
            (item.physical_start, item.physical_end) for item in sequences
        )
        if (
            any(start < offset for start, _ in sequence_ranges)
            or any(
                left_end > right_start
                for (_, left_end), (right_start, _) in zip(
                    sequence_ranges, sequence_ranges[1:]
                )
            )
        ):
            continue
        candidates.append(PointerCandidate(
            candidate_id=f"Ptr_u32be-animation-root_{root:06X}",
            schema_id="megadrive.u32be.absolute",
            physical_start=physical_start,
            physical_end=offset,
            logical_start=root,
            entry_size=4,
            status="accepted",
            score=100,
            entries=tuple(entries),
            evidence=(
                f"stored_to_animation_field_by_{assignment:06X}",
                f"reader_at_{reader:06X}",
                "all_targets_have_counted_word_offset_layout",
            ),
            contradictions=(),
        ))
        candidates.extend(sequences)
    return tuple(candidates)


def detect_pointer_candidates(
    image: MegaDriveImage, facts: dict[int, InstructionFact]
) -> tuple[PointerCandidate, ...]:
    candidates = [_vector_candidate(image)]
    candidates.extend(_ram_trampoline_candidates(image, facts))
    absolute = tuple(_absolute_candidates(image, facts, 4))
    candidates.extend(absolute)
    candidates.extend(_animation_candidates(image, facts, absolute))
    candidates.extend(_absolute_candidates(image, facts, 2))
    candidates.extend(_relative_candidates(image, facts, "table_base"))
    candidates.extend(_relative_candidates(image, facts, "entry_address"))
    unique: dict[tuple[str, int, int], PointerCandidate] = {}
    for candidate in candidates:
        key = (candidate.schema_id, candidate.physical_start, candidate.physical_end)
        previous = unique.get(key)
        if previous is None or candidate.score > previous.score:
            unique[key] = candidate
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (item.physical_start, item.schema_id, item.physical_end),
        )
    )


def write_pointer_report(
    path: Path,
    image: MegaDriveImage,
    candidates: tuple[PointerCandidate, ...],
) -> None:
    document = {
        "schema": "retrolarium.megadrive.pointers",
        "schema_version": 1,
        "input_sha256": image.sha256,
        "candidates": [candidate.as_dict() for candidate in candidates],
    }
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
