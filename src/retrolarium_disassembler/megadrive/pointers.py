"""Explainable big-endian pointer schemas for Mega Drive cartridge ROMs."""

from __future__ import annotations

from array import array
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
from typing import Callable

from retrolarium_disasm.facts import InstructionFact
from retrolarium_disasm.m68k.instructions import absolute_referenced_addresses, instruction_sets
from retrolarium_core.megadrive import MegaDriveImage
from retrolarium_disasm.m68k.seeds import (
    DecoderSeed,
    RamCopyRegion,
    discover_ram_copy_regions,
    discover_ram_trampoline_tables,
)


MIN_ENTRIES = 3
MIN_ACCEPTED_ENTRIES = 4
MAX_ENTRIES = 64
MAX_DISPATCH_ENTRIES = 1024
MIN_DISPATCH_ENTRIES = 2
DISPATCH_INDEX_WINDOW = 8
GUARDED_DISPATCH_WINDOW = 16


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
    *,
    scan_start: int = 0x200,
) -> list[PointerCandidate]:
    occupied, interiors, instruction_starts = instruction_sets(facts)
    referenced = _referenced_addresses(facts)
    indexed_long_reads = _indexed_long_read_addresses(facts)
    candidates: list[PointerCandidate] = []
    offset = scan_start
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
    *,
    scan_start: int = 0x200,
) -> list[PointerCandidate]:
    occupied, interiors, instruction_starts = instruction_sets(facts)
    referenced = _referenced_addresses(facts)
    indexed_word_reads = _indexed_word_read_addresses(facts)
    candidates: list[PointerCandidate] = []
    origin = image.header.rom_start
    rom_end = image.actual_rom_end
    # An overlay's address-indexed view has a synthetic prefix. Index only
    # bytes eligible for scanning; neither arrays nor suffix preprocessing
    # should scale with the module's load address.
    words = array("h", image.data[scan_start:len(image.data) & ~1])
    if sys.byteorder != "big":
        words.byteswap()
    code_starts = sorted(instruction_starts)
    schema_id = f"megadrive.s16be.target-{base_policy}"
    entry_relative = base_policy != "table_base"
    if entry_relative:
        # These targets depend on the entry address, not on the table start.
        # Index the valid run and instruction-hit count once, so overlapping
        # 64-word windows do not decode or allocate the same words repeatedly.
        next_stop = array("I", [len(words)]) * (len(words) + 1)
        suffix_hits = array("I", [0]) * (len(words) + 1)
        for index in range(len(words) - 1, -1, -1):
            offset = scan_start + index * 2
            target = origin + offset + words[index]
            valid = (offset not in occupied and offset + 1 not in occupied
                     and origin <= target <= rom_end and not target & 1)
            next_stop[index] = next_stop[index + 1] if valid else index
            suffix_hits[index] = suffix_hits[index + 1] + (target in instruction_starts)
        reference_offsets = sorted(address - origin for address in referenced
                                   if not (address - origin) & 1)
    for start in range(scan_start, max(scan_start, len(image.data) - 5), 2):
        logical_start = origin + start
        is_referenced = logical_start in referenced
        if not is_referenced:
            # _evaluate drops an unreferenced window without >=75% code
            # targets. No signed word can reach outside this inclusive range.
            rightmost = logical_start + 0x7FFF
            if entry_relative:
                rightmost += 2 * (MAX_ENTRIES - 1)
            nearest = bisect_left(code_starts, logical_start - 0x8000)
            if nearest == len(code_starts) or code_starts[nearest] > rightmost:
                continue
        first = (start - scan_start) // 2
        if entry_relative:
            last = min(first + MAX_ENTRIES, next_stop[first])
            boundary = bisect_right(reference_offsets, start)
            if boundary < len(reference_offsets):
                last = min(last, (reference_offsets[boundary] - scan_start) // 2)
            target_hits = suffix_hits[first] - suffix_hits[last]
        else:
            last = first
            target_hits = 0
            while last < min(first + MAX_ENTRIES, len(words)):
                offset = scan_start + last * 2
                if offset in occupied or offset + 1 in occupied:
                    break
                if last != first and origin + offset in referenced:
                    break
                target = logical_start + words[last]
                if not origin <= target <= rom_end or target & 1:
                    break
                target_hits += target in instruction_starts
                last += 1
        count = last - first
        if count < MIN_ENTRIES or not is_referenced and target_hits * 4 < count * 3:
            continue
        # Materialize only windows which survive _evaluate's existing filter.
        entries = tuple(PointerEntry(
            physical_offset=scan_start + index * 2,
            logical_address=origin + scan_start + index * 2,
            raw_value=words[index] & 0xFFFF,
            target=(origin + scan_start + index * 2 if entry_relative else logical_start) + words[index],
            base_address=origin + scan_start + index * 2 if entry_relative else logical_start,
        ) for index in range(first, last))
        candidate = _evaluate(
            image,
            schema_id,
            entries,
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
    image: MegaDriveImage, facts: dict[int, InstructionFact], *, scan_start: int = 0x200,
) -> tuple[PointerCandidate, ...]:
    """Promote loader-proven counted u16 function tables."""
    _, interiors, instruction_starts = instruction_sets(facts)
    candidates = []
    for table in discover_ram_trampoline_tables(image, scan_start=scan_start):
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
    *,
    scan_start: int = 0x200,
) -> tuple[PointerCandidate, ...]:
    """Recover long animation roots and their counted copied-RAM offsets."""
    regions = tuple(
        region for region in discover_ram_copy_regions(image, scan_start=scan_start)
        if region.destination_start & 0xFFFF == 0
        and region.destination_end - region.destination_start <= 0x10000
    )
    fields = _animation_reader_fields(facts)
    if not regions or not fields:
        return ()
    roots = _animation_roots(facts, fields, absolute_candidates)
    referenced = _referenced_addresses(facts)
    occupied, _, _ = instruction_sets(facts)
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


_REGISTER_INDIRECT = re.compile(r"\(([Aa][0-7])\)$")
_DATA_TO_ADDRESS = re.compile(r"[Dd][0-7]w?\|([Aa][0-7])$", re.I)
_PC_INDEXED_ADDRESS = re.compile(
    r"\((-?0x[0-9a-f]+|-?\d+),PC,[DA][0-7][wl]?\*0x1\)\|([Aa][0-7])$", re.I
)
_IMMEDIATE_ADDRESS = re.compile(r"#(-?0x[0-9a-f]+|-?\d+)\|([Aa][0-7])$", re.I)
_INDIRECT_TO_ADDRESS = re.compile(r"\(([Aa][0-7])\)\|([Aa][0-7])$", re.I)
_PC_DATA_WORD_INDEX = re.compile(r",(D[0-7])w\*0x1\)\|A[0-7]$", re.I)
# Compilers often double a long switch index (ADD.L Dn,Dn) and read the
# offset with a long index; only the JMP needs the word-sized offset.
_PC_WORD_TO_DATA = re.compile(
    r"\((-?0x[0-9a-f]+|-?\d+),PC,[DA][0-7][wl]?\*0x1\)\|(D[0-7])w$", re.I
)
_PC_WORD_BRANCH = re.compile(
    r"\((-?0x[0-9a-f]+|-?\d+),PC,(D[0-7])w\*0x1\)$", re.I
)


@dataclass(frozen=True)
class _DispatchTable:
    candidate: PointerCandidate
    load_address: int
    call_address: int
    call_mnemonic: str
    seed_kind: str = "indexed_pointer_table_target"
    seed_confidence: str = "high"
    excluded_targets: frozenset[int] = frozenset()


def _weak_absolute_lea_boundaries(facts: dict[int, InstructionFact]) -> set[int]:
    """Boundaries named only by LEA values without a proved data read.

    These remain boundaries globally. A PC word dispatcher may supersede one
    only after independently proving its complete table and a handler CFG.
    """
    from retrolarium_disasm.m68k.abstract import _register_use

    by_address = {fact.cpu_address: fact for fact in facts.values()}
    strong = {}
    for key, fact in facts.items():
        operands = fact.operands.split("|")
        if (fact.mnemonic.upper() == "LEA" and len(operands) == 2
                and re.fullmatch(r"\(-?0x[0-9a-f]+\)\.[wl]", operands[0], re.I)
                and re.fullmatch(r"A[0-6]", operands[1], re.I)
                and _register_use(by_address, fact.cpu_address + fact.length,
                                  operands[1].upper()) != "data"):
            continue
        strong[key] = fact
    return absolute_referenced_addresses(facts) - absolute_referenced_addresses(strong)


def _index_register_from_data_register(
    ends: dict[int, InstructionFact],
    load: InstructionFact,
    register: str,
) -> bool:
    """Prove the base register was last set from a data register.

    Only straight-line predecessors are inspected, so a struct pointer
    loaded by LEA or an absolute MOVEA never qualifies as a table index.
    """
    current = load
    for _ in range(DISPATCH_INDEX_WINDOW):
        previous = ends.get(current.cpu_address)
        if previous is None or previous.flow_type.upper() != "FALL_THROUGH":
            return False
        destination = previous.operands.rsplit("|", 1)[-1].upper()
        if destination == register:
            return (
                previous.mnemonic.upper() in {"MOVEA.W", "MOVEA.L"}
                and _DATA_TO_ADDRESS.fullmatch(previous.operands) is not None
            )
        current = previous
    return False


def _guarded_nonzero_byte_index(
    ends: dict[int, InstructionFact], load: InstructionFact,
    call: InstructionFact | None,
) -> bool:
    """Prove that a byte index starts at one before multiplication by four.

    The lookup address may be four bytes before its first actual entry. Only
    shift the table start when a zero-initialized byte is read, zero branches
    past the indirect call, and the surviving index is multiplied by four.
    """
    indexed = _PC_DATA_WORD_INDEX.search(load.operands)
    if indexed is None or call is None:
        return False
    register = indexed.group(1).upper()
    current = ends.get(load.cpu_address)
    if current is None:
        return False
    doubled = (current.mnemonic.upper() == "ADD.W"
               and current.operands.upper() == f"{register}W|{register}W")
    shifted = (current.mnemonic.upper() in {"LSL.W", "ASL.W"}
               and current.operands.upper() == f"#0X2|{register}W")
    if doubled:
        previous = ends.get(current.cpu_address)
        if (previous is None or previous.mnemonic.upper() != "ADD.W"
                or previous.operands.upper() != f"{register}W|{register}W"):
            return False
        current = previous
    elif not shifted:
        return False
    branch = ends.get(current.cpu_address)
    if (branch is None or branch.mnemonic.upper() not in {"BEQ.B", "BEQ.W"}
            or not branch.flows or min(branch.flows) < call.cpu_address + call.length):
        return False
    read = ends.get(branch.cpu_address)
    if (read is None or read.mnemonic.upper() != "MOVE.B"
            or not read.operands.upper().endswith(f"|{register}B")
            or not read.operands.startswith("(")):
        return False
    current = read
    for _ in range(GUARDED_DISPATCH_WINDOW):
        current = ends.get(current.cpu_address)
        if current is None:
            return False
        if current.flow_type.upper() != "FALL_THROUGH" and not (
            current.flow_type.upper() == "CONDITIONAL_JUMP"
            and current.flows and min(current.flows) > current.cpu_address
        ):
            return False
        if current.mnemonic.upper() == "MOVEQ" and current.operands.upper() == f"0X0|{register}":
            return True
        if current.operands.rsplit("|", 1)[-1].upper() in {
            register, f"{register}B", f"{register}W", f"{register}L"
        }:
            return False
    return False


def _dispatch_tables(
    image: MegaDriveImage, facts: dict[int, InstructionFact]
) -> tuple[_DispatchTable, ...]:
    """Recover u32 handler tables selected by an indexed MOVEA.L dispatch.

    The table base comes from a decoded ``MOVEA.L (d16,An),Am`` with a
    proven data-register index, or ``MOVEA.L (table,PC,Rn.W),Am``. Both
    must lead to ``JSR/JMP (Am)``. A single store of Am into the object
    callback field is allowed between the load and call. Entries stop at the first odd, unmapped,
    self-referencing, code-overlapping or structurally invalid target.
    """
    occupied, interiors, instruction_starts = instruction_sets(facts)
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    def indirect_call(load: InstructionFact, register: str) -> InstructionFact | None:
        next_fact = by_address.get(load.cpu_address + load.length)
        if (next_fact is not None and next_fact.mnemonic.upper() == "MOVE.L"
                and next_fact.operands.upper() in {
                    f"{register}|(A0)", f"{register}|(A1)"
                }):
            next_fact = by_address.get(next_fact.cpu_address + next_fact.length)
        if (next_fact is None or next_fact.mnemonic.upper() not in {"JSR", "JMP"}
                or next_fact.operands.upper() != f"({register})"):
            return None
        return next_fact

    # Tables end at another dispatch base or an absolute data reference;
    # base-register displacements are never treated as boundaries.
    boundaries = absolute_referenced_addresses(facts)
    ends = {fact.cpu_address + fact.length: fact for fact in facts.values()}
    for fact in facts.values():
        match = (_DISPLACEMENT_ADDRESS.fullmatch(fact.operands)
                 or _PC_INDEXED_ADDRESS.fullmatch(fact.operands))
        if fact.mnemonic.upper() == "MOVEA.L" and match is not None:
            call = indirect_call(fact, match.group(3 if _DISPLACEMENT_ADDRESS.fullmatch(fact.operands) else 2).upper())
            if call is not None:
                offset = (4 if _PC_INDEXED_ADDRESS.fullmatch(fact.operands)
                          and _guarded_nonzero_byte_index(ends, fact, call) else 0)
                boundaries.add(int(match.group(1), 0) + offset)
    rom_start = image.header.rom_start
    data = image.data
    tables: dict[int, _DispatchTable] = {}
    for load in sorted(facts.values(), key=lambda item: item.cpu_address):
        if load.mnemonic.upper() != "MOVEA.L":
            continue
        match = _DISPLACEMENT_ADDRESS.fullmatch(load.operands)
        pc_indexed = _PC_INDEXED_ADDRESS.fullmatch(load.operands)
        if load.flow_type.upper() != "FALL_THROUGH" or (match is None and pc_indexed is None):
            continue
        if pc_indexed is not None:
            table = int(pc_indexed.group(1), 0)
            loaded_register = pc_indexed.group(2).upper()
            call = indirect_call(load, loaded_register)
            if _guarded_nonzero_byte_index(ends, load, call):
                table += 4
            kind = "address" if ",A" in load.operands.upper() else "data"
            size = "word" if "w*" in load.operands.lower() else "long"
            index_evidence = f"pc_relative_{kind}_register_{size}_index"
        else:
            assert match is not None
            table = int(match.group(1), 0)
            loaded_register = match.group(3).upper()
            call = indirect_call(load, loaded_register)
            if not _index_register_from_data_register(ends, load, match.group(2).upper()):
                continue
            index_evidence = "index_register_from_data_register"
        if call is None:
            continue
        physical_start = table - rom_start
        if (
            table in tables
            or physical_start < 0x200
            or table & 1
            or physical_start + MIN_DISPATCH_ENTRIES * 4 > len(data)
        ):
            continue
        entries: list[PointerEntry] = []
        offset = physical_start
        while offset + 4 <= len(data) and len(entries) < MAX_DISPATCH_ENTRIES:
            if any(byte in occupied for byte in range(offset, offset + 4)):
                break
            logical_offset = rom_start + offset
            if entries and logical_offset in boundaries:
                break
            raw = int.from_bytes(data[offset:offset + 4], "big")
            physical_target = raw - rom_start
            if (
                not _mapped(image, raw)
                or physical_target < 0x200
                or physical_target + 2 > len(data)
                or physical_target in interiors
                or physical_start <= physical_target < offset + 4
                or data[physical_target:physical_target + 2]
                in {b"\x00\x00", b"\xff\xff"}
            ):
                break
            entries.append(PointerEntry(
                physical_offset=offset,
                logical_address=logical_offset,
                raw_value=raw,
                target=raw,
            ))
            offset += 4
        # A later entry may still aim back into earlier table bytes.
        while entries:
            end = physical_start + len(entries) * 4
            inside = [
                index for index, entry in enumerate(entries)
                if physical_start <= entry.target - rom_start < end
            ]
            if not inside:
                break
            entries = entries[:inside[0]]
        if len(entries) < MIN_DISPATCH_ENTRIES:
            continue
        target_starts = sum(
            entry.target in instruction_starts for entry in entries
        )
        accepted = target_starts == len(entries)
        tables[table] = _DispatchTable(
            candidate=PointerCandidate(
                candidate_id=f"Ptr_u32be-dispatch_{table:06X}",
                schema_id="megadrive.u32be.absolute",
                physical_start=physical_start,
                physical_end=physical_start + len(entries) * 4,
                logical_start=table,
                entry_size=4,
                status="accepted" if accepted else "candidate",
                score=100 if accepted else 60,
                entries=tuple(entries),
                evidence=(
                    f"indexed_movea_l_at_{load.cpu_address:06X}",
                    f"{call.mnemonic.lower()}_indirect_at_"
                    f"{call.cpu_address:06X}",
                    index_evidence,
                    f"entry_count={len(entries)}",
                    f"instruction_targets={target_starts}",
                ),
                contradictions=(),
            ),
            load_address=load.cpu_address,
            call_address=call.cpu_address,
            call_mnemonic=call.mnemonic.upper(),
        )
    return tuple(tables[address] for address in sorted(tables))


def can_bootstrap_dispatch_seeds(seeds, decoded_starts) -> bool:
    """Exact executable word-table readers need two targets; guesses need witnesses."""
    targets = {seed.address for seed in seeds}
    if len(targets) < 2:
        return False
    if all(seed.confidence == "proven" and seed.kind in {
        "leaf_word_dispatch", "inline_word_dispatch", "pc_word_dispatch",
    } for seed in seeds):
        return True
    decoded = len(targets & decoded_starts)
    return len(targets) >= 4 and (decoded >= 2 or decoded == 1 and len(seeds) >= 8)


def discover_dispatch_table_seeds(
    image: MegaDriveImage, facts: dict[int, InstructionFact],
    *, handler_validator: Callable[[int], bool] | None = None, entrypoints=(),
) -> tuple[DecoderSeed, ...]:
    """Turn instruction-proven absolute and relative dispatch tables into seeds."""
    from retrolarium_disasm.m68k.dispatch.record import discover_record_callback_seeds
    from retrolarium_disasm.m68k.callbacks.abi import discover_callback_abi_seeds
    from retrolarium_disasm.m68k.dispatch.ram import discover_ram_stub_dispatch_seeds
    from retrolarium_disasm.m68k.dispatch.table import discover_lea_indexed_call_seeds, discover_trap_relative_dispatch_seeds
    from retrolarium_disasm.m68k.callbacks.word import discover_nested_word_resolver_seeds
    from retrolarium_disasm.m68k.dispatch.leaf import discover_leaf_word_dispatch_seeds
    from retrolarium_disasm.m68k.dispatch.indexed import (
        discover_register_indexed_dispatch_seeds, discover_added_index_dispatch_seeds,
        discover_nested_word_dispatch_seeds,
    )
    seeds = [*discover_record_callback_seeds(image, facts),
             *discover_callback_abi_seeds(image, facts),
             *discover_ram_stub_dispatch_seeds(image, facts),
             *discover_nested_word_resolver_seeds(image, facts),
             *discover_leaf_word_dispatch_seeds(image, facts, handler_validator=handler_validator,
                                                 entrypoints=entrypoints),
             *discover_lea_indexed_call_seeds(image, facts),
             *discover_trap_relative_dispatch_seeds(image, facts)]
    for table in (*_dispatch_tables(image, facts), *_word_dispatch_tables(image, facts),
                  *_pc_word_dispatch_tables(image, facts, handler_validator=handler_validator,
                                            skip_conflicting_targets=True),
                  *_object_callback_tables(image, facts)):
        candidate = table.candidate
        evidence = (
            f"{candidate.schema_id} handler table at 0x{candidate.logical_start:06X} "
            f"({len(candidate.entries)} entries) selected by load at "
            f"0x{table.load_address:06X} and {table.call_mnemonic} at "
            f"0x{table.call_address:06X}"
        )
        evidence += "".join(f"; {item}" for item in candidate.evidence
                            if item.startswith("complete_cfg_witness_at_"))
        seeds.extend(
            DecoderSeed(
                address=entry.target,
                kind=table.seed_kind,
                confidence=table.seed_confidence,
                evidence=evidence,
                source_address=table.load_address,
            )
            for entry in candidate.entries
            if entry.target not in table.excluded_targets
        )
    # These readers are also used by CD overlays. Cartridge analysis must
    # receive the same proven register-index and nested-table discoveries.
    seen = {seed.address for seed in seeds}
    for seed in (*discover_register_indexed_dispatch_seeds(image, facts),
                 *discover_added_index_dispatch_seeds(image, facts),
                 *discover_nested_word_dispatch_seeds(image, facts)):
        if seed.address not in seen:
            seeds.append(seed)
            seen.add(seed.address)
    return tuple(seeds)


def _object_callback_tables(
    image: MegaDriveImage, facts: dict[int, InstructionFact]
) -> tuple[_DispatchTable, ...]:
    """Find indexed ROM pointers installed as object callbacks.

    The reader copies a longword from a four-byte-indexed table directly
    into the object's first field. Its A4 table base may be loaded directly
    or through a RAM variable initialized from a ROM address.
    """
    ends = {fact.cpu_address + fact.length: fact for fact in facts.values()}
    ordered = sorted(facts.values(), key=lambda item: item.cpu_address)
    occupied, _, starts = instruction_sets(facts)
    ram_bases: dict[int, set[int]] = {}
    immediate = re.compile(r"#(0x[0-9a-f]+)\|(D[0-7])$", re.I)
    ram_store = re.compile(r"(D[0-7])\|\((0x[0-9a-f]+)\)\.w$", re.I)
    ram_load = re.compile(r"\((0x[0-9a-f]+)\)\.w\|A4$", re.I)
    direct = re.compile(r"\((0x[0-9a-f]+)\)\.l\|A4$", re.I)
    indexed = re.compile(r"\(0x0,A4,(D[0-7])w\*0x1\)\|\(A1\)$", re.I)
    for position, second in enumerate(ordered):
        stored = ram_store.fullmatch(second.operands)
        if second.mnemonic.upper() != "MOVE.L" or stored is None:
            continue
        for first in reversed(ordered[max(0, position - 32):position]):
            if second.cpu_address - first.cpu_address > 0x40:
                break
            match = immediate.fullmatch(first.operands)
            if (first.mnemonic.upper() == "MOVE.L" and match is not None
                    and match.group(2).upper() == stored.group(1).upper()):
                ram_bases.setdefault(int(stored.group(2), 0), set()).add(int(match.group(1), 0))

    origins: list[tuple[int, set[int]]] = []
    for fact in ordered:
        found = direct.fullmatch(fact.operands)
        if fact.mnemonic.upper() == "LEA" and found is not None:
            origins.append((fact.cpu_address, {int(found.group(1), 0)}))
        found = ram_load.fullmatch(fact.operands)
        if fact.mnemonic.upper() == "MOVEA.L" and found is not None:
            bases = ram_bases.get(int(found.group(1), 0))
            if bases:
                origins.append((fact.cpu_address, bases))

    tables: dict[int, _DispatchTable] = {}
    for read in ordered:
        match = indexed.fullmatch(read.operands)
        if read.mnemonic.upper() != "MOVE.L" or match is None:
            continue
        register = match.group(1).upper()
        second = ends.get(read.cpu_address)
        first = ends.get(second.cpu_address) if second is not None else None
        if not all(
            item is not None and item.mnemonic.upper() == "ADD.W"
            and item.operands.upper() == f"{register}W|{register}W"
            for item in (first, second)
        ):
            continue
        source = ends.get(first.cpu_address)
        if (source is None or source.mnemonic.upper() != "MOVE.B"
                or not source.operands.upper().endswith(f"|{register}B")):
            continue
        preceding = [item for item in origins
                     if 0 < read.cpu_address - item[0] <= 0x2000]
        if not preceding:
            continue
        origin, bases = preceding[-1]
        for table in bases:
            offset = table - image.header.rom_start
            if (table in tables or offset < 0x200 or table & 1
                    or offset + 32 > len(image.data) or offset in occupied):
                continue
            entries: list[PointerEntry] = []
            for index in range(MAX_DISPATCH_ENTRIES):
                at = offset + index * 4
                if at + 4 > len(image.data) or any(at + part in occupied for part in range(4)):
                    break
                target = int.from_bytes(image.data[at:at + 4], "big")
                physical = target - image.header.rom_start
                if (not _mapped(image, target) or physical < 0x200
                        or physical + 2 > len(image.data)
                        or offset <= physical < at + 4
                        or image.data[physical:physical + 2] in {b"\x00\x00", b"\xff\xff"}):
                    break
                entries.append(PointerEntry(at, image.header.rom_start + at, target, target))
            if len(entries) < 8 or len({entry.target for entry in entries}) < 8:
                continue
            tables[table] = _DispatchTable(
                candidate=PointerCandidate(
                    candidate_id=f"Ptr_u32be-object-callback_{table:06X}",
                    schema_id="megadrive.u32be.absolute",
                    physical_start=offset,
                    physical_end=offset + 4 * len(entries),
                    logical_start=table,
                    entry_size=4,
                    status="accepted" if all(entry.target in starts for entry in entries) else "candidate",
                    score=90,
                    entries=tuple(entries),
                    evidence=(f"table_base_at_{origin:06X}",
                              f"indexed_object_callback_store_at_{read.cpu_address:06X}",
                              f"entry_count={len(entries)}"),
                    contradictions=(),
                ),
                load_address=read.cpu_address,
                call_address=read.cpu_address,
                call_mnemonic="OBJECT_CALLBACK",
            )
    return tuple(tables[address] for address in sorted(tables))


def _word_dispatch_tables(
    image: MegaDriveImage, facts: dict[int, InstructionFact]
) -> tuple[_DispatchTable, ...]:
    """Prove signed-word dispatches with a constant or entry-address base.

    MOVEA.W (table,PC,Dn.W),An / ADDA.L #base,An uses a constant base.
    LEA (table,PC,Dn.W),An / ADDA.W (An),An uses each entry's own address.
    Both must end with JMP/JSR (An); ADDA.W sign-extends its source word.
    Read until code, another explicit data boundary, or an invalid target;
    a forward code base also bounds the table before the first handler.
    """
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    occupied, interiors, instruction_starts = instruction_sets(facts)
    boundaries = absolute_referenced_addresses(facts)
    rom_start = image.header.rom_start
    data = image.data
    tables: dict[int, _DispatchTable] = {}
    for load in sorted(facts.values(), key=lambda fact: fact.cpu_address):
        word_load = load.mnemonic.upper() == "MOVEA.W"
        if not word_load and load.mnemonic.upper() != "LEA":
            continue
        indexed = _PC_INDEXED_ADDRESS.fullmatch(load.operands)
        if indexed is None or load.flow_type.upper() != "FALL_THROUGH":
            continue
        table = int(indexed.group(1), 0)
        register = indexed.group(2).upper()
        add = by_address.get(load.cpu_address + load.length)
        if (
            add is None or add.mnemonic.upper() != ("ADDA.L" if word_load else "ADDA.W")
            or add.flow_type.upper() != "FALL_THROUGH"
        ):
            continue
        if word_load:
            immediate = _IMMEDIATE_ADDRESS.fullmatch(add.operands)
            if immediate is None or immediate.group(2).upper() != register:
                continue
            base = int(immediate.group(1), 0) & 0xFFFFFF
            schema = "megadrive.s16be.target-code_base"
            base_evidence = f"adda_l_base_{base:06X}_at_{add.cpu_address:06X}"
            arithmetic_evidence = "signed_word_offsets_added_to_constant_base"
        else:
            indirect = _INDIRECT_TO_ADDRESS.fullmatch(add.operands)
            if indirect is None or any(group.upper() != register for group in indirect.groups()):
                continue
            base = None
            schema = "megadrive.s16be.target-entry_address"
            base_evidence = f"adda_w_entry_base_at_{add.cpu_address:06X}"
            arithmetic_evidence = "signed_word_offsets_added_to_entry_address"
        call = by_address.get(add.cpu_address + add.length)
        if (
            call is None or call.mnemonic.upper() not in {"JMP", "JSR"}
            or (target_register := _REGISTER_INDIRECT.fullmatch(call.operands)) is None
            or target_register.group(1).upper() != register
        ):
            continue
        start = table - rom_start
        if (
            table in tables or start < 0x200 or table & 1
            or start + 2 * MIN_DISPATCH_ENTRIES > len(data)
            or (base is not None and not _mapped(image, base))
        ):
            continue
        limit = min(len(data), start + 2 * MAX_DISPATCH_ENTRIES)
        if base is not None and table < base:
            limit = min(limit, base - rom_start)
        forward_code_start = limit
        entries: list[PointerEntry] = []
        for offset in range(start, limit - 1, 2):
            if offset + 2 > forward_code_start:
                break
            if offset in occupied or offset + 1 in occupied:
                break
            if entries and rom_start + offset in boundaries:
                break
            raw = int.from_bytes(data[offset:offset + 2], "big")
            entry_base = base if base is not None else rom_start + offset
            target = (entry_base + (raw - 0x10000 if raw & 0x8000 else raw)) & 0xFFFFFF
            physical = target - rom_start
            if (
                not _mapped(image, target) or physical < 0x200
                or physical + 2 > len(data) or physical in interiors
                or start <= physical < offset + 2
                or data[physical:physical + 2] in {b"\x00\x00", b"\xff\xff"}
            ):
                break
            entries.append(PointerEntry(offset, rom_start + offset, raw, target, entry_base))
            if physical >= start:
                # A forward handler is also a structural end boundary. Without
                # this, undecoded handler opcodes can resemble more offsets and
                # make the whole table appear self-referencing on the next pass.
                forward_code_start = min(forward_code_start, physical)
        while entries:
            end = start + 2 * len(entries)
            inside = next((
                index for index, entry in enumerate(entries)
                if start <= entry.target - rom_start < end
            ), None)
            if inside is None:
                break
            entries = entries[:inside]
        if len(entries) < MIN_DISPATCH_ENTRIES:
            continue
        decoded = sum(entry.target in instruction_starts for entry in entries)
        accepted = decoded == len(entries)
        tables[table] = _DispatchTable(
            candidate=PointerCandidate(
                candidate_id=f"Ptr_s16be-dispatch_{'code' if word_load else 'entry'}_{table:06X}",
                schema_id=schema,
                physical_start=start, physical_end=start + 2 * len(entries),
                logical_start=table, entry_size=2,
                status="accepted" if accepted else "candidate", score=100 if accepted else 60,
                entries=tuple(entries),
                evidence=(
                    f"indexed_{'movea_w' if word_load else 'lea'}_at_{load.cpu_address:06X}",
                    base_evidence,
                    f"{call.mnemonic.lower()}_indirect_at_{call.cpu_address:06X}",
                    arithmetic_evidence,
                    f"entry_count={len(entries)}", f"instruction_targets={decoded}",
                ),
                contradictions=(),
            ),
            load_address=load.cpu_address, call_address=call.cpu_address,
            call_mnemonic=call.mnemonic.upper(),
        )
    return tuple(tables[address] for address in sorted(tables))


def _pc_word_dispatch_tables(
    image: MegaDriveImage, facts: dict[int, InstructionFact],
    *, handler_validator: Callable[[int], bool] | None = None,
    skip_conflicting_targets: bool = False,
) -> tuple[_DispatchTable, ...]:
    """Recover signed offsets loaded from a table then used by PC-indexed JMP/JSR."""
    from retrolarium_disasm.m68k.abstract import _register_list
    by_address = {fact.cpu_address: fact for fact in facts.values()}
    occupied, interiors, instruction_starts = instruction_sets(facts)
    boundaries = absolute_referenced_addresses(facts)
    weak_boundaries = None
    rom_start, data = image.header.rom_start, image.data
    tables = {}
    for load in facts.values():
        if load.mnemonic.upper() != "MOVE.W":
            continue
        indexed = _PC_WORD_TO_DATA.fullmatch(load.operands)
        if indexed is None or load.flow_type.upper() != "FALL_THROUGH":
            continue
        call = by_address.get(load.cpu_address + load.length)
        branch = None
        # The loaded table offset may be used after a few independent
        # instructions, for example a stack push before an indirect JSR.
        for _ in range(4):
            if call is None:
                break
            branch = _PC_WORD_BRANCH.fullmatch(call.operands)
            if call.mnemonic.upper() in {"JMP", "JSR"} and branch is not None:
                break
            offset_register = indexed.group(2).upper()
            operands = call.operands.upper().split("|")
            operation = call.mnemonic.upper().split(".", 1)[0]
            clobbers_offset = operands[-1] in {
                offset_register + size for size in ("", "B", "W", "L")
            }
            if operation == "MOVEM":
                clobbers_offset |= offset_register.lower() in _register_list(operands[-1])
            if operation == "EXG":
                clobbers_offset |= offset_register in operands
            if (call.flow_type.upper() != "FALL_THROUGH"
                    or clobbers_offset):
                call = None
                break
            call = by_address.get(call.cpu_address + call.length)
        else:
            call = None
        if (call is None or call.mnemonic.upper() not in {"JMP", "JSR"}
                or branch is None or int(indexed.group(1), 0) != int(branch.group(1), 0)
                or indexed.group(2).upper() != branch.group(2).upper()):
            continue
        table = int(indexed.group(1), 0)
        start = table - rom_start
        if (table in tables or start < 0x200 or table & 1
                or start + 2 * MIN_DISPATCH_ENTRIES > len(data)):
            continue
        entries = []
        strict_entries = None
        before_conflict = None
        excluded_targets = set()
        witness = None
        suffix_witnesses = ()
        forward_code_start = min(len(data), start + 2 * MAX_DISPATCH_ENTRIES)
        for offset in range(start, forward_code_start - 1, 2):
            if (offset + 2 > forward_code_start
                    or offset in occupied or offset + 1 in occupied):
                break
            if entries and rom_start + offset in boundaries:
                if handler_validator is None:
                    break
                if weak_boundaries is None:
                    weak_boundaries = _weak_absolute_lea_boundaries(facts)
                if rom_start + offset not in weak_boundaries:
                    break
                if strict_entries is None:
                    strict_entries = list(entries)
            raw = int.from_bytes(data[offset:offset + 2], "big")
            target = (table + (raw - 0x10000 if raw & 0x8000 else raw)) & 0xFFFFFF
            physical = target - rom_start
            if (not _mapped(image, target) or physical < 0x200
                    or physical + 2 > len(data)
                    or start <= physical < offset + 2
                    or data[physical:physical + 2] in {b"\x00\x00", b"\xff\xff"}):
                break
            if physical in interiors:
                if not skip_conflicting_targets:
                    break
                if before_conflict is None:
                    before_conflict = list(entries)
                excluded_targets.add(target)
            entries.append(PointerEntry(offset, rom_start + offset, raw, target, table))
            if physical >= start:
                forward_code_start = min(forward_code_start, physical)
        if strict_entries is not None:
            # A weak LEA annotation is not negative evidence of a pointer.
            # Supersede it only locally: the table must finish exactly at its
            # first forward handler, and a rooted-code-connected complete CFG
            # must independently establish at least one speculative handler.
            end = start + 2 * len(entries)
            if (end == forward_code_start
                    and rom_start + end in {entry.target for entry in entries}):
                witness = next((entry.target for entry in entries
                                if handler_validator(entry.target)), None)
            if witness is None:
                entries = strict_entries
        if before_conflict is not None:
            end = start + 2 * len(entries)
            # A conflict at one handler must not silently shorten a bounded
            # array. Keep its slot for geometry, but never seed that address.
            # A decoded forward handler bounds the scan, but adjacent data can
            # still imitate offsets before it. Require an independent complete
            # CFG for each new suffix target; a valid neighbour is not proof.
            if not (end == forward_code_start and rom_start + end in instruction_starts
                    and rom_start + end in {entry.target for entry in entries}):
                entries = before_conflict if len(before_conflict) < len(entries) else entries
                excluded_targets.clear()
            else:
                suffix_targets = ({entry.target for entry in entries}
                                  - {entry.target for entry in before_conflict}
                                  - excluded_targets)
                suffix_witnesses = tuple(sorted(target for target in suffix_targets
                    if handler_validator is not None and handler_validator(target)))
                if suffix_witnesses:
                    excluded_targets.update(suffix_targets - set(suffix_witnesses))
                else:
                    entries = before_conflict if len(before_conflict) < len(entries) else entries
                    excluded_targets.clear()
        if len(entries) < MIN_DISPATCH_ENTRIES:
            continue
        decoded = sum(entry.target in instruction_starts for entry in entries)
        tables[table] = _DispatchTable(
            candidate=PointerCandidate(
                candidate_id=f"Ptr_s16be-pc-word-dispatch_{table:06X}",
                schema_id="megadrive.s16be.target-table_base",
                physical_start=start, physical_end=start + len(entries) * 2,
                logical_start=table, entry_size=2,
                status="accepted" if decoded == len(entries) else "candidate",
                score=100 if decoded == len(entries) else 60,
                entries=tuple(entries),
                evidence=(f"indexed_move_w_at_{load.cpu_address:06X}",
                          f"{call.mnemonic.lower()}_pc_indexed_at_{call.cpu_address:06X}",
                          "same_pc_relative_table_base_and_offset_register",
                          f"entry_count={len(entries)}", f"instruction_targets={decoded}")
                         + ((f"complete_cfg_witness_at_{witness:06X}",) if witness is not None else ())
                         + tuple(f"complete_cfg_witness_at_{target:06X}" for target in suffix_witnesses),
                contradictions=(),
            ),
            load_address=load.cpu_address, call_address=call.cpu_address,
            call_mnemonic=call.mnemonic.upper(),
            seed_kind="pc_word_dispatch", seed_confidence="proven",
            excluded_targets=frozenset(excluded_targets),
        )
    return tuple(tables[address] for address in sorted(tables))


def detect_pointer_candidates(
    image: MegaDriveImage, facts: dict[int, InstructionFact], *, scan_start: int = 0x200,
) -> tuple[PointerCandidate, ...]:
    """Detect pointer schemas; ``scan_start`` bounds physical scan-only work.

    Explicit instruction-derived tables and vectors keep their original gates.
    Overlay callers can skip their synthetic address-view prefix without
    changing any candidate within the real module bytes.
    """
    if not isinstance(scan_start, int) or scan_start < 0 or scan_start & 1:
        raise ValueError("pointer scan start must be a nonnegative even physical offset")
    candidates = [_vector_candidate(image)]
    candidates.extend(_ram_trampoline_candidates(image, facts, scan_start=scan_start))
    candidates.extend(
        table.candidate for table in _dispatch_tables(image, facts)
    )
    candidates.extend(table.candidate for table in _word_dispatch_tables(image, facts))
    candidates.extend(table.candidate for table in _pc_word_dispatch_tables(image, facts))
    absolute = tuple(_absolute_candidates(image, facts, 4, scan_start=scan_start))
    candidates.extend(absolute)
    candidates.extend(_animation_candidates(image, facts, absolute, scan_start=scan_start))
    candidates.extend(_absolute_candidates(image, facts, 2, scan_start=scan_start))
    candidates.extend(_relative_candidates(image, facts, "table_base", scan_start=scan_start))
    candidates.extend(_relative_candidates(image, facts, "entry_address", scan_start=scan_start))
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
