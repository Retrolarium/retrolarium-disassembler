"""Explainable pointer schemas over independently decoded SNES ROM bytes."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from retrolarium_core.snes import (
    SnesError,
    SnesImage,
    rom_offset_aliases,
    snes_to_rom_offset,
)
from retrolarium_disassembler.snes.analysis import AnalysisResult


MIN_ENTRIES = 3
MAX_ENTRIES = 64
MAX_SPLIT_ENTRIES = 16


@dataclass(frozen=True)
class PointerEntry:
    physical_offset: int
    logical_address: int
    raw_value: int
    target: int
    base_address: int | None = None
    component_offsets: tuple[int, ...] = ()

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "physical_offset": self.physical_offset,
            "logical_address": self.logical_address,
            "raw_value": self.raw_value,
            "target": self.target,
        }
        if self.base_address is not None:
            result["base_address"] = self.base_address
        if self.component_offsets:
            result["component_offsets"] = list(self.component_offsets)
        return result


@dataclass(frozen=True)
class PointerCandidate:
    candidate_id: str
    schema_id: str
    physical_start: int
    physical_end: int
    logical_start: int
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
            "status": self.status,
            "score": self.score,
            "entries": [entry.as_dict() for entry in self.entries],
            "evidence": list(self.evidence),
            "contradictions": list(self.contradictions),
        }


def _instruction_sets(
    result: AnalysisResult,
) -> tuple[set[int], set[int], set[int]]:
    occupied: set[int] = set()
    interiors: set[int] = set()
    starts: set[int] = set()
    for instruction in result.instructions:
        starts.add(instruction.logical_address)
        occupied.update(
            range(
                instruction.physical_offset,
                instruction.physical_offset + instruction.length,
            )
        )
        interiors.update(
            range(
                instruction.physical_offset + 1,
                instruction.physical_offset + instruction.length,
            )
        )
    return occupied, interiors, starts


def _physical_target(image: SnesImage, target: int) -> int | None:
    try:
        return snes_to_rom_offset(image, target)
    except SnesError:
        return None


def _table_aliases(image: SnesImage, offset: int) -> tuple[int, ...]:
    return rom_offset_aliases(image, offset)


def _evaluate(
    schema_id: str,
    physical_start: int,
    physical_end: int,
    logical_start: int,
    entries: tuple[PointerEntry, ...],
    instruction_starts: set[int],
    instruction_interiors: set[int],
    image: SnesImage,
) -> PointerCandidate:
    target_offsets = tuple(
        _physical_target(image, entry.target) for entry in entries
    )
    contradictions: list[str] = []
    if any(offset is None for offset in target_offsets):
        contradictions.append("target_outside_file_backed_rom")
    if any(
        offset in instruction_interiors
        for offset in target_offsets
        if offset is not None
    ):
        contradictions.append("target_inside_instruction")
    if any(
        physical_start <= offset < physical_end
        for offset in target_offsets
        if offset is not None
    ):
        contradictions.append("target_inside_own_table")
    instruction_targets = sum(
        entry.target in instruction_starts for entry in entries
    )
    evidence = (
        "all_entries_map_to_file_backed_rom",
        f"entry_count={len(entries)}",
        f"instruction_targets={instruction_targets}",
        "all_targets_are_instruction_starts",
    )
    accepted = (
        len(entries) >= MIN_ENTRIES
        and instruction_targets == len(entries)
        and not contradictions
    )
    score = min(100, 45 + len(entries) * 5 + instruction_targets * 10)
    slug = schema_id.removeprefix("snes.").replace(".", "-")
    return PointerCandidate(
        candidate_id=f"Ptr_{slug}_{logical_start:06X}",
        schema_id=schema_id,
        physical_start=physical_start,
        physical_end=physical_end,
        logical_start=logical_start,
        status="accepted" if accepted else "rejected",
        score=score if accepted else max(0, score - 50),
        entries=entries,
        evidence=evidence,
        contradictions=tuple(contradictions),
    )


def _u16_candidates(
    image: SnesImage,
    occupied: set[int],
    interiors: set[int],
    starts: set[int],
) -> list[PointerCandidate]:
    candidates: list[PointerCandidate] = []
    for start in range(0, len(image.data) - MIN_ENTRIES * 2 + 1):
        if start in occupied:
            continue
        for logical_start in _table_aliases(image, start):
            bank = logical_start & 0xFF0000
            if start >= 2 and start - 2 not in occupied:
                previous = int.from_bytes(
                    image.data[start - 2 : start], "little"
                )
                if bank | previous in starts:
                    continue
            entries: list[PointerEntry] = []
            targets: set[int] = set()
            offset = start
            while offset + 2 <= len(image.data) and len(entries) < MAX_ENTRIES:
                if offset in occupied or offset + 1 in occupied:
                    break
                raw = int.from_bytes(image.data[offset : offset + 2], "little")
                target = bank | raw
                if target not in starts or target in targets:
                    break
                targets.add(target)
                entries.append(
                    PointerEntry(
                        offset,
                        logical_start + (offset - start),
                        raw,
                        target,
                    )
                )
                offset += 2
            if len(entries) >= MIN_ENTRIES:
                candidates.append(
                    _evaluate(
                        "snes.u16le.current-bank",
                        start,
                        offset,
                        logical_start,
                        tuple(entries),
                        starts,
                        interiors,
                        image,
                    )
                )
    return candidates


def _u24_candidates(
    image: SnesImage,
    occupied: set[int],
    interiors: set[int],
    starts: set[int],
) -> list[PointerCandidate]:
    candidates: list[PointerCandidate] = []
    for start in range(0, len(image.data) - MIN_ENTRIES * 3 + 1):
        if start in occupied:
            continue
        if start >= 3 and start - 3 not in occupied:
            previous = int.from_bytes(image.data[start - 3 : start], "little")
            if previous in starts:
                continue
        entries: list[PointerEntry] = []
        targets: set[int] = set()
        offset = start
        while offset + 3 <= len(image.data) and len(entries) < MAX_ENTRIES:
            if any(item in occupied for item in range(offset, offset + 3)):
                break
            target = int.from_bytes(image.data[offset : offset + 3], "little")
            if target not in starts or target in targets:
                break
            targets.add(target)
            logical = next(
                (
                    alias
                    for alias in _table_aliases(image, offset)
                    if alias >> 16 == target >> 16
                ),
                _table_aliases(image, offset)[0],
            )
            entries.append(PointerEntry(offset, logical, target, target))
            offset += 3
        if len(entries) >= MIN_ENTRIES:
            logical_start = entries[0].logical_address
            candidates.append(
                _evaluate(
                    "snes.u24le.far",
                    start,
                    offset,
                    logical_start,
                    tuple(entries),
                    starts,
                    interiors,
                    image,
                )
            )
    return candidates


def _relative_candidates(
    image: SnesImage,
    occupied: set[int],
    interiors: set[int],
    starts: set[int],
) -> list[PointerCandidate]:
    candidates: list[PointerCandidate] = []
    for start in range(0, len(image.data) - MIN_ENTRIES * 2 + 1):
        if start in occupied:
            continue
        for logical_start in _table_aliases(image, start):
            entries: list[PointerEntry] = []
            targets: set[int] = set()
            offset = start
            while offset + 2 <= len(image.data) and len(entries) < MAX_ENTRIES:
                if offset in occupied or offset + 1 in occupied:
                    break
                raw = int.from_bytes(image.data[offset : offset + 2], "little")
                signed = int.from_bytes(
                    image.data[offset : offset + 2], "little", signed=True
                )
                target = (logical_start & 0xFF0000) | (
                    ((logical_start & 0xFFFF) + signed) & 0xFFFF
                )
                if target not in starts or target in targets:
                    break
                targets.add(target)
                entries.append(
                    PointerEntry(
                        offset,
                        logical_start + (offset - start),
                        raw,
                        target,
                        base_address=logical_start,
                    )
                )
                offset += 2
            if len(entries) >= MIN_ENTRIES:
                candidates.append(
                    _evaluate(
                        "snes.s16le.table-base",
                        start,
                        offset,
                        logical_start,
                        tuple(entries),
                        starts,
                        interiors,
                        image,
                    )
                )
    return candidates


def _split_candidates(
    image: SnesImage,
    occupied: set[int],
    interiors: set[int],
    starts: set[int],
) -> list[PointerCandidate]:
    candidates: list[PointerCandidate] = []
    size = len(image.data)
    for start in range(0, size - MIN_ENTRIES * 3 + 1):
        if start in occupied:
            continue
        for count in range(MIN_ENTRIES, MAX_SPLIT_ENTRIES + 1):
            end = start + count * 3
            if end > size:
                break
            first_target = (
                image.data[start]
                | image.data[start + count] << 8
                | image.data[start + count * 2] << 16
            )
            if first_target not in starts:
                continue
            if any(item in occupied for item in range(start, end)):
                break
            entries: list[PointerEntry] = []
            targets: set[int] = set()
            for index in range(count):
                low_offset = start + index
                high_offset = start + count + index
                bank_offset = start + count * 2 + index
                target = (
                    image.data[low_offset]
                    | image.data[high_offset] << 8
                    | image.data[bank_offset] << 16
                )
                if target not in starts or target in targets:
                    break
                targets.add(target)
                logical = next(
                    (
                        alias
                        for alias in _table_aliases(image, low_offset)
                        if alias >> 16 == target >> 16
                    ),
                    _table_aliases(image, low_offset)[0],
                )
                entries.append(
                    PointerEntry(
                        low_offset,
                        logical,
                        target,
                        target,
                        component_offsets=(low_offset, high_offset, bank_offset),
                    )
                )
            if len(entries) == count:
                logical_start = entries[0].logical_address
                candidates.append(
                    _evaluate(
                        "snes.split-lo-hi-bank",
                        start,
                        end,
                        logical_start,
                        tuple(entries),
                        starts,
                        interiors,
                        image,
                    )
                )
    return candidates


def _vector_candidate(image: SnesImage) -> PointerCandidate:
    entries = tuple(
        PointerEntry(
            physical_offset=image.header_offset + 0x20 + index * 2,
            logical_address=0x00FFE0 + index * 2,
            raw_value=vector.raw_value,
            target=vector.cpu_address,
        )
        for index, vector in enumerate(image.vector_table)
        if vector.cpu_address is not None
    )
    return PointerCandidate(
        candidate_id=f"SnesVectors_{image.header_offset + 0x20:06X}",
        schema_id="snes.vectors.u16le.bank00",
        physical_start=image.header_offset + 0x20,
        physical_end=image.header_offset + 0x40,
        logical_start=0x00FFE0,
        status="accepted",
        score=100,
        entries=entries,
        evidence=("validated_internal_header_vector_table",),
        contradictions=(),
    )


def detect_pointer_candidates(
    image: SnesImage, result: AnalysisResult
) -> tuple[PointerCandidate, ...]:
    occupied, interiors, starts = _instruction_sets(result)
    occupied.update(range(image.header_offset, image.header_offset + 0x40))
    candidates: list[PointerCandidate] = [_vector_candidate(image)]
    candidates.extend(_u16_candidates(image, occupied, interiors, starts))
    candidates.extend(_u24_candidates(image, occupied, interiors, starts))
    candidates.extend(_relative_candidates(image, occupied, interiors, starts))
    candidates.extend(_split_candidates(image, occupied, interiors, starts))
    unique: dict[tuple[str, int, int], PointerCandidate] = {}
    for candidate in candidates:
        key = (
            candidate.schema_id,
            candidate.physical_start,
            candidate.physical_end,
        )
        previous = unique.get(key)
        if previous is None or candidate.score > previous.score:
            unique[key] = candidate
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (
                item.physical_start,
                item.schema_id,
                item.physical_end,
            ),
        )
    )


def accepted_pointer_tables(
    candidates: tuple[PointerCandidate, ...],
) -> tuple[PointerCandidate, ...]:
    return tuple(candidate for candidate in candidates if candidate.status == "accepted")


def write_pointer_report(
    path: Path,
    image: SnesImage,
    candidates: tuple[PointerCandidate, ...],
) -> None:
    document = {
        "schema": "retrolarium.snes.pointers",
        "schema_version": 1,
        "input_sha256": image.rom_sha256,
        "schemas": [
            "snes.vectors.u16le.bank00",
            "snes.u16le.current-bank",
            "snes.u24le.far",
            "snes.split-lo-hi-bank",
            "snes.s16le.table-base",
        ],
        "candidates": [candidate.as_dict() for candidate in candidates],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
