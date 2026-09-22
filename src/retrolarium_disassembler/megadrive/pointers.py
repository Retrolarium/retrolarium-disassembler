"""Explainable big-endian pointer schemas for Mega Drive cartridge ROMs."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from .facts import InstructionFact
from .megadrive import MegaDriveImage
from .m68k_seeds import discover_ram_trampoline_tables


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
        if "DATA" in reference.reference_type
    }


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
    ratio = target_starts / len(entries)
    if not referenced and ratio < 0.75:
        return None
    accepted = (
        len(entries) >= MIN_ACCEPTED_ENTRIES
        and not contradictions
        and all_instruction_targets
    )
    status = "accepted" if accepted else "rejected" if contradictions else "candidate"
    score = 35 + min(len(entries) * 3, 24) + min(target_starts * 8, 32)
    if referenced:
        score += 10
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
    candidates: list[PointerCandidate] = []
    for start in range(0x200, max(0x200, len(image.data) - 5), 2):
        entries: list[PointerEntry] = []
        offset = start
        while offset + 2 <= len(image.data) and len(entries) < MAX_ENTRIES:
            if offset in occupied or offset + 1 in occupied:
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


def detect_pointer_candidates(
    image: MegaDriveImage, facts: dict[int, InstructionFact]
) -> tuple[PointerCandidate, ...]:
    candidates = [_vector_candidate(image)]
    candidates.extend(_ram_trampoline_candidates(image, facts))
    candidates.extend(_absolute_candidates(image, facts, 4))
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
