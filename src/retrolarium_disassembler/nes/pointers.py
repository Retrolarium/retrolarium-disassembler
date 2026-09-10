"""Explainable pointer-table candidates for immutable NES PRG bytes."""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
from pathlib import Path
import re
import struct

from .facts import InstructionFact
from .ines import (
    InesImage,
    canonical_prg_start,
    cpu_to_prg_offset,
    prg_analysis_targets,
)


MIN_CANDIDATE_ENTRIES = 3
MIN_ACCEPTED_ENTRIES = 4
MAX_ACCEPTED_TARGET_SPAN = 0x800
MAX_UNREFERENCED_TARGET_SPAN = 0x100
MAX_ANCHORED_FIELD_OFFSET = 3
MAX_ANCHORED_ENTRIES = 8
MAX_INTERLEAVED_ENTRIES = 32
MAX_INTERLEAVED_LANE_SPAN = 0x400
MAX_INTERLEAVED_TARGET_DISTANCE = 0x2000
OPERAND_HEX_RE = re.compile(r"0x([0-9a-fA-F]+)")


@dataclass(frozen=True)
class PointerEntry:
    physical_offset: int
    cpu_address: int
    target: int
    high_physical_offset: int | None = None
    high_cpu_address: int | None = None
    bank: int = 0

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "physical_offset": self.physical_offset,
            "cpu_address": self.cpu_address,
            "target": self.target,
            "bank": self.bank,
        }
        if self.high_physical_offset is not None:
            result["high_physical_offset"] = self.high_physical_offset
            result["high_cpu_address"] = self.high_cpu_address
        return result


@dataclass(frozen=True)
class PointerCandidate:
    candidate_id: str
    schema_id: str
    physical_start: int
    physical_end: int
    cpu_start: int
    status: str
    score: int
    entries: tuple[PointerEntry, ...]
    evidence: tuple[str, ...]
    contradictions: tuple[str, ...]
    bank: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.candidate_id,
            "schema_id": self.schema_id,
            "physical_start": self.physical_start,
            "physical_end": self.physical_end,
            "cpu_start": self.cpu_start,
            "bank": self.bank,
            "status": self.status,
            "score": self.score,
            "entries": [entry.as_dict() for entry in self.entries],
            "evidence": list(self.evidence),
            "contradictions": list(self.contradictions),
        }


def accepted_u16le(
    candidates: tuple[PointerCandidate, ...]
) -> tuple[PointerCandidate, ...]:
    return tuple(
        candidate
        for candidate in candidates
        if candidate.schema_id == "nes.u16le" and candidate.status == "accepted"
    )


def accepted_pointer_tables(
    candidates: tuple[PointerCandidate, ...]
) -> tuple[PointerCandidate, ...]:
    return tuple(
        candidate
        for candidate in candidates
        if candidate.schema_id in {"nes.u16le", "nes.split_lo_hi"}
        and candidate.status == "accepted"
    )


def _instruction_sets(
    image: InesImage, facts: dict[int, InstructionFact],
) -> tuple[set[int], set[int], set[int], set[int]]:
    occupied: set[int] = set()
    interiors: set[int] = set()
    starts: set[int] = set(facts)
    control_targets: set[int] = set()
    for fact in facts.values():
        occupied.update(range(fact.physical_offset, fact.physical_offset + fact.length))
        interiors.update(
            range(fact.physical_offset + 1, fact.physical_offset + fact.length)
        )
        for target in fact.flows:
            try:
                control_targets.add(cpu_to_prg_offset(image, target))
            except ValueError:
                pass
    return occupied, interiors, starts, control_targets


def _operand_references(facts: dict[int, InstructionFact]) -> set[int]:
    references: set[int] = set()
    for fact in facts.values():
        if fact.operands.lstrip().startswith("#"):
            continue
        for match in OPERAND_HEX_RE.finditer(fact.operands):
            value = int(match.group(1), 16)
            if 0 <= value <= 0xFFFF:
                references.add(value)
    return references


def _operand_reference_offsets(
    image: InesImage, facts: dict[int, InstructionFact]
) -> set[int]:
    offsets: set[int] = set()
    for address in _operand_references(facts):
        try:
            offsets.add(cpu_to_prg_offset(image, address))
        except ValueError:
            pass
    return offsets


def _mapped_target(image: InesImage, target: int) -> bool:
    try:
        cpu_to_prg_offset(image, target)
    except ValueError:
        return False
    return True


def _evaluate_u16le(
    image: InesImage,
    entries: tuple[PointerEntry, ...],
    interiors: set[int],
    instruction_starts: set[int],
    control_targets: set[int],
    operand_reference_offsets: set[int],
) -> PointerCandidate:
    start = entries[0].physical_offset
    end = entries[-1].physical_offset + 2
    cpu_start = entries[0].cpu_address
    targets = tuple(entry.target for entry in entries)
    evidence = ["all_entries_map_to_prg", f"entry_count={len(entries)}"]
    contradictions: list[str] = []
    score = 30 + min(len(entries) * 2, 20)

    if all(left < right for left, right in zip(targets, targets[1:])):
        evidence.append("targets_strictly_increasing")
        score += 20
    else:
        contradictions.append("targets_not_strictly_increasing")
        score -= 20

    span = max(targets) - min(targets)
    if span <= MAX_ACCEPTED_TARGET_SPAN:
        evidence.append(f"compact_target_span={span}")
        score += 15
    else:
        contradictions.append(f"wide_target_span={span}")
        score -= 10

    referenced = start in operand_reference_offsets
    if referenced:
        evidence.append("table_start_referenced_by_instruction")
        score += 10

    target_offsets = tuple(cpu_to_prg_offset(image, target) for target in targets)
    instruction_target_count = sum(
        offset in instruction_starts for offset in target_offsets
    )
    if instruction_target_count:
        evidence.append(f"instruction_targets={instruction_target_count}")
        score += min(instruction_target_count, 5)
    if any(offset in interiors for offset in target_offsets):
        contradictions.append("target_inside_instruction")
        score -= 30
    if any(start <= offset < end for offset in target_offsets):
        contradictions.append("target_inside_own_table")
        score -= 30

    if any(start < target < end for target in control_targets):
        contradictions.append("control_target_inside_table")
        score -= 30

    hard_rejection = bool(contradictions)
    promotion_evidence = referenced or span <= MAX_UNREFERENCED_TARGET_SPAN
    if not promotion_evidence:
        evidence.append("awaiting_reference_or_tighter_target_cluster")
    accepted = (
        len(entries) >= MIN_ACCEPTED_ENTRIES
        and not hard_rejection
        and promotion_evidence
    )
    status = "accepted" if accepted else "rejected" if hard_rejection else "candidate"
    return PointerCandidate(
        candidate_id=f"PtrTable_B00_{cpu_start:04X}",
        schema_id="nes.u16le",
        physical_start=start,
        physical_end=end,
        cpu_start=cpu_start,
        status=status,
        score=max(0, min(score, 100)),
        entries=entries,
        evidence=tuple(evidence),
        contradictions=tuple(contradictions),
    )


def _u16le_candidates(
    image: InesImage, facts: dict[int, InstructionFact]
) -> list[PointerCandidate]:
    occupied, interiors, instruction_starts, control_targets = _instruction_sets(
        image, facts
    )
    operand_reference_offsets = _operand_reference_offsets(image, facts)
    candidates: list[PointerCandidate] = []
    scan_end = max(0, len(image.prg) - 6)
    cpu_base = canonical_prg_start(image)

    # Scan the two possible byte alignments independently and keep maximal
    # runs. This avoids reporting every suffix of the same table.
    for alignment in (0, 1):
        offset = alignment
        while offset + 1 < scan_end:
            if offset in occupied or offset + 1 in occupied:
                offset += 2
                continue
            target = int.from_bytes(image.prg[offset:offset + 2], "little")
            if not _mapped_target(image, target):
                offset += 2
                continue
            start = offset
            entries: list[PointerEntry] = []
            while offset + 1 < scan_end:
                if offset in occupied or offset + 1 in occupied:
                    break
                target = int.from_bytes(image.prg[offset:offset + 2], "little")
                if not _mapped_target(image, target):
                    break
                entries.append(PointerEntry(offset, cpu_base + offset, target))
                offset += 2
            if len(entries) >= MIN_CANDIDATE_ENTRIES:
                evaluated = _evaluate_u16le(
                    image,
                    tuple(entries),
                    interiors,
                    instruction_starts,
                    control_targets,
                    operand_reference_offsets,
                )
                instruction_target_count = sum(
                    cpu_to_prg_offset(image, entry.target) in instruction_starts
                    for entry in entries
                )
                interesting = (
                    "targets_strictly_increasing" in evaluated.evidence
                    or evaluated.physical_start in operand_reference_offsets
                    or instruction_target_count >= 2
                )
                if interesting:
                    candidates.append(evaluated)
            if offset == start:
                offset += 2
    return candidates


def _split_lo_hi_candidates(
    image: InesImage, facts: dict[int, InstructionFact]
) -> list[PointerCandidate]:
    occupied, interiors, instruction_starts, control_targets = _instruction_sets(
        image, facts
    )
    cpu_base = canonical_prg_start(image)
    scan_end = max(0, len(image.prg) - 6)
    referenced_offsets = sorted(
        offset
        for offset in _operand_reference_offsets(image, facts)
        if offset < scan_end
    )

    candidates: list[PointerCandidate] = []
    for low_offset in referenced_offsets:
        for high_offset in referenced_offsets:
            count = high_offset - low_offset
            if count < MIN_ACCEPTED_ENTRIES or count > 0x100:
                continue
            end = high_offset + count
            if end > scan_end or any(
                offset in occupied for offset in range(low_offset, end)
            ):
                continue
            targets = tuple(
                image.prg[low_offset + index]
                | (image.prg[high_offset + index] << 8)
                for index in range(count)
            )
            if not all(_mapped_target(image, target) for target in targets):
                continue
            low_address = cpu_base + low_offset
            high_address = cpu_base + high_offset

            evidence = [
                "all_entries_map_to_prg",
                f"entry_count={count}",
                "low_and_high_arrays_referenced_by_instructions",
            ]
            contradictions: list[str] = []
            score = 60 + min(count * 2, 20)
            if all(left < right for left, right in zip(targets, targets[1:])):
                evidence.append("targets_strictly_increasing")
                score += 20
            else:
                contradictions.append("targets_not_strictly_increasing")
                score -= 20
            span = max(targets) - min(targets)
            evidence.append(f"target_span={span}")

            target_offsets = tuple(
                cpu_to_prg_offset(image, target) for target in targets
            )
            if any(offset in interiors for offset in target_offsets):
                contradictions.append("target_inside_instruction")
                score -= 30
            if any(low_offset <= offset < end for offset in target_offsets):
                contradictions.append("target_inside_own_table")
                score -= 30
            if any(low_offset < target < end for target in control_targets):
                contradictions.append("control_target_inside_table")
                score -= 30

            instruction_target_count = sum(
                offset in instruction_starts for offset in target_offsets
            )
            if instruction_target_count:
                evidence.append(f"instruction_targets={instruction_target_count}")
                score += min(instruction_target_count, 5)

            entries = tuple(
                PointerEntry(
                    physical_offset=low_offset + index,
                    cpu_address=low_address + index,
                    target=target,
                    high_physical_offset=high_offset + index,
                    high_cpu_address=high_address + index,
                )
                for index, target in enumerate(targets)
            )
            candidates.append(
                PointerCandidate(
                    candidate_id=(
                        f"PtrTableSplit_B00_{low_address:04X}_{high_address:04X}"
                    ),
                    schema_id="nes.split_lo_hi",
                    physical_start=low_offset,
                    physical_end=end,
                    cpu_start=low_address,
                    status="accepted" if not contradictions else "rejected",
                    score=max(0, min(score, 100)),
                    entries=entries,
                    evidence=tuple(evidence),
                    contradictions=tuple(contradictions),
                )
            )
    return candidates


def _interleaved_u16le_candidates(
    image: InesImage, facts: dict[int, InstructionFact]
) -> list[PointerCandidate]:
    occupied, interiors, instruction_starts, control_targets = _instruction_sets(
        image, facts
    )
    scan_end = max(0, len(image.prg) - 6)
    cpu_base = canonical_prg_start(image)
    candidates: list[PointerCandidate] = []

    for alignment in (0, 1):
        for start in range(alignment, scan_end - 1, 2):
            entries: list[PointerEntry] = []
            offset = start
            while offset + 1 < scan_end and len(entries) < MAX_INTERLEAVED_ENTRIES:
                if offset in occupied or offset + 1 in occupied:
                    break
                target = int.from_bytes(image.prg[offset:offset + 2], "little")
                if not _mapped_target(image, target):
                    break
                entries.append(PointerEntry(offset, cpu_base + offset, target))
                offset += 2
            if len(entries) < 6:
                continue

            selected: tuple[PointerEntry, ...] | None = None
            selected_evidence: tuple[str, ...] = ()
            for count in range(len(entries), 5, -1):
                window = tuple(entries[:count])
                targets = tuple(entry.target for entry in window)
                if all(left < right for left, right in zip(targets, targets[1:])):
                    continue
                even_lane = targets[0::2]
                odd_lane = targets[1::2]
                if not all(
                    left < right for left, right in zip(even_lane, even_lane[1:])
                ):
                    continue
                if not all(
                    left < right for left, right in zip(odd_lane, odd_lane[1:])
                ):
                    continue
                even_span = max(even_lane) - min(even_lane)
                odd_span = max(odd_lane) - min(odd_lane)
                if (
                    even_span > MAX_INTERLEAVED_LANE_SPAN
                    or odd_span > MAX_INTERLEAVED_LANE_SPAN
                ):
                    continue
                end = start + count * 2
                target_offsets = tuple(
                    cpu_to_prg_offset(image, target) for target in targets
                )
                if any(
                    target_offset < end
                    or target_offset - end > MAX_INTERLEAVED_TARGET_DISTANCE
                    for target_offset in target_offsets
                ):
                    continue
                if any(target_offset in interiors for target_offset in target_offsets):
                    continue
                if any(start < target < end for target in control_targets):
                    continue
                selected = window
                instruction_target_count = sum(
                    target_offset in instruction_starts
                    for target_offset in target_offsets
                )
                selected_evidence = (
                    "all_entries_map_to_prg",
                    f"entry_count={count}",
                    "two_interleaved_strictly_increasing_lanes",
                    f"even_lane_span={even_span}",
                    f"odd_lane_span={odd_span}",
                    "targets_follow_table",
                    f"instruction_targets={instruction_target_count}",
                )
                break
            if selected is None:
                continue
            end = selected[-1].physical_offset + 2
            candidates.append(
                PointerCandidate(
                    candidate_id=(
                        f"PtrTableInterleaved_B00_{cpu_base + start:04X}_{len(selected):02X}"
                    ),
                    schema_id="nes.u16le",
                    physical_start=start,
                    physical_end=end,
                    cpu_start=cpu_base + start,
                    status="accepted",
                    score=min(100, 95 + len(selected)),
                    entries=selected,
                    evidence=selected_evidence,
                    contradictions=(),
                )
            )
    return candidates


def _anchored_u16le_candidates(
    image: InesImage,
    facts: dict[int, InstructionFact],
    accepted: tuple[PointerCandidate, ...],
) -> list[PointerCandidate]:
    occupied, interiors, instruction_starts, control_targets = _instruction_sets(
        image, facts
    )
    scan_end = max(0, len(image.prg) - 6)
    cpu_base = canonical_prg_start(image)
    anchors: set[int] = set()
    for candidate in accepted:
        for entry in candidate.entries:
            try:
                anchors.add(cpu_to_prg_offset(image, entry.target))
            except ValueError:
                pass

    candidates_by_range: dict[tuple[int, int], PointerCandidate] = {}
    for anchor in sorted(anchors):
        for field_offset in range(MAX_ANCHORED_FIELD_OFFSET + 1):
            start = anchor + field_offset
            if start + MIN_CANDIDATE_ENTRIES * 2 > scan_end:
                continue
            entries: list[PointerEntry] = []
            offset = start
            while offset + 1 < scan_end and len(entries) < MAX_ANCHORED_ENTRIES:
                if offset in occupied or offset + 1 in occupied:
                    break
                target = int.from_bytes(image.prg[offset:offset + 2], "little")
                if not _mapped_target(image, target):
                    break
                entries.append(PointerEntry(offset, cpu_base + offset, target))
                offset += 2
            if len(entries) < MIN_CANDIDATE_ENTRIES:
                continue

            selected: tuple[PointerEntry, ...] | None = None
            for count in range(len(entries), MIN_CANDIDATE_ENTRIES - 1, -1):
                window = tuple(entries[:count])
                end = start + count * 2
                target_offsets = tuple(
                    cpu_to_prg_offset(image, entry.target) for entry in window
                )
                span = max(target_offsets) - min(target_offsets)
                if span > MAX_UNREFERENCED_TARGET_SPAN:
                    continue
                if any(target_offset < end for target_offset in target_offsets):
                    continue
                if any(target_offset in interiors for target_offset in target_offsets):
                    continue
                if any(start < target < end for target in control_targets):
                    continue
                selected = window
                break
            if selected is None:
                continue

            end = selected[-1].physical_offset + 2
            target_offsets = tuple(
                cpu_to_prg_offset(image, entry.target) for entry in selected
            )
            instruction_target_count = sum(
                target_offset in instruction_starts for target_offset in target_offsets
            )
            evidence = (
                "all_entries_map_to_prg",
                f"entry_count={len(selected)}",
                f"anchored_record_start={cpu_base + anchor:04X}",
                f"record_field_offset={field_offset}",
                f"compact_target_span={max(target_offsets) - min(target_offsets)}",
                "targets_follow_table",
                f"instruction_targets={instruction_target_count}",
            )
            candidate = PointerCandidate(
                candidate_id=(
                    f"PtrTableAnchored_B00_{cpu_base + start:04X}_{len(selected):02X}"
                ),
                schema_id="nes.u16le",
                physical_start=start,
                physical_end=end,
                cpu_start=cpu_base + start,
                status="accepted",
                score=min(100, 85 + len(selected)),
                entries=selected,
                evidence=evidence,
                contradictions=(),
            )
            key = (start, end)
            existing = candidates_by_range.get(key)
            if existing is None or candidate.score > existing.score:
                candidates_by_range[key] = candidate
    return list(candidates_by_range.values())


def _interrupt_vectors(image: InesImage) -> PointerCandidate:
    start = len(image.prg) - 6
    cpu_start = canonical_prg_start(image) + start
    targets = struct.unpack_from("<HHH", image.prg, start)
    entries = tuple(
        PointerEntry(start + index * 2, cpu_start + index * 2, target)
        for index, target in enumerate(targets)
    )
    mapped = sum(_mapped_target(image, target) for target in targets if target)
    return PointerCandidate(
        candidate_id=f"InterruptVectors_B00_{cpu_start:04X}",
        schema_id="nes.interrupt_vectors",
        physical_start=start,
        physical_end=len(image.prg),
        cpu_start=cpu_start,
        status="accepted",
        score=100,
        entries=entries,
        evidence=("architecture_defined_range", f"mapped_nonzero_targets={mapped}"),
        contradictions=(),
    )


def _resolve_overlaps(
    candidates: list[PointerCandidate],
) -> list[PointerCandidate]:
    accepted = sorted(
        (candidate for candidate in candidates if candidate.status == "accepted"),
        key=lambda candidate: (-candidate.score, -len(candidate.entries), candidate.physical_start),
    )
    retained: set[str] = set()
    occupied: set[int] = set()
    for candidate in accepted:
        byte_range = set(range(candidate.physical_start, candidate.physical_end))
        if occupied & byte_range:
            continue
        retained.add(candidate.candidate_id)
        occupied.update(byte_range)

    resolved: list[PointerCandidate] = []
    for candidate in candidates:
        if candidate.status == "accepted" and candidate.candidate_id not in retained:
            resolved.append(
                replace(
                    candidate,
                    status="rejected",
                    score=max(0, candidate.score - 30),
                    contradictions=candidate.contradictions
                    + ("overlaps_stronger_candidate",),
                )
            )
        else:
            resolved.append(candidate)
    return resolved


def detect_pointer_candidates(
    image: InesImage, facts: dict[int, InstructionFact]
) -> tuple[PointerCandidate, ...]:
    initial = (
        _u16le_candidates(image, facts)
        + _split_lo_hi_candidates(image, facts)
        + _interleaved_u16le_candidates(image, facts)
    )
    initial_resolved = _resolve_overlaps(initial)
    anchored = _anchored_u16le_candidates(
        image, facts, accepted_pointer_tables(tuple(initial_resolved))
    )
    candidates = _resolve_overlaps(initial + anchored)
    candidates.append(_interrupt_vectors(image))
    return tuple(
        sorted(candidates, key=lambda candidate: (candidate.physical_start, candidate.schema_id))
    )


def pointer_report(
    image: InesImage, candidates: tuple[PointerCandidate, ...]
) -> dict[str, object]:
    return {
        "schema": "retrolarium.nes.pointers",
        "schema_version": 1,
        "input_sha256": image.sha256,
        "registry": [
            {
                "id": "nes.u16le",
                "entry_size": 2,
                "endianness": "little",
                "minimum_candidate_entries": MIN_CANDIDATE_ENTRIES,
                "minimum_accepted_entries": MIN_ACCEPTED_ENTRIES,
                "maximum_accepted_target_span": MAX_ACCEPTED_TARGET_SPAN,
                "maximum_unreferenced_target_span": MAX_UNREFERENCED_TARGET_SPAN,
                "reporting_prefilter": (
                    "increasing targets, a direct table reference, or at least "
                    "two instruction targets"
                ),
                "accepted_evidence_patterns": [
                    "strictly increasing compact targets",
                    "two interleaved monotonic lanes whose targets follow the table",
                    "compact pointer fields near a target of an accepted table",
                ],
            },
            {
                "id": "nes.interrupt_vectors",
                "entry_size": 2,
                "endianness": "little",
                "count": 3,
            },
            {
                "id": "nes.split_lo_hi",
                "entry_size": 2,
                "endianness": "little",
                "layout": "adjacent low-byte array followed by high-byte array",
                "minimum_accepted_entries": MIN_ACCEPTED_ENTRIES,
                "maximum_accepted_entries": 256,
                "required_evidence": "both array starts referenced by instructions",
            },
        ],
        "candidates": [candidate.as_dict() for candidate in candidates],
    }


def write_pointer_report(
    path: Path, image: InesImage, candidates: tuple[PointerCandidate, ...]
) -> None:
    path.write_text(
        json.dumps(pointer_report(image, candidates), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


BANK_ID_RE = re.compile(r"_B\d{2}_")


def relocate_pointer_candidate(
    candidate: PointerCandidate, *, bank: int, physical_delta: int
) -> PointerCandidate:
    """Move a bank-local candidate into or out of the physical ROM address space."""
    entries = tuple(
        replace(
            entry,
            physical_offset=entry.physical_offset + physical_delta,
            high_physical_offset=(
                None
                if entry.high_physical_offset is None
                else entry.high_physical_offset + physical_delta
            ),
            bank=bank,
        )
        for entry in candidate.entries
    )
    return replace(
        candidate,
        candidate_id=BANK_ID_RE.sub(f"_B{bank:02d}_", candidate.candidate_id),
        physical_start=candidate.physical_start + physical_delta,
        physical_end=candidate.physical_end + physical_delta,
        entries=entries,
        bank=bank,
    )


def detect_banked_pointer_candidates(
    image: InesImage, facts: dict[int, InstructionFact]
) -> tuple[PointerCandidate, ...]:
    """Run existing pointer schemas independently in each canonical PRG bank."""
    candidates: list[PointerCandidate] = []
    for target in prg_analysis_targets(image):
        local_facts = {
            offset - target.physical_start: replace(
                fact,
                physical_offset=offset - target.physical_start,
                bank=0,
            )
            for offset, fact in facts.items()
            if target.physical_start <= offset <= target.physical_end
        }
        local_candidates = detect_pointer_candidates(target.image, local_facts)
        candidates.extend(
            relocate_pointer_candidate(
                candidate,
                bank=target.bank,
                physical_delta=target.physical_start,
            )
            for candidate in local_candidates
        )
    return tuple(
        sorted(
            candidates,
            key=lambda candidate: (
                candidate.physical_start,
                candidate.schema_id,
                candidate.candidate_id,
            ),
        )
    )
