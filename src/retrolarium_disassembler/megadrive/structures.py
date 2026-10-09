"""Instruction-proven mixed data structures used by Mega Drive programs."""

from __future__ import annotations

from dataclasses import dataclass

from retrolarium_disasm.facts import InstructionFact
from retrolarium_core.megadrive import MegaDriveImage


STANDARD_BOOT_SETUP_SIZE = 0x6C
LONG_FF_PADDING_MIN_BYTES = 64
STANDARD_BOOT_HARDWARE = (
    0xA00000,
    0xA11100,
    0xA11200,
    0xC00000,
    0xC00004,
)
_STANDARD_STREAM_READS = (
    "MOVEM.W",
    "MOVEM.L",
    "MOVE.B",
    "MOVE.L",
    "MOVE.B",
    "MOVE.L",
    "MOVE.L",
    "MOVE.L",
    "MOVE.B",
)


@dataclass(frozen=True)
class StandardBootSetup:
    physical_start: int
    physical_end: int
    logical_start: int
    logical_end: int
    loader_address: int


def discover_long_ff_padding(
    image: MegaDriveImage,
    facts: dict[int, InstructionFact],
    *,
    minimum_size: int = LONG_FF_PADDING_MIN_BYTES,
) -> tuple[tuple[int, int], ...]:
    """Return long all-FF file ranges that contain no decoded instruction."""
    occupied = {
        offset
        for fact in facts.values()
        for offset in range(fact.physical_offset, fact.physical_offset + fact.length)
    }
    ranges: list[tuple[int, int]] = []
    offset = 0
    while offset < len(image.data):
        if image.data[offset] != 0xFF:
            offset += 1
            continue
        end = offset + 1
        while end < len(image.data) and image.data[end] == 0xFF:
            end += 1
        if end - offset >= minimum_size and not any(
            byte in occupied for byte in range(offset, end)
        ):
            ranges.append((offset, end))
        offset = end
    return tuple(ranges)


def _source_operand(fact: InstructionFact) -> str:
    return fact.operands.split("|", 1)[0].replace(" ", "").upper()


def discover_standard_boot_setups(
    image: MegaDriveImage,
    facts: dict[int, InstructionFact],
) -> tuple[StandardBootSetup, ...]:
    """Find the canonical mixed-width startup stream consumed through A5."""
    ordered = tuple(sorted(facts.values(), key=lambda item: item.cpu_address))
    results: list[StandardBootSetup] = []
    for loader in ordered:
        if loader.mnemonic.upper() != "LEA" or not loader.operands.upper().endswith("|A5"):
            continue
        starts = {
            reference.address
            for reference in loader.references
            if "DATA" in reference.reference_type
        }
        for logical_start in starts:
            physical_start = logical_start - image.header.rom_start
            physical_end = physical_start + STANDARD_BOOT_SETUP_SIZE
            logical_end = logical_start + STANDARD_BOOT_SETUP_SIZE
            if physical_start < 0 or physical_end > len(image.data):
                continue
            if any(
                physical_start <= fact.physical_offset < physical_end
                for fact in facts.values()
            ):
                continue
            hardware = tuple(
                int.from_bytes(image.data[offset:offset + 4], "big")
                for offset in range(physical_start + 6, physical_start + 26, 4)
            )
            if hardware != STANDARD_BOOT_HARDWARE:
                continue
            readers = tuple(
                fact.mnemonic.upper()
                for fact in ordered
                if (
                    loader.cpu_address < fact.cpu_address < logical_start
                    and _source_operand(fact) == "(A5)+"
                )
            )
            if readers != _STANDARD_STREAM_READS:
                continue
            preceding = [
                fact for fact in ordered if fact.cpu_address < logical_start
            ]
            if not preceding:
                continue
            exit_branch = preceding[-1]
            if (
                not exit_branch.mnemonic.upper().startswith("BRA")
                or logical_end not in exit_branch.flows
            ):
                continue
            results.append(StandardBootSetup(
                physical_start=physical_start,
                physical_end=physical_end,
                logical_start=logical_start,
                logical_end=logical_end,
                loader_address=loader.cpu_address,
            ))
    return tuple(results)
