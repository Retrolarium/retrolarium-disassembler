"""Conservative recovery of Mega Drive 68000-to-Z80 program copies."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

from .facts import InstructionFact
from .megadrive import MegaDriveImage, m68k_to_rom_offset


Z80_WINDOW_START = 0xA00000
Z80_WINDOW_END = 0xA01FFF


@dataclass(frozen=True)
class CrossCpuCopy:
    edge_id: str
    schema_id: str
    source_cpu_id: str
    source_space: str
    source_start: int
    source_end: int
    target_cpu_id: str
    target_space: str
    target_start: int
    target_end: int
    size: int
    payload_sha256: str
    evidence_addresses: tuple[int, ...]
    confidence: str


def _destination_register(fact: InstructionFact) -> str | None:
    operands = fact.operands.split("|")
    if len(operands) != 2:
        return None
    register = operands[1].strip().upper()
    return register if re.fullmatch(r"[AD][0-7](?:[BWL])?", register) else None


def _absolute_address(operand: str) -> int | None:
    match = re.search(r"\(0x([0-9a-f]+)\)(?:\.l)?", operand, re.I)
    return int(match.group(1), 16) if match else None


def _immediate(operand: str) -> int | None:
    match = re.fullmatch(r"#(-?0x[0-9a-f]+|-?[0-9]+)", operand, re.I)
    return int(match.group(1), 0) if match else None


def _source_address(image: MegaDriveImage, fact: InstructionFact) -> int | None:
    for reference in fact.references:
        if reference.operand_index != 0 or "DATA" not in reference.reference_type:
            continue
        if image.header.rom_start <= reference.address <= image.actual_rom_end:
            return reference.address
    operands = fact.operands.split("|")
    if not operands:
        return None
    address = _absolute_address(operands[0])
    if address is None or not image.header.rom_start <= address <= image.actual_rom_end:
        return None
    return address


def detect_z80_copies(
    image: MegaDriveImage, facts: dict[int, InstructionFact]
) -> tuple[CrossCpuCopy, ...]:
    """Find statically proven LEA/DBF byte-copy loops into the Z80 RAM window."""
    ordered = sorted(facts.values(), key=lambda fact: fact.cpu_address)
    copies: list[CrossCpuCopy] = []
    seen: set[tuple[int, int, int]] = set()
    for index, copy in enumerate(ordered):
        match = re.fullmatch(
            r"\(A([0-7])\)\+\|\(A([0-7])\)\+", copy.operands, re.I
        )
        if copy.mnemonic != "MOVE.B" or match is None:
            continue
        source_register = f"A{match.group(1)}"
        target_register = f"A{match.group(2)}"
        if source_register == target_register:
            continue

        source_fact = None
        target_fact = None
        count_fact = None
        for previous in reversed(ordered[max(0, index - 10):index]):
            destination = _destination_register(previous)
            if (
                source_fact is None
                and previous.mnemonic == "LEA"
                and destination == source_register
                and _source_address(image, previous) is not None
            ):
                source_fact = previous
            if (
                target_fact is None
                and previous.mnemonic == "LEA"
                and destination == target_register
                and _absolute_address(previous.operands.split("|")[0]) is not None
            ):
                target_fact = previous
            if count_fact is None and previous.mnemonic == "MOVE.W":
                operands = previous.operands.split("|")
                if len(operands) == 2 and _immediate(operands[0]) is not None:
                    count_fact = previous
            if source_fact and target_fact and count_fact:
                break
        if source_fact is None or target_fact is None or count_fact is None:
            continue

        count_operands = count_fact.operands.split("|")
        count_register = count_operands[1].strip().upper()
        if not re.fullmatch(r"D[0-7]W?", count_register):
            continue
        count_value = _immediate(count_operands[0])
        assert count_value is not None
        size = (count_value & 0xFFFF) + 1
        if not 1 <= size <= 0x2000:
            continue

        loop = None
        for following in ordered[index + 1:index + 4]:
            operands = following.operands.split("|")
            if (
                following.mnemonic == "DBF"
                and len(operands) == 2
                and operands[0].strip().upper() == count_register
                and copy.cpu_address in following.flows
            ):
                loop = following
                break
        if loop is None:
            continue

        source_start = _source_address(image, source_fact)
        target_start = _absolute_address(target_fact.operands.split("|")[0])
        assert source_start is not None and target_start is not None
        source_end = source_start + size - 1
        target_end = target_start + size - 1
        if source_end > image.actual_rom_end:
            continue
        if not Z80_WINDOW_START <= target_start <= target_end <= Z80_WINDOW_END:
            continue
        key = (source_start, target_start, size)
        if key in seen:
            continue
        seen.add(key)
        payload_offset = m68k_to_rom_offset(image, source_start)
        payload = image.data[payload_offset:payload_offset + size]
        z80_start = target_start - Z80_WINDOW_START
        copies.append(
            CrossCpuCopy(
                edge_id=(
                    f"megadrive.cross.m68k-z80.{source_start:06X}.{z80_start:04X}"
                ),
                schema_id="megadrive.m68k-z80.dbf-postincrement-copy",
                source_cpu_id="m68k",
                source_space="m68k",
                source_start=source_start,
                source_end=source_end,
                target_cpu_id="z80",
                target_space="z80",
                target_start=z80_start,
                target_end=z80_start + size - 1,
                size=size,
                payload_sha256=hashlib.sha256(payload).hexdigest(),
                evidence_addresses=(
                    source_fact.cpu_address,
                    target_fact.cpu_address,
                    count_fact.cpu_address,
                    copy.cpu_address,
                    loop.cpu_address,
                ),
                confidence="proven-static-copy",
            )
        )
    return tuple(copies)
