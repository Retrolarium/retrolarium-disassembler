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


def _register_constant(fact: InstructionFact, register: str) -> int | None:
    operands = fact.operands.split("|")
    if len(operands) != 2 or operands[1].upper().rstrip("BWL") != register:
        return None
    if fact.mnemonic not in {"MOVE.W", "MOVE.L", "MOVEQ"}:
        return None
    value = operands[0].removeprefix("#")
    return int(value, 0) if re.fullmatch(r"-?(?:0x[0-9a-f]+|\d+)", value, re.I) else None


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


def _subroutine_copy_routines(ordered: list[InstructionFact]) -> set[int]:
    """Find calls that copy A0 bytes into Z80 RAM using D0/D1 parameters."""
    routines: set[int] = set()
    for entry in ordered:
        if not (entry.mnemonic.startswith("MOVEM") and entry.operands.endswith("|-(SP)")):
            continue
        window = [fact for fact in ordered if entry.cpu_address < fact.cpu_address < entry.cpu_address + 0x40]
        bus = next((fact for fact in window if fact.mnemonic == "LEA"
                    and fact.operands.upper() == "(0XA00000).L|A1"), None)
        if bus is None:
            continue
        if not any(fact.mnemonic == "ADDA.W" and fact.operands.upper() == "D1W|A1"
                   for fact in window):
            continue
        source = next((fact for fact in window if fact.mnemonic == "MOVE.B"
                       and fact.operands.upper() == "(A0)+|D1B"), None)
        if source is None:
            continue
        if not any(fact.mnemonic == "MOVE.B" and fact.operands.upper() == "D1B|(A1)"
                   for fact in window):
            continue
        if not any(fact.mnemonic == "ADDQ.W" and fact.operands.upper() == "0X1|A1"
                   for fact in window):
            continue
        if not any(fact.mnemonic == "DBF" and fact.operands.upper().startswith("D0W|")
                   and source.cpu_address in fact.flows for fact in window):
            continue
        routines.add(entry.cpu_address)
    return routines


def _detect_subroutine_copies(
    image: MegaDriveImage, ordered: list[InstructionFact], seen: set[tuple[int, int, int]]
) -> list[CrossCpuCopy]:
    routines = _subroutine_copy_routines(ordered)
    copies: list[CrossCpuCopy] = []
    for index, call in enumerate(ordered):
        if not call.mnemonic.startswith("BSR") or not routines.intersection(call.flows):
            continue
        prior = [fact for fact in ordered[max(0, index - 8):index]
                 if call.cpu_address - 0x20 <= fact.cpu_address]
        count = next((fact for fact in reversed(prior)
                      if _register_constant(fact, "D0") is not None), None)
        destination = next((fact for fact in reversed(prior)
                            if _register_constant(fact, "D1") is not None), None)
        source = next((fact for fact in reversed(prior) if fact.mnemonic == "LEA"
                       and fact.operands.upper().endswith("|A0")
                       and _source_address(image, fact) is not None), None)
        if count is None or destination is None or source is None:
            continue
        count_value = _register_constant(count, "D0")
        destination_value = _register_constant(destination, "D1")
        source_start = _source_address(image, source)
        assert count_value is not None and destination_value is not None and source_start is not None
        if count.cpu_address >= source.cpu_address or destination.cpu_address >= source.cpu_address:
            continue
        size = (count_value & 0xFFFF) + 1
        # This analysis lane extracts executable Z80 images, which enter RAM
        # at zero. Short copies to the sound command area are data transfers.
        if destination_value != 0 or not 0x20 <= size <= 0x2000:
            continue
        source_end = source_start + size - 1
        if source_end > image.actual_rom_end:
            continue
        key = (source_start, Z80_WINDOW_START, size)
        if key in seen:
            continue
        seen.add(key)
        payload_offset = m68k_to_rom_offset(image, source_start)
        payload = image.data[payload_offset:payload_offset + size]
        copies.append(CrossCpuCopy(
            edge_id=f"megadrive.cross.m68k-z80.{source_start:06X}.0000",
            schema_id="megadrive.m68k-z80.subroutine-copy",
            source_cpu_id="m68k",
            source_space="m68k",
            source_start=source_start,
            source_end=source_end,
            target_cpu_id="z80",
            target_space="z80",
            target_start=0,
            target_end=size - 1,
            size=size,
            payload_sha256=hashlib.sha256(payload).hexdigest(),
            evidence_addresses=(count.cpu_address, destination.cpu_address,
                                source.cpu_address, call.cpu_address, *call.flows),
            confidence="proven-static-copy",
        ))
    return copies


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
    copies.extend(_detect_subroutine_copies(image, ordered, seen))
    return tuple(sorted(copies, key=lambda copy: (copy.source_start, copy.target_start)))
